from __future__ import annotations

import argparse
import re
import subprocess
import time
from functools import lru_cache
from typing import Any, Generator, Pattern, TypedDict
from wsgiref.simple_server import WSGIRequestHandler, make_server

import psutil
from prometheus_client import make_wsgi_app
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily, Metric


class ProcInfo(TypedDict, total=False):
    name: str
    exe: str
    cmdline: list[str]
    uids: Any
    uid: int
    environ: dict[str, str]


class AgentResourceStats(TypedDict):
    process_count: int
    memory_rss: int
    cpu_usage: float
    threads_count: int


@lru_cache(maxsize=200)
def get_username(uid: int) -> str:
    """Convert a numerical UID to a username."""
    try:
        command: list[str] = ["/usr/bin/id", "--name", "--user", str(uid)]
        return subprocess.check_output(command, stderr=subprocess.DEVNULL).strip().decode()
    except Exception:
        return f"uid_{uid}"


# Agent Signatures (Direct binary, package, module, or process name patterns)
KNOWN_AGENT_PATTERNS: list[tuple[str, Pattern[str]]] = [
    (
        "claude",
        re.compile(
            r"(^|/|\s)(claude|claude-code|@anthropic-ai/claude-code)($|\s|/)",
            re.IGNORECASE,
        ),
    ),
    (
        "aider",
        re.compile(r"(^|/|\s)(aider|aider-chat)($|\s|/)|python\d*\s+-m\s+aider", re.IGNORECASE),
    ),
    (
        "cursor",
        re.compile(r"(^|/|\s)(cursor|cursor-server|\.cursor-server)($|\s|/)", re.IGNORECASE),
    ),
    (
        "copilot",
        re.compile(r"(^|/|\s)(copilot|copilot-agent|github-copilot-cli)($|\s|/)", re.IGNORECASE),
    ),
    ("openhands", re.compile(r"(^|/|\s)(openhands|opendevin)($|\s|/)", re.IGNORECASE)),
    ("goose", re.compile(r"(^|/|\s)(goose|goose-agent)($|\s|/)", re.IGNORECASE)),
    ("antigravity", re.compile(r"(^|/|\s)(antigravity)($|\s|/)", re.IGNORECASE)),
    (
        "continue",
        re.compile(r"(^|/|\s)(continue-server|continue-agent)($|\s|/)", re.IGNORECASE),
    ),
]

# Remote Agent Subshell Execution Heuristics
REMOTE_SUBSHELL_REDIRECTION_RE: Pattern[str] = re.compile(
    r"2>/dev/null|2>&1\s*>/dev/null|> /tmp/\S+ 2>&1"
)
REMOTE_AGENT_CMD_PATTERNS: list[Pattern[str]] = [
    re.compile(r"CLAUDE_CODE|ANTHROPIC_API_KEY|AIDER_|OPENHANDS_", re.IGNORECASE),
]


def detect_agent_type(proc_info: ProcInfo) -> tuple[str | None, bool]:
    """
    Analyzes process info (name, exe, cmdline, envs) to determine if it is an AI agent process.
    Returns (agent_type, is_remote) or (None, False).
    """
    cmdline: list[str] = proc_info.get("cmdline") or []
    cmdline_str: str = " ".join(cmdline)
    name: str = proc_info.get("name") or ""
    exe: str = proc_info.get("exe") or ""

    full_search_str: str = f"{name} {exe} {cmdline_str}"

    # 1. Match direct known agent signatures
    for agent_type, pattern in KNOWN_AGENT_PATTERNS:
        if pattern.search(full_search_str):
            return agent_type, False

    # 2. Check environment variables if available
    envs: dict[str, str] = proc_info.get("environ") or {}
    if any(k in envs for k in ("CLAUDE_CODE_ENTRYPOINT", "CLAUDE_SESSION_ID")):
        return "claude", True
    if any(k.startswith("AIDER_") for k in envs):
        return "aider", True
    if "CURSOR_TRACE" in envs:
        return "cursor", True

    # 3. Check remote agent subshell execution heuristics
    if REMOTE_SUBSHELL_REDIRECTION_RE.search(cmdline_str):
        for pattern in REMOTE_AGENT_CMD_PATTERNS:
            if pattern.search(cmdline_str) or pattern.search(str(envs)):
                return "remote_agent", True

    return None, False


class AIAgentCollector:
    """
    Prometheus Collector that scans login node processes to gather stats
    on active AI coding agents and user activity.
    """

    def collect(self) -> Generator[Metric, None, None]:
        start_time: float = time.time()

        # Define Prometheus Metric Families
        metrics: dict[str, Metric] = {
            "process_count": GaugeMetricFamily(
                "ai_agent_process_count",
                "Number of active AI agent processes running on the login node",
                labels=["user", "agent_type"],
            ),
            "memory_rss": GaugeMetricFamily(
                "ai_agent_memory_rss_bytes",
                "Resident set size memory used by AI agent processes in bytes",
                labels=["user", "agent_type"],
            ),
            "cpu_usage": CounterMetricFamily(
                "ai_agent_cpu_usage_seconds_total",
                "Total CPU time consumed by AI agent processes in seconds",
                labels=["user", "agent_type"],
            ),
            "threads_count": GaugeMetricFamily(
                "ai_agent_threads_count",
                "Total number of threads spawned by AI agent processes",
                labels=["user", "agent_type"],
            ),
            "agent_active_users": GaugeMetricFamily(
                "ai_agent_active_users",
                "Count of distinct active users using a specific AI agent type",
                labels=["agent_type"],
            ),
            "login_node_active_users_total": GaugeMetricFamily(
                "login_node_active_users_total",
                "Total count of unique active users logged into or running processes on the login node",
            ),
            "scrape_duration": GaugeMetricFamily(
                "ai_agent_exporter_scrape_duration_seconds",
                "Time spent collecting AI agent statistics in seconds",
            ),
        }

        agent_stats: dict[tuple[str, str], AgentResourceStats] = {}
        agent_users: dict[str, set[str]] = {}
        active_uids: set[int] = set()

        for proc in psutil.process_iter(attrs=["pid", "uids", "name", "exe", "cmdline"]):
            try:
                proc_info: ProcInfo = proc.info  # type: ignore[assignment]
                uids: Any = proc_info.get("uids")
                uid: int | None = uids.real if uids else None

                if uid is None:
                    try:
                        uid = proc.uids().real
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                # Filter user processes (UID >= 500 for standard Linux system user threshold)
                if uid is not None and uid >= 500:
                    active_uids.add(uid)

                try:
                    proc_info["environ"] = proc.environ()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_info["environ"] = {}

                agent_type, is_remote = detect_agent_type(proc_info)
                if not agent_type:
                    continue

                user: str = get_username(uid)

                # Fetch process resource stats
                try:
                    mem_rss: int = proc.memory_info().rss
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    mem_rss = 0

                try:
                    cpu_times: Any = proc.cpu_times()
                    cpu_total: float = cpu_times.user + cpu_times.system
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    cpu_total = 0.0

                try:
                    num_threads: int = proc.num_threads()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    num_threads = 1

                key: tuple[str, str] = (user, agent_type)
                if key not in agent_stats:
                    agent_stats[key] = {
                        "process_count": 0,
                        "memory_rss": 0,
                        "cpu_usage": 0.0,
                        "threads_count": 0,
                    }

                agent_stats[key]["process_count"] += 1
                agent_stats[key]["memory_rss"] += mem_rss
                agent_stats[key]["cpu_usage"] += cpu_total
                agent_stats[key]["threads_count"] += num_threads

                if agent_type not in agent_users:
                    agent_users[agent_type] = set()
                agent_users[agent_type].add(user)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        try:
            for u in psutil.users():
                if u.name:
                    pass
        except Exception:
            pass

        # Populate Prometheus metric families
        for (user, agent_type), stats in agent_stats.items():
            metrics["process_count"].add_metric([user, agent_type], stats["process_count"])
            metrics["memory_rss"].add_metric([user, agent_type], stats["memory_rss"])
            metrics["cpu_usage"].add_metric([user, agent_type], stats["cpu_usage"])
            metrics["threads_count"].add_metric([user, agent_type], stats["threads_count"])

        for agent_type, users in agent_users.items():
            metrics["agent_active_users"].add_metric([agent_type], len(users))

        # Total unique active users on login node
        metrics["login_node_active_users_total"].add_metric([], len(active_uids))

        # Scrape duration
        duration: float = time.time() - start_time
        metrics["scrape_duration"].add_metric([], duration)

        yield from metrics.values()


class NoLoggingWSGIRequestHandler(WSGIRequestHandler):
    """Suppress WSGI HTTP request logging."""

    def log_message(self, format: str, *args: Any) -> None:
        pass


def main() -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Prometheus exporter for tracking AI agent usage on Slurm login nodes"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=9799,
        help="Collector HTTP port, default is 9799",
    )
    args: argparse.Namespace = parser.parse_args()

    app = make_wsgi_app(AIAgentCollector())
    httpd = make_server("", args.port, app, handler_class=NoLoggingWSGIRequestHandler)
    print(f"Starting AI Agents Usage Stats Exporter on port {args.port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping exporter.")


if __name__ == "__main__":
    main()
