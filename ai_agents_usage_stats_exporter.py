"""
Prometheus Exporter for AI Agents Usage Statistics on Slurm Login Nodes.

This exporter scans running processes on multi-user HPC login nodes using `psutil`,
identifies active AI coding agent sessions (direct CLI binaries, Python/Node modules,
IDE remote servers, and SSH remote agent subshells), and exports resource consumption
metrics (CPU, memory, threads, process counts, user counts) to Prometheus.
"""

from __future__ import annotations

import argparse
import collections
import logging
import re
import shlex
import subprocess
import time
from enum import Enum
from functools import lru_cache
from typing import Any, Iterable, NamedTuple, TypedDict
from wsgiref.simple_server import WSGIRequestHandler, make_server

import psutil
from prometheus_client import make_wsgi_app
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily, Metric
from typing_extensions import NewType

logger = logging.getLogger(__name__)
UsernameOrUID = NewType("UsernameOrUID", str)


class ProcInfo(TypedDict, total=False):
    """Data structure representing process attributes retrieved during inspection."""

    name: str
    exe: str
    cmdline: list[str]
    uids: Any
    uid: int
    environ: dict[str, str]


class AgentResourceStats(TypedDict):
    """Aggregated resource usage statistics for a specific (user, agent_type) pair."""

    process_count: int
    memory_rss: int
    cpu_usage: float
    threads_count: int


class PrometheusMetrics(TypedDict):
    """Typed mapping of all metric families emitted by collect_metrics."""

    process_count: GaugeMetricFamily
    memory_rss: GaugeMetricFamily
    cpu_usage: CounterMetricFamily
    threads_count: GaugeMetricFamily
    agent_active_users: GaugeMetricFamily
    login_node_active_users_total: GaugeMetricFamily
    scrape_duration: GaugeMetricFamily


class AgentType(str, Enum):
    """Supported AI agent identities used by detection signatures and metrics."""

    CODEX = "codex"
    CLAUDE = "claude"
    AIDER = "aider"
    CURSOR = "cursor"
    COPILOT = "copilot"
    OPENHANDS = "openhands"
    GOOSE = "goose"
    ANTIGRAVITY = "antigravity"
    CONTINUE = "continue"
    REMOTE_AGENT = "remote_agent"


class DetectionRule(str, Enum):
    """Finite set of transparent process-detection heuristics."""

    CMDLINE_AGENT_SIGNATURE = "cmdline:agent_signature"
    SSH_AGENT_SIGNATURE = "ssh:agent_signature"
    ENV_CLAUDE = "env:claude"
    ENV_AIDER = "env:aider"
    ENV_CURSOR = "env:cursor"
    SSH_STDERR_REDIRECTION = "ssh:stderr_redirection"
    SSH_NONINTERACTIVE_COMMAND = "ssh:noninteractive_command"


class DetectionResult(NamedTuple):
    """A classified process and every heuristic category that matched it."""

    agent_type: AgentType
    detection_rule: DetectionRule
    matched_heuristics: tuple[DetectionRule, ...]


# Signatures for direct agent executables, CLI packages, or module invocations.
# Each entry maps a typed agent identity to a regex matched against name, exe, or cmdline.
KNOWN_AGENT_SIGNATURES = [
    # OpenAI Codex CLI (e.g. `codex`, `codex exec`)
    (AgentType.CODEX, re.compile(r"(^|/|\s)(codex)($|\s|/)", re.IGNORECASE)),
    # Claude Code CLI (e.g. `claude`, `@anthropic-ai/claude-code`, `claude-code`)
    (
        AgentType.CLAUDE,
        re.compile(
            r"(^|/|\s)(claude|claude-code|@anthropic-ai/claude-code)($|\s|/)", re.IGNORECASE
        ),
    ),
    # Aider AI pair programmer (e.g. `aider`, `python -m aider`)
    (
        AgentType.AIDER,
        re.compile(r"(^|/|\s)(aider|aider-chat)($|\s|/)|python\d*\s+-m\s+aider", re.IGNORECASE),
    ),
    # Cursor IDE remote server (e.g. `cursor-server`, `.cursor-server/bin/...`)
    (
        AgentType.CURSOR,
        re.compile(r"(^|/|\s)(cursor|cursor-server|\.cursor-server)($|\s|/)", re.IGNORECASE),
    ),
    # GitHub Copilot CLI / agent backend
    (
        AgentType.COPILOT,
        re.compile(r"(^|/|\s)(copilot|copilot-agent|github-copilot-cli)($|\s|/)", re.IGNORECASE),
    ),
    # OpenHands / OpenDevin coding agent
    (AgentType.OPENHANDS, re.compile(r"(^|/|\s)(openhands|opendevin)($|\s|/)", re.IGNORECASE)),
    # Block Goose AI coding agent
    (AgentType.GOOSE, re.compile(r"(^|/|\s)(goose|goose-agent)($|\s|/)", re.IGNORECASE)),
    # Antigravity / Gemini AI agent tool
    (AgentType.ANTIGRAVITY, re.compile(r"(^|/|\s)(antigravity|agy)($|\s|/)", re.IGNORECASE)),
    # Continue IDE agent server
    (
        AgentType.CONTINUE,
        re.compile(r"(^|/|\s)(continue-server|continue-agent)($|\s|/)", re.IGNORECASE),
    ),
]

# Heuristic patterns for detecting SSH-invoked remote agent subshell execution:
# Remote agents executing shell commands over SSH typically invoke subshells with heavy stderr redirections.
REMOTE_SUBSHELL_REDIRECTION_RE = re.compile(r"2>/dev/null|2>&1\s*>/dev/null|> /tmp/\S+ 2>&1")
REMOTE_AGENT_CMD_PATTERNS = [
    re.compile(r"CLAUDE_CODE|ANTHROPIC_API_KEY|AIDER_|OPENHANDS_", re.IGNORECASE),
]


class AIAgentCollector:
    """
    Custom Prometheus Collector for login node AI agent usage.

    Scans the system process table on demand during Prometheus scrape requests,
    aggregating CPU, RSS memory, process counts, thread counts, and active user metrics.
    """

    def collect(self) -> Iterable[Metric]:
        """Scans system processes and yields Prometheus Metric objects."""
        yield from collect_metrics()


def collect_metrics(debug: bool = False) -> Iterable[Metric]:
    """Scans system processes and yields Prometheus Metric objects."""
    start_time = time.time()

    # Initialize Prometheus Metric Families
    metrics: PrometheusMetrics = {
        "process_count": GaugeMetricFamily(
            "ai_agent_process_count",
            "Number of active AI agent processes running on the login node",
            labels=["user", "agent_type", "detection_rule"],
        ),
        "memory_rss": GaugeMetricFamily(
            "ai_agent_memory_rss_bytes",
            "Resident set size memory used by AI agent processes in bytes",
            labels=["user", "agent_type", "detection_rule"],
        ),
        "cpu_usage": CounterMetricFamily(
            "ai_agent_cpu_usage_seconds_total",
            "Total CPU time consumed by AI agent processes in seconds",
            labels=["user", "agent_type", "detection_rule"],
        ),
        "threads_count": GaugeMetricFamily(
            "ai_agent_threads_count",
            "Total number of threads spawned by AI agent processes",
            labels=["user", "agent_type", "detection_rule"],
        ),
        "agent_active_users": GaugeMetricFamily(
            "ai_agent_active_users",
            "Count of distinct active users using a specific AI agent type",
            labels=["agent_type", "detection_rule"],
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

    # Aggregation tracking structures
    agent_stats: dict[tuple[UsernameOrUID, AgentType, DetectionRule], AgentResourceStats] = {}
    agent_users: dict[tuple[AgentType, DetectionRule], set[UsernameOrUID]] = {}
    active_uids: set[int] = set()
    match_commands: dict[UsernameOrUID, list[str]] = collections.defaultdict(list)
    no_match_commands: dict[UsernameOrUID, list[str]] = collections.defaultdict(list)
    # Iterate over all running system processes retrieving key attributes in a single pass
    for proc in psutil.process_iter(attrs=["pid", "uids", "name", "exe", "cmdline"]):
        try:
            proc_info: ProcInfo = proc.info  # type: ignore[assignment]
            uids: Any = proc_info.get("uids")
            uid: int | None = uids.real if uids else None

            # Fallback UID lookup if process_iter attribute was unavailable
            if uid is None:
                try:
                    uid = proc.uids().real
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Filter user processes (UID >= 500 for standard Linux user account threshold)
            if uid >= 500:
                active_uids.add(uid)

            # Attempt to retrieve environment variables (may fail due to OS permissions for other users)
            try:
                proc_info["environ"] = proc.environ()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_info["environ"] = {}

            user = UsernameOrUID(get_username(uid))
            command = get_command(proc_info)
            if user == "root":
                continue
            # Determine if process is an AI agent process
            detection = detect_agent(proc_info)
            if detection is None:
                logger.debug("No match for User %s's command: %s", user, command)
                if debug:
                    no_match_commands[user].append(command)
                continue
            logger.debug("MATCH for User %s's command: %s", user, command)
            if debug:
                match_commands[user].append(command)
            agent_type = detection.agent_type
            detection_rule = detection.detection_rule

            # Collect memory usage (RSS in bytes)
            try:
                mem_rss: int = proc.memory_info().rss
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                mem_rss = 0

            # Collect CPU times (user + system mode seconds)
            try:
                cpu_times: Any = proc.cpu_times()
                cpu_total: float = cpu_times.user + cpu_times.system
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cpu_total = 0.0

            # Collect thread counts
            try:
                num_threads: int = proc.num_threads()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                num_threads = 1

            # Aggregate metrics by (user, agent_type)
            key = (user, agent_type, detection_rule)
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

            agent_user_key = (agent_type, detection_rule)
            if agent_user_key not in agent_users:
                agent_users[agent_user_key] = set()
            agent_users[agent_user_key].add(user)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Process exited during iteration or access was denied by OS security policy
            continue

    # Populate metrics for each (user, agent_type) group
    for (user, agent_type, detection_rule), stats in agent_stats.items():
        labels = [user, agent_type.value, detection_rule.value]
        metrics["process_count"].add_metric(labels, stats["process_count"])
        metrics["memory_rss"].add_metric(labels, stats["memory_rss"])
        metrics["cpu_usage"].add_metric(labels, stats["cpu_usage"])
        metrics["threads_count"].add_metric(labels, stats["threads_count"])

    # Populate active user counts per agent type
    for (agent_type, detection_rule), users in agent_users.items():
        metrics["agent_active_users"].add_metric(
            [agent_type.value, detection_rule.value], len(users)
        )

    # Total unique active users on login node (denominator metric for percentage calculations)
    metrics["login_node_active_users_total"].add_metric([], len(active_uids))

    # Record scrape duration self-monitoring metric
    duration: float = time.time() - start_time
    metrics["scrape_duration"].add_metric([], duration)
    if debug:
        import json

        logger.debug(
            "Matched (presumably AI-related) commands: %d",
            sum(len(cmds) for cmds in match_commands.values()),
        )
        logger.debug(
            "Not Matched (presumably NOT AI-related) commands: %d",
            sum(len(cmds) for cmds in no_match_commands.values()),
        )
        with open("matches.json", "w") as f:
            json.dump(match_commands, f, indent=2)
        with open("no_matches.json", "w") as f:
            json.dump(no_match_commands, f, indent=2)
        logger.debug("Scrape duration: %.3f seconds", duration)

    emitted_metrics: tuple[Metric, ...] = (
        metrics["process_count"],
        metrics["memory_rss"],
        metrics["cpu_usage"],
        metrics["threads_count"],
        metrics["agent_active_users"],
        metrics["login_node_active_users_total"],
        metrics["scrape_duration"],
    )
    yield from emitted_metrics


@lru_cache(maxsize=200)
def get_username(uid: int) -> str:
    """
    Convert a numerical POSIX UID to a human-readable username using `/usr/bin/id`.
    Results are cached in memory to minimize subshell invocation overhead.
    """
    try:
        command: list[str] = ["/usr/bin/id", "--name", "--user", str(uid)]
        return subprocess.check_output(command, stderr=subprocess.DEVNULL).strip().decode()
    except Exception:
        # Fallback to string UID if user resolution fails or UID is ephemeral
        return f"uid_{uid}"


def get_command(proc_info: ProcInfo) -> str:
    """Returns a compact string of the command line for this process."""
    command_parts = proc_info.get("cmdline") or []
    command = shlex.join(command_parts)
    command = " ".join(command.split())  # Replace multiple spaces/tabs with a single space.
    return command


def detect_agent(proc_info: ProcInfo) -> DetectionResult | None:
    """
    Analyzes process metadata (name, executable path, command line, environment)
    to detect whether a process belongs to a known AI agent tool.

    Returns:
        A typed detection result, or ``None`` when no heuristic matches.
    """
    cmdline: list[str] = proc_info.get("cmdline") or []
    cmdline_str: str = " ".join(cmdline)
    envs: dict[str, str] = proc_info.get("environ") or {}
    matched_rules: list[DetectionRule] = []
    selected: tuple[AgentType, DetectionRule] | None = None

    def add_match(agent_type: AgentType, rule: DetectionRule) -> None:
        """Record a rule once and retain the first match as the classification."""
        nonlocal selected
        if rule not in matched_rules:
            matched_rules.append(rule)
        if selected is None:
            selected = (agent_type, rule)

    # Step 1: Match against known direct binary and module signatures
    for agent_type, pattern in KNOWN_AGENT_SIGNATURES:
        full_search_str = (
            f"{proc_info.get('name') or ''} {proc_info.get('exe') or ''} {cmdline_str}"
        )
        if pattern.search(full_search_str):
            rule = (
                DetectionRule.SSH_AGENT_SIGNATURE
                if "SSH_CONNECTION" in envs
                else DetectionRule.CMDLINE_AGENT_SIGNATURE
            )
            add_match(agent_type, rule)

    # Step 2: Inspect process environment variables if accessible
    if any(k in envs for k in ("CLAUDE_CODE_ENTRYPOINT", "CLAUDE_SESSION_ID")):
        add_match(AgentType.CLAUDE, DetectionRule.ENV_CLAUDE)
    if any(k.startswith("AIDER_") for k in envs):
        add_match(AgentType.AIDER, DetectionRule.ENV_AIDER)
    if "CURSOR_TRACE" in envs:
        add_match(AgentType.CURSOR, DetectionRule.ENV_CURSOR)

    # Step 3: Check heuristic subshell redirection patterns for SSH-invoked remote agents
    if REMOTE_SUBSHELL_REDIRECTION_RE.search(cmdline_str) and any(
        pattern.search(cmdline_str) or pattern.search(str(envs))
        for pattern in REMOTE_AGENT_CMD_PATTERNS
    ):
        add_match(AgentType.REMOTE_AGENT, DetectionRule.SSH_STDERR_REDIRECTION)

    # SSH does not identify the local program that issued a command.  Treat an
    # agent-less, non-interactive SSH command as a low-confidence remote-agent
    # heuristic, but make that fact visible to metric consumers in its rule code.
    # if "SSH_CONNECTION" in envs and "SSH_TTY" not in envs:
    #     add_match(AgentType.REMOTE_AGENT, DetectionRule.SSH_NONINTERACTIVE_COMMAND)

    if selected is None:
        return None
    return DetectionResult(*selected, tuple(matched_rules))


class NoLoggingWSGIRequestHandler(WSGIRequestHandler):
    """Custom WSGI request handler that suppresses routine HTTP access logs for clean stdout."""

    def log_message(self, format: str, *args: Any) -> None:
        pass


def main() -> None:
    """CLI entrypoint for running the Prometheus exporter HTTP daemon."""
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Prometheus exporter for tracking AI agent usage on Slurm login nodes"
    )
    default_port = 9799
    parser.add_argument(
        "--port",
        type=int,
        default=default_port,
        help=f"Collector HTTP port, default is {default_port}",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help=(
            "Run a single collection pass on the current system, outputs the matched and non-matched "
            "commands per user to json files for debugging/analysis."
        ),
    )

    args: argparse.Namespace = parser.parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
        # need to pull from the generator for the function to run.
        # No need to print the metrics. We just want to dump the jsons when debugging.
        list(collect_metrics(debug=True))
        exit()
    app = make_wsgi_app(AIAgentCollector())
    httpd = make_server("", args.port, app, handler_class=NoLoggingWSGIRequestHandler)
    print(f"Starting AI Agents Usage Stats Exporter on port {args.port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping exporter.")


if __name__ == "__main__":
    main()
