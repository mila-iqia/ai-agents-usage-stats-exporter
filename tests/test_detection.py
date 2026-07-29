"""
Unit tests for AI Agents Usage Stats Exporter.

Verifies process signature detection logic, environment variable inspection,
remote agent subshell heuristics, non-agent filtering, and metric family output.
"""

from __future__ import annotations

from typing import Any
import pytest
from ai_agents_usage_stats_exporter import AIAgentCollector, ProcInfo, detect_agent_type


@pytest.mark.parametrize(
    "proc_info, expected",
    [
        ({"name": "claude", "cmdline": ["claude"]}, ("claude", False)),
        ({"name": "codex", "cmdline": ["codex", "exec"]}, ("codex", False)),
        (
            {"name": "node", "cmdline": ["node", "/path/to/@anthropic-ai/claude-code/cli.js"]},
            ("claude", False),
        ),
        ({"name": "aider", "cmdline": ["aider", "--model", "gpt-4o"]}, ("aider", False)),
        ({"name": "python3", "cmdline": ["python3", "-m", "aider"]}, ("aider", False)),
        (
            {"name": "cursor-server", "cmdline": ["/home/user/.cursor-server/bin/cursor-server"]},
            ("cursor", False),
        ),
        ({"name": "copilot-agent", "cmdline": ["copilot-agent"]}, ("copilot", False)),
        ({"name": "openhands", "cmdline": ["openhands", "run"]}, ("openhands", False)),
        ({"name": "goose", "cmdline": ["goose"]}, ("goose", False)),
        ({"name": "antigravity", "cmdline": ["antigravity"]}, ("antigravity", False)),
    ],
)
def test_direct_agent_signatures(proc_info: ProcInfo, expected: tuple[str | None, bool]) -> None:
    """Test detection of direct AI agent binary names, packages, and module execution patterns."""
    result: tuple[str | None, bool] = detect_agent_type(proc_info)
    assert result == expected


def test_environment_variable_detection() -> None:
    """Test detection of AI agents based on environment variable flags."""
    proc_info: ProcInfo = {
        "name": "python",
        "cmdline": ["python", "script.py"],
        "environ": {"CLAUDE_CODE_ENTRYPOINT": "cli"},
    }
    assert detect_agent_type(proc_info) == ("claude", True)

    proc_info_aider: ProcInfo = {
        "name": "python",
        "cmdline": ["python", "app.py"],
        "environ": {"AIDER_MODEL": "claude-3-5-sonnet"},
    }
    assert detect_agent_type(proc_info_aider) == ("aider", True)


def test_explicit_remote_ssh_agent_marker() -> None:
    """Only an explicitly marked SSH command is categorized as remote SSH agent use."""
    proc_info: ProcInfo = {
        "name": "sleep",
        "cmdline": ["sleep", "10"],
        "environ": {
            "AI_AGENTS_USAGE_EXPORTER_AGENT_TYPE": "codex",
            "SSH_CONNECTION": "192.0.2.1 22 192.0.2.2 12345",
        },
    }
    assert detect_agent_type(proc_info) == ("codex", True)


def test_remote_subshell_heuristics() -> None:
    """Test heuristic detection of SSH-invoked subshell calls executed by remote agents."""
    proc_info: ProcInfo = {
        "name": "bash",
        "cmdline": ["bash", "-c", "git status 2>/dev/null"],
        "environ": {"CLAUDE_CODE": "1"},
    }
    assert detect_agent_type(proc_info) == ("remote_agent", True)


def test_non_agent_process() -> None:
    """Ensure standard non-agent user processes return None."""
    proc_info: ProcInfo = {
        "name": "vim",
        "cmdline": ["vim", "file.txt"],
        "environ": {},
    }
    assert detect_agent_type(proc_info) == (None, False)


def test_collector_metrics_output() -> None:
    """Test that AIAgentCollector yields expected Prometheus metric families."""
    collector: AIAgentCollector = AIAgentCollector()
    metrics: list[Any] = list(collector.collect())
    assert len(metrics) > 0
    metric_names: list[str] = [m.name for m in metrics]
    assert "ai_agent_process_count" in metric_names
    assert "login_node_active_users_total" in metric_names
    assert "ai_agent_exporter_scrape_duration_seconds" in metric_names
