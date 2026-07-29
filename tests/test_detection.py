"""
Unit tests for AI Agents Usage Stats Exporter.

Verifies process signature detection logic, environment variable inspection,
remote agent subshell heuristics, non-agent filtering, and metric family output.
"""

from __future__ import annotations

from typing import Any

import pytest

from ai_agents_usage_stats_exporter import (
    AgentType,
    AIAgentCollector,
    DetectionResult,
    DetectionRule,
    ProcInfo,
    detect_agent,
)


@pytest.mark.parametrize(
    "proc_info, expected",
    [
        ({"name": "claude", "cmdline": ["claude"]}, (AgentType.CLAUDE, False)),
        ({"name": "codex", "cmdline": ["codex", "exec"]}, (AgentType.CODEX, False)),
        (
            {"name": "node", "cmdline": ["node", "/path/to/@anthropic-ai/claude-code/cli.js"]},
            (AgentType.CLAUDE, False),
        ),
        ({"name": "aider", "cmdline": ["aider", "--model", "gpt-4o"]}, (AgentType.AIDER, False)),
        ({"name": "python3", "cmdline": ["python3", "-m", "aider"]}, (AgentType.AIDER, False)),
        (
            {"name": "cursor-server", "cmdline": ["/home/user/.cursor-server/bin/cursor-server"]},
            (AgentType.CURSOR, False),
        ),
        ({"name": "copilot-agent", "cmdline": ["copilot-agent"]}, (AgentType.COPILOT, False)),
        ({"name": "openhands", "cmdline": ["openhands", "run"]}, (AgentType.OPENHANDS, False)),
        ({"name": "goose", "cmdline": ["goose"]}, (AgentType.GOOSE, False)),
        ({"name": "antigravity", "cmdline": ["antigravity"]}, (AgentType.ANTIGRAVITY, False)),
    ],
)
def test_direct_agent_signatures(proc_info: ProcInfo, expected: tuple[AgentType, bool]) -> None:
    """Test detection of direct AI agent binary names, packages, and module execution patterns."""
    agent_type, is_remote = expected
    expected_rule = DetectionRule.CMDLINE_AGENT_SIGNATURE
    assert detect_agent(proc_info) == DetectionResult(agent_type, expected_rule, (expected_rule,))
    assert is_remote is False


def test_environment_variable_detection() -> None:
    """Test detection of AI agents based on environment variable flags."""
    proc_info: ProcInfo = {
        "name": "python",
        "cmdline": ["python", "script.py"],
        "environ": {"CLAUDE_CODE_ENTRYPOINT": "cli"},
    }
    assert detect_agent(proc_info) == DetectionResult(
        AgentType.CLAUDE, DetectionRule.ENV_CLAUDE, (DetectionRule.ENV_CLAUDE,)
    )

    proc_info_aider: ProcInfo = {
        "name": "python",
        "cmdline": ["python", "app.py"],
        "environ": {"AIDER_MODEL": "claude-3-5-sonnet"},
    }
    assert detect_agent(proc_info_aider) == DetectionResult(
        AgentType.AIDER, DetectionRule.ENV_AIDER, (DetectionRule.ENV_AIDER,)
    )


def test_noninteractive_ssh_heuristic() -> None:
    """Non-interactive SSH commands are detected with a transparent rule code."""
    proc_info: ProcInfo = {
        "name": "sleep",
        "cmdline": ["sleep", "10"],
        "environ": {
            "SSH_CONNECTION": "192.0.2.1 22 192.0.2.2 12345",
        },
    }
    assert detect_agent(proc_info) == DetectionResult(
        AgentType.REMOTE_AGENT,
        DetectionRule.SSH_NONINTERACTIVE_COMMAND,
        (DetectionRule.SSH_NONINTERACTIVE_COMMAND,),
    )


def test_remote_subshell_heuristics() -> None:
    """Test heuristic detection of SSH-invoked subshell calls executed by remote agents."""
    proc_info: ProcInfo = {
        "name": "bash",
        "cmdline": ["bash", "-c", "git status 2>/dev/null"],
        "environ": {"CLAUDE_CODE": "1"},
    }
    assert detect_agent(proc_info) == DetectionResult(
        AgentType.REMOTE_AGENT,
        DetectionRule.SSH_STDERR_REDIRECTION,
        (DetectionRule.SSH_STDERR_REDIRECTION,),
    )


def test_non_agent_process() -> None:
    """Ensure standard non-agent user processes return None."""
    proc_info: ProcInfo = {
        "name": "vim",
        "cmdline": ["vim", "file.txt"],
        "environ": {},
    }
    assert detect_agent(proc_info) is None


def test_collector_metrics_output() -> None:
    """Test that AIAgentCollector yields expected Prometheus metric families."""
    collector: AIAgentCollector = AIAgentCollector()
    metrics: list[Any] = list(collector.collect())
    assert len(metrics) > 0
    metric_names: list[str] = [m.name for m in metrics]
    assert "ai_agent_process_count" in metric_names
    assert "login_node_active_users_total" in metric_names
    assert "ai_agent_exporter_scrape_duration_seconds" in metric_names
