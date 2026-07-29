# AI Agents Usage Stats Exporter

Prometheus exporter for tracking AI coding agent usage (e.g., Claude Code, Aider, Cursor, Copilot, OpenHands, Goose, etc.) and active user statistics on Slurm cluster login nodes.

## Features

- **Multi-Agent Process Detection**: Detects direct agent executables, Node/Python modules, and environment flags for popular AI coding agents:
  - Claude Code (`claude`, `@anthropic-ai/claude-code`)
  - Aider (`aider`)
  - Cursor Server (`cursor-server`, `cursor`)
  - GitHub Copilot CLI / Agent (`copilot-agent`, `copilot`)
  - OpenHands / OpenDevin (`openhands`)
  - Goose (`goose`)
  - Antigravity / Gemini CLI (`antigravity`)
  - Continue (`continue-server`)
- **Remote Agent & Heuristic Matcher**: Detects SSH-invoked remote agent subshells (pattern matching on stderr redirections like `2>/dev/null` combined with agent context).
- **Resource Usage Metrics**: Tracks process count, RSS memory bytes, CPU time, and thread count per user and per agent type.
- **Login Node Denominator Metric**: Exposes `login_node_active_users_total` (total unique active users on the login node) so Prometheus/Grafana can compute the percentage of active users utilizing AI agents.
- **Lightweight & Fast**: Pure Python WSGI HTTP server with zero heavy web framework dependencies.

---

## Quickstart with `uv`

### Installation & Environment Setup

```bash
git clone https://github.com/lebrice/ai-agents-usage-stats-exporter.git
cd ai-agents-usage-stats-exporter

# Install dependencies and sync virtual environment
uv sync
```

### Running Exporter Locally

```bash
# Run exporter on default port 9799
uv run ai-agents-usage-stats-exporter --port 9799
```

### Running Tests

```bash
uv run pytest
```

---

## Sample Prometheus Output

```prometheus
# HELP ai_agent_process_count Number of active AI agent processes running on the login node
# TYPE ai_agent_process_count gauge
ai_agent_process_count{agent_type="claude",user="alice"} 3.0
ai_agent_process_count{agent_type="aider",user="bob"} 1.0

# HELP ai_agent_memory_rss_bytes Resident set size memory used by AI agent processes in bytes
# TYPE ai_agent_memory_rss_bytes gauge
ai_agent_memory_rss_bytes{agent_type="claude",user="alice"} 4.51583232e+08
ai_agent_memory_rss_bytes{agent_type="aider",user="bob"} 2.15061248e+08

# HELP ai_agent_cpu_usage_seconds_total Total CPU time consumed by AI agent processes in seconds
# TYPE ai_agent_cpu_usage_seconds_total counter
ai_agent_cpu_usage_seconds_total{agent_type="claude",user="alice"} 142.50
ai_agent_cpu_usage_seconds_total{agent_type="aider",user="bob"} 35.12

# HELP ai_agent_threads_count Total number of threads spawned by AI agent processes
# TYPE ai_agent_threads_count gauge
ai_agent_threads_count{agent_type="claude",user="alice"} 36.0
ai_agent_threads_count{agent_type="aider",user="bob"} 12.0

# HELP ai_agent_active_users Count of distinct active users using a specific AI agent type
# TYPE ai_agent_active_users gauge
ai_agent_active_users{agent_type="claude"} 1.0
ai_agent_active_users{agent_type="aider"} 1.0

# HELP login_node_active_users_total Total count of unique active users logged into or running processes on the login node
# TYPE login_node_active_users_total gauge
login_node_active_users_total 25.0

# HELP ai_agent_exporter_scrape_duration_seconds Time spent collecting AI agent statistics in seconds
# TYPE ai_agent_exporter_scrape_duration_seconds gauge
ai_agent_exporter_scrape_duration_seconds 0.082
```

---

## Deployment & RPM Packaging

### Systemd Service Deployment

To deploy directly as a systemd daemon on a Slurm login node:

1. Copy the systemd service file to `/etc/systemd/system/`:
   ```bash
   sudo cp ai-agents-usage-stats-exporter.service /etc/systemd/system/
   ```
2. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now ai-agents-usage-stats-exporter
   ```

### RPM Package Building

For Enterprise Linux environments (RHEL, Rocky Linux, AlmaLinux), an RPM spec file `ai-agents-usage-stats-exporter.spec` is provided:

```bash
rpmbuild -ba ai-agents-usage-stats-exporter.spec
```

---

## License

Apache-2.0 / MIT
