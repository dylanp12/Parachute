# Multi-Agent Runtime Support + Friction Fixes

**Date:** 2026-04-03
**Status:** Approved

## Problem

Parachute's Docker setup is hardcoded to OpenClaw and broken for new users:
- Healthchecks use `localhost` (IPv6 in Alpine) instead of `127.0.0.1` -- kills all demos and examples
- `openclaw.json` missing from repo -- agent container crashes with EISDIR
- Docker Hub image `dylanp12/parachute:latest` doesn't exist
- `install.sh` non-functional (no release binaries, no Docker image)
- `ANTHROPIC_API_KEY` not mentioned in Quick Start
- Examples directories incomplete (no configs, no READMEs)
- Only OpenClaw supported; no path for Claude Code, NemoClaw, OpenCode, T3Code, etc.

## Design

### Multi-Agent Runtime Architecture

Single parameterized `docker-compose.yml` with Parachute-only base. Agent runtimes live in `agents/` with per-runtime compose fragments composed via `-f`:

```
agents/
├── openclaw/
│   ├── compose.yaml            # Service definition extending base
│   ├── openclaw.example.json   # Starter OpenClaw config
│   └── README.md               # Runtime-specific setup guide
├── nemoclaw/
│   ├── compose.yaml
│   ├── openclaw.example.json   # NemoClaw wraps OpenClaw, same config format
│   ├── blueprint.example.yaml  # NemoClaw blueprint
│   └── README.md
├── claude-code/
│   ├── compose.yaml
│   └── README.md
├── opencode/
│   ├── compose.yaml
│   └── README.md
├── t3-code/
│   ├── compose.yaml
│   └── README.md
└── generic/
    ├── compose.yaml            # BYOA template
    └── README.md
```

Usage pattern:
```bash
docker compose -f docker-compose.yml -f agents/claude-code/compose.yaml up -d
```

Convenience wrapper `run.sh` for one-command startup:
```bash
./run.sh claude-code   # picks the right compose files
./run.sh openclaw
./run.sh nemoclaw
```

### Base docker-compose.yml

Defines only:
- `parachute` service (build from source, healthcheck, ports 8080 + 8888)
- `public-net` and `agent-net` networks

No agent service. Agent is added by the runtime-specific compose fragment.

### Agent Compose Fragments

Each `agents/<runtime>/compose.yaml` defines:
- The agent service with correct image, config mounts, env vars, ports
- `HTTP_PROXY`/`HTTPS_PROXY` pointing at `parachute:8888`
- `depends_on: parachute: condition: service_healthy`
- Network attachment to `agent-net` (and `public-net` only if needed for host port mapping)

### Friction Fixes

| Issue | Fix |
|-------|-----|
| Healthcheck `localhost` | Change to `127.0.0.1` in ALL compose files |
| Missing `openclaw.json` | Move to `agents/openclaw/openclaw.example.json`, remove from base compose |
| Docker Hub image refs | Replace with `build: .` or remove; no published image yet |
| `install.sh` broken | Add early-exit with message pointing to Quick Start |
| Missing `ANTHROPIC_API_KEY` in Quick Start | Add to README step 2 |
| Port mapping `18888` vs `8888` | Standardize on `8888:8888` everywhere |
| Version endpoint `go1.21+` | Use build-time Go version from `runtime.Version()` |
| Examples directory | Migrate to `agents/`, delete `examples/` |

### README Structure

```
# Parachute

## Quick Start
1. Clone + copy config
2. Pick your agent (table of supported runtimes with links)
3. Set env vars
4. docker compose -f docker-compose.yml -f agents/<runtime>/compose.yaml up -d
5. Open dashboard

## Supported Agents (table)
| Runtime | Image | Description | Guide |
|---------|-------|-------------|-------|
| Claude Code | node:22-slim | Anthropic's coding agent | agents/claude-code/ |
| OpenClaw | alpine/openclaw:latest | Open-source AI assistant | agents/openclaw/ |
| NemoClaw | ghcr.io/nvidia/openshell-community/... | NVIDIA hardened OpenClaw | agents/nemoclaw/ |
| OpenCode | ... | Open-source coding agent | agents/opencode/ |
| T3Code | ... | T3 coding agent | agents/t3-code/ |
| Generic | any | Bring your own agent | agents/generic/ |

## Demo Mode (no API keys needed)
## Architecture
## Configuration
## API Endpoints
## Development
```

### What Stays the Same

- Parachute core (egress, proxy, dashboard, metrics, MCP gateway)
- Config format (`parachute.yaml`)
- Hardened compose overlay pattern
- Credential broker

### OpenClaw Feature Overlap Assessment

OpenClaw v2026.4.2 now has:
- Exec security modes, approval flows, safe-bin profiles -- overlaps with Parachute's deprecated reverse-proxy command interception
- SSRF protection, `openclaw doctor` audit

OpenClaw does NOT have:
- Network egress domain whitelisting -- Parachute's core value
- PII detection in outbound traffic -- Parachute's core value
- Centralized dashboard for approval/audit across agents -- Parachute's core value

Conclusion: No action needed. The MCP gateway pivot was correct. Parachute's egress + PII + dashboard remain uniquely valuable.
