# Parachute

[![CI](https://github.com/dylanp12/parachute/actions/workflows/ci.yml/badge.svg)](https://github.com/dylanp12/parachute/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/go-1.23+-blue.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Policy](https://img.shields.io/badge/Security-Policy-red.svg)](SECURITY.md)

**The Seatbelt for your AI Agent.**

A security sidecar that sits between the internet and your autonomous AI agent, providing egress control, PII detection, audit logging, and human-in-the-loop approval. Works with any agent runtime.

## Quick Start

```bash
# 1. Clone and configure
git clone https://github.com/dylanp12/parachute.git
cd parachute
cp parachute.example.yaml parachute.yaml

# 2. Set your credentials
export PARACHUTE_PASSWORD="your-secure-password"
export ANTHROPIC_API_KEY="your-api-key"

# 3. Pick an agent and start
./run.sh claude-code

# 4. Access Dashboard
open http://localhost:8080/dashboard/
# Login with admin / your-secure-password
```

Or compose manually:

```bash
docker compose -f docker-compose.yml -f agents/claude-code/compose.yaml up -d
```

## Supported Agents

| Runtime | Image | Description | Guide |
|---------|-------|-------------|-------|
| **Claude Code** | `node:22-slim` | Anthropic's AI coding agent | [agents/claude-code/](agents/claude-code/) |
| **OpenClaw** | `alpine/openclaw:latest` | Open-source AI assistant runtime | [agents/openclaw/](agents/openclaw/) |
| **NemoClaw** | `ghcr.io/nvidia/openshell-community/...` | NVIDIA hardened OpenClaw (Linux only) | [agents/nemoclaw/](agents/nemoclaw/) |
| **OpenCode** | `node:22-slim` | Open-source coding agent | [agents/opencode/](agents/opencode/) |
| **T3 Code** | `node:22-slim` | T3 coding agent | [agents/t3-code/](agents/t3-code/) |
| **Generic** | `python:3.13-slim` | Bring your own agent | [agents/generic/](agents/generic/) |

Each agent directory contains a `compose.yaml` fragment, starter configs, and a README with setup details.

## Features

- **Egress Control**: Domain whitelist with HTTPS CONNECT proxy support
- **PII Detection**: Blocks requests containing credit cards, API keys, private keys
- **Audit Logging**: Structured JSON logs with correlation IDs
- **HITL Approval**: Dashboard for reviewing and approving risky operations
- **Prometheus Metrics**: `/metrics` endpoint for monitoring
- **Dashboard**: Real-time web UI for command approval
- **Credential Broker**: Credentialless agent access to managed APIs ([docs](docs/credential-broker.md))
- **MCP Gateway**: Policy enforcement for Model Context Protocol tool calls

## Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │           Docker Private Network             │
                    │                                              │
┌─────────────┐     │  ┌─────────────┐        ┌─────────────┐     │
│   Internet  │────▶│  │  Parachute  │───────▶│   Agent     │     │
│             │     │  │  :8080/:8888│        │  (any runtime│     │
└─────────────┘     │  └──────┬──────┘        └─────────────┘     │
                    │         │                                    │
                    │  ┌──────┴──────┐                            │
                    │  │  Dashboard  │                            │
                    │  │  (Approve)  │                            │
                    │  └─────────────┘                            │
                    └──────────────────────────────────────────────┘
```

**Key Points:**
- Only Parachute has exposed ports
- Agent is on an internal network with no direct internet access
- Agent's HTTP/HTTPS traffic goes through Parachute's forward proxy (:8888)
- All outbound traffic is filtered by domain whitelist and PII patterns

## Demo Mode

Try Parachute without any API keys. The demo runs a scripted agent simulator that generates security events:

```bash
docker compose -f docker-compose.demo.yml up --build -d
open http://localhost:8080/dashboard/
# Login with admin / demo
```

## Build from Source

```bash
make build
export PARACHUTE_PASSWORD="your-password"
./build/parachute --config parachute.yaml
```

## Hardened Deployment

For production, add the hardened overlay which adds resource limits and security options:

```bash
docker compose -f docker-compose.yml -f agents/openclaw/compose.yaml -f docker-compose.hardened.yml up -d
```

See [docs/iptables-hardening.md](docs/iptables-hardening.md) for host-level egress enforcement.

## Configuration

See `parachute.example.yaml` for all options. Key sections:

### Egress Control

```yaml
egress:
  mode: "enforce"
  rules:
    - domains:
        - "api.anthropic.com"
        - "*.anthropic.com"
      label: "llm-providers"
      action: "allow"
    - domains:
        - "github.com"
        - "*.githubusercontent.com"
      label: "code-hosting"
      action: "allow"
```

### PII Detection

```yaml
egress:
  pii_patterns:
    - "AKIA[0-9A-Z]{16}"                # AWS Access Key ID
    - "-----BEGIN (?:RSA )?PRIVATE KEY-----"  # Private keys
    - "gh[pous]_[a-zA-Z0-9]{36}"        # GitHub tokens
```

### Authentication

```yaml
auth:
  username: "admin"
  password_env: "PARACHUTE_PASSWORD"
```

## API Endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /health` | No | Health check |
| `GET /healthz` | No | Kubernetes health check |
| `GET /version` | No | Version info |
| `GET /metrics` | No | Prometheus metrics |
| `GET /dashboard/*` | Yes | Approval web UI |
| `GET /api/pending` | Yes | List pending commands |
| `POST /api/approve/:id` | Yes | Approve a command |
| `POST /api/deny/:id` | Yes | Deny a command |
| `* /proxy/*` | Yes | Reverse proxy to agent |

### Forward Proxy (Agent Egress)

Port 8888 runs a forward HTTP/HTTPS proxy for agent egress control:
- Supports HTTP CONNECT for HTTPS tunneling
- Enforces domain whitelist
- Blocks PII in outbound requests

## Project Structure

```
parachute/
├── cmd/parachute/         # Main entry point
├── internal/              # Core packages
│   ├── approval/          # HITL approval queue
│   ├── audit/             # Structured JSON logging
│   ├── config/            # Configuration loading
│   ├── dashboard/         # Web UI
│   ├── egress/            # Domain whitelist, PII detection
│   ├── interceptor/       # Command parsing
│   ├── metrics/           # Prometheus metrics
│   ├── middleware/        # Auth, rate limiting
│   ├── proxy/             # Reverse + forward proxy
│   └── storage/           # SQLite persistence
├── agents/                # Agent runtime profiles
│   ├── openclaw/          # OpenClaw
│   ├── nemoclaw/          # NemoClaw (NVIDIA)
│   ├── claude-code/       # Claude Code
│   ├── opencode/          # OpenCode
│   ├── t3-code/           # T3 Code
│   └── generic/           # Bring your own agent
├── demo/                  # Demo configs and simulators
├── tests/integration/     # Integration tests
├── docker-compose.yml     # Base Parachute service
├── docker-compose.hardened.yml  # Production hardening overlay
├── run.sh                 # Convenience wrapper for agent selection
└── Makefile               # Build targets
```

## Development

```bash
make build          # Build binary
make test-unit      # Run unit tests
make test-integration  # Integration tests (requires Docker)
make fmt            # Format code
make lint           # Run linters
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PARACHUTE_PASSWORD` | Password for dashboard auth (required) |
| `ANTHROPIC_API_KEY` | API key for Anthropic agents (Claude Code, OpenClaw) |
| `OPENAI_API_KEY` | API key for OpenAI agents (OpenCode, T3 Code) |
| `NVIDIA_API_KEY` | API key for NVIDIA NIM (NemoClaw) |

## Security Notes

See [SECURITY.md](SECURITY.md) for the full security policy.

**What Parachute protects against:**
1. **Data Exfiltration**: PII detection blocks credit cards, API keys, private keys
2. **Unauthorized Egress**: Domain whitelist + HTTPS CONNECT proxy
3. **Risky Operations**: HITL approval queue for dangerous commands
4. **Audit Trail**: Structured JSON logs with correlation IDs

**Hardening recommendations:**
1. Always set `PARACHUTE_PASSWORD` (never run without auth)
2. Use the hardened Docker Compose overlay for production
3. Configure `auth.allowed_ips` to restrict dashboard access
4. Add [iptables rules](docs/iptables-hardening.md) for host-level enforcement

## License

MIT
