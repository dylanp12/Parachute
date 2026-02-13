# 🪂 Parachute

[![CI](https://github.com/dylanp12/parachute/actions/workflows/ci.yml/badge.svg)](https://github.com/parachute-security/parachute/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/go-1.23+-blue.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Policy](https://img.shields.io/badge/Security-Policy-red.svg)](SECURITY.md)

**The Seatbelt for your AI Agent.**

A security sidecar that sits between the internet and your autonomous AI agent, providing authentication, command approval, egress control, and data leak prevention.

## Features

- **Ingress Control**: Basic Auth, Bearer Token, IP whitelisting, rate limiting
- **Command Interception**: Block or require approval for risky commands
- **Fork Bomb Detection**: Detects and blocks shell fork bombs
- **Shell Wrapper Detection**: Detects `bash -c`, `sh -c` and extracts inner commands
- **Egress Control**: Domain whitelist with HTTPS CONNECT proxy support
- **PII Detection**: Blocks requests containing credit cards, API keys, private keys
- **Persistent Storage**: SQLite-backed approval queue with TTL
- **Audit Logging**: Structured JSON logs with correlation IDs
- **Prometheus Metrics**: `/metrics` endpoint for monitoring
- **Dashboard**: Real-time web UI for command approval

## Quick Start

### Option 1: Docker Compose (Recommended)

```bash
# 1. Clone and configure
git clone https://github.com/parachute-security/parachute.git
cd parachute
cp parachute.example.yaml parachute.yaml

# 2. Set your password
export PARACHUTE_PASSWORD="your-secure-password"

# 3. Start the stack
docker compose up -d

# 4. Access Dashboard
open http://localhost:8080/dashboard/
# Login with admin / your-secure-password
```

### Option 2: Build from Source

```bash
# Build
make build

# Run
./build/parachute --config parachute.yaml
```

### Option 3: Hardened Deployment

For production use, use the hardened profile which adds resource limits and security options:

```bash
docker compose -f docker-compose.yml -f docker-compose.hardened.yml up -d
```

See [docs/iptables-hardening.md](docs/iptables-hardening.md) for host-level egress enforcement.

## Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │           Docker Private Network             │
                    │                                              │
┌─────────────┐     │  ┌─────────────┐        ┌─────────────┐     │
│   Internet  │────▶│  │  Parachute  │───────▶│  OpenClaw   │     │
│             │     │  │  :8080/:8888│        │  (Agent)    │     │
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
- All commands are intercepted and checked against policy

## Configuration

See `parachute.example.yaml` for all options.

### Authentication

```yaml
auth:
  username: "admin"
  password_env: "PARACHUTE_PASSWORD"  # Read from environment
  # token: "your-bearer-token"        # Alternative: Bearer token
  allowed_ips: []                      # Empty = allow all authenticated
```

### Risk Policy

```yaml
risk_policy:
  # Commands always blocked (regex patterns)
  block_commands:
    - "rm -rf /"
    - ":(){ :|:& };:"          # Fork bomb
    - "mkfs\\."                 # Filesystem format

  # Commands requiring manual approval (regex patterns)
  require_approval:
    - "\\brm\\b"               # Any rm command
    - "\\bsudo\\b"             # Any sudo usage
    - "\\bcurl\\b.*POST"       # Curl POST requests
```

### Egress Control

```yaml
egress:
  allow_domains:
    - "api.anthropic.com"
    - "*.github.com"           # Wildcard subdomain support

  pii_patterns:
    - "\\b4[0-9]{12}(?:[0-9]{3})?\\b"  # Credit cards
    - "-----BEGIN.*PRIVATE KEY-----"    # Private keys
    - "AKIA[0-9A-Z]{16}"                # AWS keys
```

### Storage

```yaml
storage:
  type: "sqlite"  # "memory" or "sqlite"
  path: "/var/lib/parachute/parachute.db"
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
| `GET /api/pending/:id` | Yes | Get specific pending command |
| `POST /api/approve/:id` | Yes | Approve a command |
| `POST /api/deny/:id` | Yes | Deny a command |
| `* /proxy/*` | Yes | Reverse proxy to agent |

### Forward Proxy (Agent Egress)

Port 8888 runs a forward HTTP/HTTPS proxy for agent egress control:
- Supports HTTP CONNECT for HTTPS tunneling
- Enforces domain whitelist
- Blocks PII in outbound requests

## Development

```bash
# Build
make build

# Run tests
make test

# Run unit tests only
make test-unit

# Run integration tests (requires Docker)
make test-integration

# Format code
make fmt

# Run linters
make lint

# Clean build artifacts
make clean
```

## Security Notes

### What Parachute Protects Against

1. **Unauthorized Access**: Basic Auth + Bearer Token + IP whitelist
2. **Destructive Commands**: Block `rm -rf /`, fork bombs, etc.
3. **Risky Operations**: Require manual approval for `sudo`, `ssh`, etc.
4. **Data Exfiltration**: PII detection blocks credit cards, API keys
5. **Unauthorized Egress**: Domain whitelist + HTTPS CONNECT proxy

### What Parachute Does NOT Protect Against

1. **Container Escape**: If the agent escapes its container, it can bypass Parachute
2. **Binary Execution**: Compiled binaries can make direct syscalls
3. **Kernel Exploits**: Kernel-level attacks bypass userspace proxying
4. **Timing Attacks**: While auth uses constant-time comparison, other side channels may exist

### Hardening Recommendations

1. **Enable Authentication**: Never run without `auth.username` or `auth.token`
2. **Use Persistent Storage**: Set `storage.type: sqlite` for production
3. **Restrict IP Access**: Configure `auth.allowed_ips` if possible
4. **Use Hardened Profile**: Deploy with `docker-compose.hardened.yml`
5. **Add iptables Rules**: See [docs/iptables-hardening.md](docs/iptables-hardening.md)
6. **Monitor Audit Logs**: Check JSON logs for security events

### Environment Variables

| Variable | Description |
|----------|-------------|
| `PARACHUTE_PASSWORD` | Password for basic auth (referenced by `password_env`) |
| `ANTHROPIC_API_KEY` | API key for agent (passed through) |

## Project Structure

```
parachute/
├── cmd/parachute/         # Main entry point
├── internal/
│   ├── approval/          # Approval queue with persistence
│   ├── audit/             # Structured JSON logging
│   ├── config/            # Configuration loading
│   ├── dashboard/         # Web UI
│   ├── egress/            # Domain whitelist, PII detection
│   ├── interceptor/       # Command parsing, fork bomb detection
│   ├── metrics/           # Prometheus metrics
│   ├── middleware/        # Auth, rate limiting, correlation ID
│   ├── proxy/             # Reverse proxy + forward proxy
│   ├── relay/             # Cloud relay (Phase 3 - placeholder)
│   └── storage/           # SQLite persistence
├── tests/integration/     # Integration tests
├── .github/               # CI/CD workflows, issue templates
├── docker-compose.yml     # Standard deployment
├── docker-compose.hardened.yml  # Hardened deployment
└── Makefile               # Build targets
```

## Roadmap

- [x] Phase 1: Basic proxy with auth and command interception
- [x] Phase 2: Enhanced HITL with persistent queue and audit logging
- [ ] Phase 3: Cloud Relay for mobile approval ("Parachute Pro")

## License

MIT
