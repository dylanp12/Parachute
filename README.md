# 🪂 Parachute

**The Seatbelt for your AI Agent.**

A security sidecar that sits between the internet and your autonomous AI agent, providing authentication, command approval, and data leak prevention.

## Features

- 🔐 **Ingress Control**: Basic Auth, Bearer Token, IP whitelisting
- ⚡ **Command Interception**: Block or require approval for risky commands
- 🔒 **Egress Control**: Domain whitelist, PII pattern detection
- 📱 **Dashboard**: Real-time web UI for command approval
- ☁️ **Cloud Relay**: Approve commands from your phone (Phase 3)

## Quick Start

```bash
# 1. Configure
cp parachute.example.yaml parachute.yaml

# 2. Run with Docker
export PARACHUTE_PASSWORD="your-secure-password"
docker compose up -d

# 3. Access Dashboard
open http://localhost:8080/dashboard/
```

## Configuration

See `parachute.example.yaml` for all options.

| Setting | Description |
|---------|-------------|
| `auth.username` | Basic auth username |
| `auth.password_env` | Env var containing password |
| `risk_policy.block_commands` | Regex patterns to always block |
| `risk_policy.require_approval` | Regex patterns requiring HITL |
| `egress.allow_domains` | Whitelisted outbound domains |

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Internet  │────▶│  Parachute  │────▶│  OpenClaw   │
│             │     │  (Filter)   │     │  (Agent)    │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                    ┌─────────────┐
                    │  Dashboard  │
                    │  (Approve)  │
                    └─────────────┘
```

## Development

```bash
# Build
go build -o parachute ./cmd/parachute

# Run
./parachute --config parachute.example.yaml

# Test
go test ./... -v
```

## API

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /dashboard/` | Approval UI |
| `GET /api/pending` | List pending |
| `POST /api/approve/:id` | Approve |
| `POST /api/deny/:id` | Deny |
| `* /proxy/*` | Proxy to agent |

## License

MIT
