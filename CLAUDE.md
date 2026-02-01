# CLAUDE.md - Parachute Project Guide

## Project Overview

Parachute is a security sidecar for autonomous AI agents (primarily OpenClaw/Moltbot). It acts as a drop-in proxy that sits between the internet and an AI agent container, providing authentication, command interception, and data leak prevention.

**Core Value Proposition:** "The Seatbelt for your AI Agent" - intercepts all traffic entering and leaving the agent container, creating a safe execution environment.

## Architecture

```
Internet → Parachute (exposed :8080) → OpenClaw Agent (isolated, no exposed ports)
                ↓
          Dashboard (approve/deny commands)
```

### Sidecar Pattern
- **Parachute Container**: Only container with exposed ports, proxies traffic to agent
- **Agent Container**: Isolated in Docker private network, no direct internet access
- All requests/responses flow through Parachute for inspection and control

## Tech Stack

- **Language**: Go 1.25
- **Web Framework**: Fiber v3 (gofiber/fiber)
- **Config**: YAML (gopkg.in/yaml.v3)
- **UUID**: google/uuid
- **Containerization**: Docker with multi-stage builds

## Project Structure

```
/home/user/parachute/
├── cmd/parachute/main.go      # Entry point, server setup
├── internal/
│   ├── approval/              # HITL approval queue and notifications
│   │   ├── approval.go        # Queue management, pending commands
│   │   └── notifier.go        # Webhook notifications
│   ├── config/                # YAML config loading and validation
│   │   └── config.go          # Config structs, regex compilation
│   ├── dashboard/             # Web UI for command approval
│   │   ├── dashboard.go       # API routes, static file serving
│   │   └── static/            # Embedded HTML/CSS/JS
│   ├── egress/                # Outbound traffic control
│   │   └── egress.go          # Domain whitelist, PII detection
│   ├── interceptor/           # Tool call analysis
│   │   └── interceptor.go     # Command parsing, risk evaluation
│   ├── middleware/            # HTTP middleware
│   │   └── auth.go            # Basic Auth, Bearer token, IP whitelist
│   ├── proxy/                 # Upstream proxy handler
│   │   └── proxy.go           # Request forwarding, tool call checking
│   └── relay/                 # Cloud relay (Phase 3)
│       └── relay.go           # WebSocket connection to relay server
├── parachute.yaml             # Runtime configuration
├── parachute.example.yaml     # Configuration template
├── docker-compose.yml         # Multi-container deployment
├── Dockerfile                 # Multi-stage Go build
└── go.mod                     # Go module definition
```

## Key Components

### 1. Ingress Control (`internal/middleware/auth.go`)
- Basic Auth with password from environment variable
- Bearer token authentication
- IP whitelist filtering

### 2. Command Interception (`internal/interceptor/interceptor.go`)
- Parses tool calls from JSON payloads
- Recognizes multiple tool name formats: `execute_bash`, `run_command`, `bash`, `shell`, etc.
- Evaluates against risk policy regex patterns
- Actions: `ActionAllow`, `ActionBlock`, `ActionPending`

### 3. Approval Queue (`internal/approval/approval.go`)
- Thread-safe queue for pending approvals
- 5-minute default timeout
- Webhook notifications for pending commands
- Decisions: `DecisionApproved`, `DecisionDenied`, `DecisionExpired`

### 4. Egress Control (`internal/egress/egress.go`)
- Domain whitelist checking (supports wildcards like `*.github.com`)
- PII pattern detection (credit cards, private keys, AWS keys, GitHub tokens)

### 5. Proxy Handler (`internal/proxy/proxy.go`)
- Forwards requests to upstream after security checks
- Blocks requests containing PII
- Waits for approval on pending commands

## Development Commands

```bash
# Build binary
go build -o parachute ./cmd/parachute

# Run locally
./parachute --config parachute.yaml

# Run tests
go test ./... -v

# Build Docker image
docker build -t parachute .

# Run with Docker Compose
docker compose up -d
```

## Configuration (`parachute.yaml`)

Key configuration sections:
- `auth`: username, password_env, token, allowed_ips
- `risk_policy.block_commands`: Regex patterns to always block
- `risk_policy.require_approval`: Regex patterns requiring HITL
- `egress.allow_domains`: Whitelisted outbound domains
- `egress.pii_patterns`: Regex patterns for sensitive data detection
- `upstream`: Agent container URL (default: `http://openclaw:3000`)
- `listen`: Server bind address (default: `:8080`)

## API Endpoints

| Endpoint | Auth Required | Description |
|----------|---------------|-------------|
| `GET /health` | No | Health check |
| `GET /dashboard/*` | Yes | Web UI for approvals |
| `GET /api/pending` | Yes | List pending commands |
| `GET /api/pending/:id` | Yes | Get specific pending command |
| `POST /api/approve/:id` | Yes | Approve a command |
| `POST /api/deny/:id` | Yes | Deny a command |
| `* /proxy/*` | Yes | Proxy to upstream agent |

## Code Patterns

### Error Handling
- Return Fiber JSON responses with `error` field
- Log with `[BLOCKED]`, `[PENDING]`, `[APPROVED]`, `[DENIED]` prefixes

### Concurrency
- Use `sync.RWMutex` for thread-safe queue operations
- Use `sync.Once` for one-time channel operations
- Background goroutines for cleanup and relay connections

### Configuration Loading
- Regex patterns are pre-compiled at startup for performance
- Passwords read from environment variables, not config files

## Testing

Tests exist for:
- `internal/config/config_test.go` - Config loading and regex matching
- `internal/interceptor/interceptor_test.go` - Tool call parsing and risk evaluation
- `internal/approval/approval_test.go` - Queue operations

Run specific package tests:
```bash
go test ./internal/interceptor/... -v
```

## Security Considerations

- Never store passwords in config files; use `password_env` to reference env vars
- Default configuration blocks destructive commands like `rm -rf /`, fork bombs
- PII patterns catch credit cards, private keys, AWS credentials, GitHub tokens
- Agent container should have no exposed ports; only Parachute is internet-facing

## Future Phases (from PRD)

- **Phase 2**: Enhanced HITL with HTML dashboard improvements
- **Phase 3**: Cloud Relay for mobile approval ($5/month "Parachute Pro")
  - WebSocket connection to `relay.parachute.io`
  - Approve commands from phone when away from home
