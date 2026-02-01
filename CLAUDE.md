# CLAUDE.md - Parachute Project Guide

## Project Overview

Parachute is a security sidecar for autonomous AI agents. It acts as a drop-in proxy that sits between the internet and an AI agent container, providing authentication, command interception, egress control, and data leak prevention.

**Core Value Proposition:** "The Seatbelt for your AI Agent" - intercepts all traffic entering and leaving the agent container, creating a safe execution environment.

## Architecture

```
Internet → Parachute (:8080 reverse proxy) → Agent Container (isolated)
                ↓
         Forward Proxy (:8888) ← Agent egress traffic
                ↓
          Dashboard (approve/deny commands)
```

### Sidecar Pattern
- **Parachute Container**: Only container with exposed ports
- **Agent Container**: Isolated in Docker private network, no direct internet access
- All ingress/egress flows through Parachute for inspection and control

## Tech Stack

- **Language**: Go 1.23+ (requires GOTOOLCHAIN=auto for Go 1.25 features)
- **Web Framework**: Fiber v3 (gofiber/fiber)
- **Database**: SQLite (modernc.org/sqlite - pure Go)
- **Config**: YAML (gopkg.in/yaml.v3)
- **Containerization**: Docker with multi-stage builds

## Project Structure

```
parachute/
├── cmd/parachute/main.go      # Entry point, server setup
├── internal/
│   ├── approval/              # HITL approval queue with persistence
│   │   ├── approval.go        # Queue management, pending commands
│   │   └── notifier.go        # Webhook notifications
│   ├── audit/                 # Structured JSON audit logging
│   │   └── logger.go          # Event types, correlation IDs
│   ├── config/                # YAML config loading with regex compilation
│   ├── dashboard/             # Web UI for command approval
│   │   └── static/            # Embedded HTML/CSS/JS
│   ├── egress/                # Outbound traffic control
│   │   └── egress.go          # Domain whitelist, PII detection
│   ├── interceptor/           # Tool call analysis
│   │   └── interceptor.go     # Command parsing, fork bomb detection
│   ├── metrics/               # Prometheus metrics
│   │   └── metrics.go         # Counter/gauge metrics, /metrics handler
│   ├── middleware/            # HTTP middleware
│   │   ├── auth.go            # Basic Auth, Bearer token, IP whitelist
│   │   ├── ratelimit.go       # Rate limiting per IP
│   │   └── correlation.go     # Request correlation IDs
│   ├── proxy/                 # Proxy handlers
│   │   ├── proxy.go           # Reverse proxy to upstream
│   │   └── forward.go         # Forward proxy for agent egress
│   ├── relay/                 # Cloud relay (Phase 3 - placeholder)
│   └── storage/               # Persistence layer
│       └── sqlite.go          # SQLite storage with cleanup
├── tests/integration/         # Docker-based integration tests
├── .github/                   # CI/CD workflows, issue templates
├── parachute.example.yaml     # Configuration template
├── docker-compose.yml         # Standard deployment
├── docker-compose.hardened.yml # Production hardening
└── Makefile                   # Build targets
```

## Key Components

### 1. Ingress Control (`internal/middleware/`)
- Basic Auth with password from environment variable
- Bearer token authentication
- IP whitelist filtering
- Rate limiting (60 req/min per IP default)
- Correlation ID injection for request tracing

### 2. Command Interception (`internal/interceptor/`)
- Parses tool calls from JSON payloads
- Recognizes tool names: `execute_bash`, `run_command`, `bash`, `shell`, etc.
- **Fork bomb detection**: Detects `:(){ :|:& };:` and variants
- Shell wrapper extraction: Handles `bash -c "..."`, `sh -c "..."`
- Actions: `ActionAllow`, `ActionBlock`, `ActionPending`

### 3. Approval Queue (`internal/approval/`)
- Thread-safe persistent queue (SQLite or in-memory)
- 5-minute default timeout with TTL cleanup
- Webhook notifications for pending commands
- Idempotency support

### 4. Egress Control (`internal/egress/` + `internal/proxy/forward.go`)
- Forward HTTP proxy on port 8888
- HTTPS CONNECT tunnel support
- Domain whitelist with wildcard support (`*.github.com`)
- PII pattern detection (credit cards, AWS keys, private keys)

### 5. Metrics (`internal/metrics/`)
- Prometheus-format `/metrics` endpoint
- Counters: requests, commands blocked/allowed, auth success/failure
- Gauges: uptime, request latency

### 6. Storage (`internal/storage/`)
- SQLite persistence for approval queue
- Auto-cleanup of expired commands
- Memory mode for development

## Development Commands

```bash
# Build
make build

# Run tests
make test-unit

# Run integration tests (requires Docker)
make test-integration

# Run locally
cp parachute.example.yaml parachute.yaml
export PARACHUTE_PASSWORD="dev-password"
./build/parachute --config parachute.yaml

# Build Docker
make docker
```

## Configuration (`parachute.yaml`)

Key sections:
- `auth`: username, password_env, token, allowed_ips
- `risk_policy.block_commands`: Regex patterns to always block
- `risk_policy.require_approval`: Regex patterns requiring HITL
- `egress.allow_domains`: Whitelisted outbound domains
- `egress.pii_patterns`: Sensitive data patterns
- `storage.type`: "memory" or "sqlite"
- `storage.path`: SQLite database path
- `upstream`: Agent container URL
- `listen`: Main server bind address (default: `:8080`)
- `proxy_listen`: Forward proxy bind address (default: `:8888`)

## API Endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /health` | No | Health check |
| `GET /healthz` | No | Kubernetes health check |
| `GET /version` | No | Version and build info |
| `GET /metrics` | No | Prometheus metrics |
| `GET /dashboard/*` | Yes | Web UI for approvals |
| `GET /api/pending` | Yes | List pending commands |
| `POST /api/approve/:id` | Yes | Approve a command |
| `POST /api/deny/:id` | Yes | Deny a command |
| `* /proxy/*` | Yes | Reverse proxy to upstream |

## Code Patterns

### Error Handling
- Return Fiber JSON responses with `error` field
- Structured audit logging with event types

### Concurrency
- `sync.RWMutex` for thread-safe queue operations
- `sync/atomic` for metrics counters
- Background goroutines for cleanup and forward proxy

### Testing
- Unit tests: `internal/interceptor/`, `internal/config/`, `internal/approval/`
- Integration tests: `tests/integration/run_tests.sh`

## Security Considerations

- Passwords from environment variables only (`password_env`)
- Fork bombs blocked by pattern matching
- PII detection for credit cards, AWS keys, private keys
- Agent container has no exposed ports
- Hardened Docker profile available
