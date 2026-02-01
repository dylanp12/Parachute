# OpenClaw Integration Guide

Parachute integrates with OpenClaw to provide security controls for AI agent tool invocations.

## Architecture

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   Gateway    │ ───────►│  Parachute   │ ───────►│   OpenClaw   │
│   (client)   │         │  (8080)      │         │   Agent      │
└──────────────┘         └──────────────┘         └──────────────┘
                               │
                               ▼
                         ┌──────────────┐
                         │   Dashboard   │
                         │  (approve/   │
                         │   deny)      │
                         └──────────────┘
```

## Configuration

### 1. Docker Compose Setup

Ensure the OpenClaw agent is configured to route traffic through Parachute:

```yaml
services:
  parachute:
    image: parachute:latest
    ports:
      - "8080:8080"   # API/Dashboard
      - "8888:8888"   # Forward proxy
    networks:
      - public-net
      - agent-net
    environment:
      - PARACHUTE_PASSWORD=${PARACHUTE_PASSWORD}

  openclaw:
    image: openclaw-agent:latest
    networks:
      - agent-net     # ONLY internal network
    environment:
      # Route all HTTP traffic through Parachute
      - HTTP_PROXY=http://parachute:8888
      - HTTPS_PROXY=http://parachute:8888
      - NO_PROXY=localhost,127.0.0.1,parachute

networks:
  public-net:
    driver: bridge
  agent-net:
    driver: bridge
    internal: true  # No direct internet access
```

### 2. OpenClaw Gateway Configuration

Configure OpenClaw's gateway to trust Parachute as a reverse proxy:

```yaml
# openclaw-config.yaml
gateway:
  # Trust Parachute to set X-Forwarded-* headers
  trustedProxies:
    - "parachute"
    - "10.0.0.0/8"    # Docker internal network

  # Endpoint configuration
  upstream: "http://parachute:8080/proxy"

  # Authentication
  auth:
    type: "basic"
    credentials:
      username: "admin"
      passwordEnv: "PARACHUTE_PASSWORD"
```

### 3. Tool Invocation Routing

Parachute automatically intercepts requests to `/tools/invoke` and applies risk policy:

```bash
# Example: Direct tool invocation through Parachute
curl -X POST http://parachute:8080/proxy/tools/invoke \
  -H "Authorization: Basic $(echo -n admin:password | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "bash",
    "input": {
      "command": "ls -la"
    }
  }'
```

## Risk Policy Integration

### Blocked Commands

Commands matching `risk_policy.block_commands` are immediately rejected:

```yaml
risk_policy:
  block_commands:
    - "rm -rf /"
    - ":(){ :|:& };:"  # Fork bomb
    - "mkfs\\."
```

Response:
```json
{
  "error": "tool invocation blocked by policy",
  "tool": "bash",
  "reason": "matches block pattern",
  "blocked": true
}
```

### Approval Required

Commands matching `risk_policy.require_approval` are queued for human approval:

```yaml
risk_policy:
  require_approval:
    - "\\brm\\b"
    - "\\bsudo\\b"
```

The request blocks until approved/denied via the dashboard or API.

## Streaming and WebSocket Support

Parachute supports:

- **Server-Sent Events (SSE)**: `Accept: text/event-stream`
- **NDJSON Streaming**: `Accept: application/x-ndjson`
- **WebSocket Upgrades**: `Upgrade: websocket`

These are transparently proxied to the upstream agent.

## API Reference

### GET /proxy/openclaw/config

Returns suggested OpenClaw configuration:

```bash
curl http://parachute:8080/proxy/openclaw/config \
  -H "Authorization: Basic $(echo -n admin:password | base64)"
```

Response:
```json
{
  "gateway": {
    "trustedProxies": ["parachute", "10.0.0.0/8"],
    "upstream": "http://parachute:8080/proxy"
  },
  "auth": {
    "type": "basic",
    "header": "Authorization"
  }
}
```

## Security Considerations

1. **Network Isolation**: The OpenClaw agent MUST be on an internal-only network with no direct internet access.

2. **Proxy Enforcement**: Set `HTTP_PROXY`/`HTTPS_PROXY` environment variables to ensure all egress goes through Parachute.

3. **Authentication**: Always configure authentication in production. Use `allow_insecure: false` (default) to fail-closed if auth is missing.

4. **HTTPS in Production**: For production deployments, put Parachute behind a TLS-terminating reverse proxy (nginx, Caddy, etc.).

## Troubleshooting

### Tool invocations not being intercepted

Ensure requests go through `/proxy/tools/invoke` path:

```bash
# Correct
POST http://parachute:8080/proxy/tools/invoke

# Wrong (bypasses Parachute)
POST http://openclaw:3000/tools/invoke
```

### WebSocket connections failing

Check that the upstream supports WebSocket and the `Upgrade` header is being forwarded:

```bash
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  http://parachute:8080/proxy/ws
```

### Streaming responses truncated

Parachute disables response compression for streaming. Ensure the client accepts uncompressed responses.
