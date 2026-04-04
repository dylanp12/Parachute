# OpenClaw + Parachute

[OpenClaw](https://openclaw.ai) is an open-source AI assistant runtime (v2026.4.x).

## Quick Start

```bash
export ANTHROPIC_API_KEY="your-key"
export PARACHUTE_PASSWORD="your-password"
docker compose -f docker-compose.yml -f agents/openclaw/compose.yaml up -d
# or: ./run.sh openclaw
```

## Ports

| Port | Service |
|------|---------|
| 8080 | Parachute dashboard |
| 8888 | Parachute forward proxy |
| 18789 | OpenClaw gateway WebSocket |

## Configuration

- `openclaw.example.json` - OpenClaw config (mounted read-only into the container)
- Edit `parachute.yaml` at repo root for egress rules, PII patterns, etc.

## What Parachute adds to OpenClaw

OpenClaw has built-in exec security (allowlists, approval flows, safe-bin profiles).
Parachute adds the network layer OpenClaw doesn't cover:

- Domain-level egress whitelisting (OpenClaw has no outbound network control)
- PII detection in outbound traffic
- Centralized audit dashboard
- Forward proxy for all HTTP/HTTPS traffic
