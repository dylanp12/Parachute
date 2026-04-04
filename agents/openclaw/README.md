# OpenClaw + Parachute

[OpenClaw](https://openclaw.ai) is an open-source AI assistant runtime (v2026.4.x).

## Anthropic API Ban

Anthropic has banned third-party harnesses (including OpenClaw) from using Claude
API keys. You must use a non-Anthropic provider:

- **OpenAI**: Set `OPENAI_API_KEY`
- **Google Gemini**: Set `GOOGLE_API_KEY`
- **NVIDIA NIM**: Set `NVIDIA_API_KEY`
- **Local models**: Use Ollama or vLLM (no key needed)

If you need Claude specifically, use the [Claude Code](../claude-code/) agent
profile instead (Anthropic's first-party tool, unaffected by the ban).

## Quick Start

```bash
export OPENAI_API_KEY="your-key"
export PARACHUTE_PASSWORD="your-password"
export OPENCLAW_GATEWAY_TOKEN="$(openssl rand -hex 24)"
docker compose -f docker-compose.yml -f agents/openclaw/compose.yaml up -d
# or: ./run.sh openclaw
```

## Ports

| Port | Service |
|------|---------|
| 8080 | Parachute dashboard |
| 8888 | Parachute forward proxy |
| 18789 | OpenClaw gateway WebSocket |

> Cannot run simultaneously with NemoClaw (port 18789 conflict).

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
