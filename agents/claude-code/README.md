# Claude Code + Parachute

[Claude Code](https://claude.ai/claude-code) is Anthropic's AI coding agent.

## Quick Start

```bash
export ANTHROPIC_API_KEY="your-key"
export PARACHUTE_PASSWORD="your-password"
docker compose -f docker-compose.yml -f agents/claude-code/compose.yaml up -d
# or: ./run.sh claude-code
```

Dashboard: http://localhost:8080/dashboard/

## What Parachute adds

All Claude Code HTTP traffic (API calls, package installs, git operations)
routes through Parachute's forward proxy:

- Egress domain whitelisting
- PII detection (blocks API keys, private keys in outbound traffic)
- Audit logging of all network requests
- Dashboard at http://localhost:8080/dashboard/

## Custom image

To use a custom Claude Code image:

```bash
export CLAUDE_CODE_IMAGE="your-registry/claude-code:latest"
```
