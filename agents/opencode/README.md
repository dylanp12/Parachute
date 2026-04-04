# OpenCode + Parachute

[OpenCode](https://github.com/opencode-ai/opencode) is an open-source AI coding agent.

## Quick Start

```bash
export ANTHROPIC_API_KEY="your-key"  # or OPENAI_API_KEY
export PARACHUTE_PASSWORD="your-password"
docker compose -f docker-compose.yml -f agents/opencode/compose.yaml up -d
# or: ./run.sh opencode
```

Dashboard: http://localhost:8080/dashboard/

## Custom image

```bash
export OPENCODE_IMAGE="your-registry/opencode:latest"
```
