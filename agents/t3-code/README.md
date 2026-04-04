# T3 Code + Parachute

T3 Code is a coding agent runtime.

## Quick Start

```bash
export ANTHROPIC_API_KEY="your-key"  # or OPENAI_API_KEY
export PARACHUTE_PASSWORD="your-password"
docker compose -f docker-compose.yml -f agents/t3-code/compose.yaml up -d
# or: ./run.sh t3-code
```

Dashboard: http://localhost:8080/dashboard/

## Custom image

```bash
export T3_CODE_IMAGE="your-registry/t3-code:latest"
```
