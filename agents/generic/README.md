# Generic Agent + Parachute

Template for running any AI agent through Parachute's security sidecar.

## Quick Start

```bash
export AGENT_IMAGE="your-agent-image:latest"
export PARACHUTE_PASSWORD="your-password"
docker compose -f docker-compose.yml -f agents/generic/compose.yaml up -d
# or: ./run.sh generic
```

Dashboard: http://localhost:8080/dashboard/

## How it works

The agent container routes all HTTP/HTTPS traffic through Parachute's forward
proxy via the `HTTP_PROXY` / `HTTPS_PROXY` environment variables. This gives you:

- Domain-level egress whitelisting
- PII detection in outbound traffic
- Audit logging
- HITL approval dashboard

## Customizing

Edit `compose.yaml` to:
- Change the image to your agent's Docker image
- Add agent-specific environment variables
- Mount agent-specific config files
- Adjust resource limits
