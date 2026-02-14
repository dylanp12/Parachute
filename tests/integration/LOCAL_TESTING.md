# Local Docker Testing Guide

This guide explains how to test Parachute in its containerized form locally.

## Prerequisites

- Docker and Docker Compose installed
- At least 2GB free disk space

## Quick Start with Test Environment

The test compose file includes a dummy agent for testing without needing a real AI agent:

```bash
cd tests/integration

# Start the test environment
docker compose -f docker-compose.test.yml up -d

# Wait for services to be healthy
docker compose -f docker-compose.test.yml ps

# Check logs
docker compose -f docker-compose.test.yml logs -f parachute
```

## Testing Endpoints

Once running, test the endpoints:

```bash
# Health check (no auth)
curl http://localhost:18080/health

# Version (no auth)
curl http://localhost:18080/version

# Metrics (no auth)
curl http://localhost:18080/metrics

# Auth required endpoints
curl -u admin:testpass123 http://localhost:18080/api/pending

# Test reverse proxy to dummy agent
curl -u admin:testpass123 http://localhost:18080/proxy/health

# Test command interception (blocked)
curl -u admin:testpass123 -X POST \
  -H "Content-Type: application/json" \
  -d '{"name": "bash", "args": {"command": ":(){ :|:& };:"}}' \
  http://localhost:18080/proxy/execute

# Test allowed command
curl -u admin:testpass123 -X POST \
  -H "Content-Type: application/json" \
  -d '{"name": "bash", "args": {"command": "echo hello"}}' \
  http://localhost:18080/proxy/execute
```

## Testing Egress Control

The forward proxy runs on port 18888:

```bash
# Test allowed domain
curl -x http://localhost:18888 http://httpbin.org/get

# Test blocked domain
curl -x http://localhost:18888 http://evil.com/

# Test HTTPS through proxy (allowed)
curl -x http://localhost:18888 https://api.anthropic.com

# Test HTTPS through proxy (blocked)
curl -x http://localhost:18888 https://malicious.com/
```

## Testing with Real Agent

To test with a real OpenClaw or other AI agent:

```bash
cd /path/to/parachute

# Create config
cp parachute.example.yaml parachute.yaml

# Set environment variables
export PARACHUTE_PASSWORD="your-secure-password"
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENCLAW_IMAGE="your-agent-image:tag"

# Start with production compose
docker compose up -d

# Check status
docker compose ps
docker compose logs -f
```

## Network Isolation Test

The test compose includes a network isolation test:

```bash
# Run the full test suite
cd tests/integration
./run_tests.sh

# Or manually check network isolation
docker compose -f docker-compose.test.yml exec test-agent sh -c "wget -q -O- http://google.com"
# Should fail - agent has no direct internet access

docker compose -f docker-compose.test.yml exec test-agent sh -c "wget -q -O- -e use_proxy=yes -e http_proxy=http://parachute:8888 http://httpbin.org/get"
# Should work - going through Parachute proxy (if httpbin.org is whitelisted)
```

## Cleanup

```bash
docker compose -f docker-compose.test.yml down -v
```

## Troubleshooting

### "openclaw-agent:latest not found"
The default `docker-compose.yml` expects an OpenClaw agent image. Use the test compose file instead, or set `OPENCLAW_IMAGE` to your agent image.

### Port already in use
The test compose uses ports 18080 and 18888 to avoid conflicts. Check if something else is using these ports:
```bash
lsof -i :18080
lsof -i :18888
```

### Container won't start
Check logs:
```bash
docker compose logs parachute
```
