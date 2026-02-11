# LangChain / LangGraph Integration Guide

## Overview

Parachute secures LangChain and LangGraph agents by controlling their network access and inspecting tool invocations. Since LangChain's HTTP transport respects standard proxy environment variables, integration requires zero code changes.

## Quick Start

```bash
cd examples/langchain/
export OPENAI_API_KEY="your-key"
export PARACHUTE_PASSWORD="your-password"
docker compose up -d
```

## How It Works

### Egress Control (Automatic)
Setting `HTTP_PROXY` and `HTTPS_PROXY` in the agent container ensures all LangChain HTTP requests (API calls, tool downloads, web scraping) flow through Parachute's forward proxy. Python's `requests`, `httpx`, and `urllib3` all respect these environment variables.

### Tool Call Interception
For LangChain tools that execute shell commands, route the tool call through Parachute's reverse proxy API:

```python
import requests

def execute_via_parachute(command: str) -> str:
    resp = requests.post(
        "http://parachute:8080/proxy/tool_call",
        json={"name": "bash", "args": {"command": command}},
        auth=("admin", os.environ["PARACHUTE_PASSWORD"]),
    )
    if resp.status_code == 403:
        raise PermissionError(f"Blocked: {resp.text}")
    return resp.text
```

### PII Detection
All outbound HTTP traffic is scanned for PII patterns (credit cards, API keys, private keys). HTTPS CONNECT tunnels are domain-filtered but not content-inspected.

## Configuration

See `examples/langchain/parachute.yaml` for the full configuration.
