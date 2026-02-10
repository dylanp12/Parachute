# OpenAI Codex CLI Integration Guide

## Overview

Parachute provides defense-in-depth for OpenAI's Codex CLI by adding egress control, PII detection, and audit logging on top of Codex's built-in sandboxing.

## Parachute vs Codex Built-in Sandbox

| Feature | Codex Sandbox | Parachute |
|---------|--------------|-----------|
| Network isolation | Yes (optional) | Yes (enforced) |
| Egress domain whitelisting | No | Yes |
| PII detection | No | Yes |
| Command interception | Limited | Full regex engine |
| HITL approval queue | No | Yes |
| Audit logging | No | Structured JSON |
| Prometheus metrics | No | Yes |

Parachute complements Codex's sandbox rather than replacing it. Use both for maximum security.

## Quick Start

```bash
cd examples/openai-codex/
export OPENAI_API_KEY="your-key"
export PARACHUTE_PASSWORD="your-password"
docker compose up -d
```

Dashboard: http://localhost:8080/dashboard/

## Configuration

See `examples/openai-codex/parachute.yaml`. The config is tuned for Codex's tool names (`shell`, `run_command`) and OpenAI API domains.
