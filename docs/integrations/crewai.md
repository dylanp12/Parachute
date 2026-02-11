# CrewAI / AutoGen Integration Guide

## Overview

Parachute enforces cross-agent security policies for multi-agent frameworks like CrewAI and AutoGen. All agents in a crew share a single Parachute instance, ensuring uniform security regardless of which agent is executing.

## Quick Start

```bash
cd examples/crewai/
export OPENAI_API_KEY="your-key"
export PARACHUTE_PASSWORD="your-password"
docker compose up -d
```

## Multi-Agent Security

In a CrewAI crew, different agents may have different roles (researcher, coder, reviewer). Parachute applies the same security policies to all agents:

- All agents share the same egress whitelist
- All tool calls are intercepted regardless of which agent initiated them
- Audit logs include correlation IDs for tracing across agent interactions

## Configuration

See `examples/crewai/parachute.yaml` for the full configuration. The config includes broader approval requirements suited for multi-agent workflows where actions may be less predictable.
