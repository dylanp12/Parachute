# NemoClaw (NVIDIA) + Parachute

[NemoClaw](https://github.com/NVIDIA/NemoClaw) wraps OpenClaw in NVIDIA's
OpenShell sandbox (Landlock + seccomp + network namespaces).

## Requirements

- **Linux only** (kernel 5.13+ for Landlock LSM support)
- Docker with access to GHCR

## Anthropic API Ban

Anthropic has banned third-party harnesses (including NemoClaw) from using Claude
API keys. Use NVIDIA NIM, OpenAI, or another supported provider instead.

## Quick Start

```bash
export NVIDIA_API_KEY="your-key"  # or OPENAI_API_KEY
export PARACHUTE_PASSWORD="your-password"
docker compose -f docker-compose.yml -f agents/nemoclaw/compose.yaml up -d
# or: ./run.sh nemoclaw
```

> Cannot run simultaneously with OpenClaw (port 18789 conflict).

## Why both NemoClaw and Parachute?

NemoClaw provides kernel-level sandboxing (syscall filtering, filesystem isolation,
network namespace isolation). Parachute provides application-layer network policy:

| Layer | NemoClaw (OpenShell) | Parachute |
|-------|---------------------|-----------|
| Syscalls | seccomp filtering | - |
| Filesystem | Landlock LSM | - |
| Network | netns deny-by-default | Domain whitelist + PII detection |
| Audit | - | Dashboard + structured JSON logs |
| Approval | - | HITL approval queue |

They are complementary: NemoClaw isolates the sandbox, Parachute inspects the traffic.

## Configuration

- `openclaw.example.json` - OpenClaw config (NemoClaw uses the same format)
- For NemoClaw blueprints, see [NemoClaw docs](https://docs.nvidia.com/nemoclaw/latest/)
