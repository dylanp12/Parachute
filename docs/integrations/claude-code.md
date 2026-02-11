# Claude Code Integration Guide

## Overview

Parachute secures Claude Code sessions by intercepting all network traffic and tool calls. Claude Code's `bash` and `execute_bash` tools are automatically recognized by Parachute's command interceptor.

## Architecture

```
Internet ──► Parachute (:8080/:8888) ──► Claude Code (isolated)
                  │
            Dashboard (approve/deny)
```

Claude Code runs in an isolated container with no direct internet access. All HTTP/HTTPS traffic flows through Parachute's forward proxy on port 8888.

## Quick Start

```bash
cd examples/claude-code/
export ANTHROPIC_API_KEY="your-key"
export PARACHUTE_PASSWORD="your-password"
docker compose up -d
```

Dashboard: http://localhost:8080/dashboard/

## What Gets Protected

### Egress Control
All outbound HTTP/HTTPS from Claude Code flows through Parachute. Only whitelisted domains are allowed:
- `api.anthropic.com` — Claude API calls
- `github.com`, `*.githubusercontent.com` — Repository access
- `pypi.org`, `registry.npmjs.org` — Package managers

### Command Interception
Claude Code uses the `bash` tool to execute commands. Parachute intercepts these:
- **Blocked**: `rm -rf /`, fork bombs, filesystem formatting
- **Requires Approval**: `rm`, `sudo`, `git push`, `npm publish`, `docker run`
- **Allowed**: `ls`, `cat`, `echo`, `grep`, `find`, etc.

### PII Detection
Outbound traffic is scanned for:
- Credit card numbers
- AWS access keys
- Private keys
- GitHub tokens

## Configuration

See `examples/claude-code/parachute.yaml` for the full configuration. Key sections:

### Customize Blocked Commands
```yaml
risk_policy:
  block_commands:
    - "rm -rf /"
    - ":(){ :|:& };:"
    # Add your patterns here
```

### Customize Approval-Required Commands
```yaml
risk_policy:
  require_approval:
    - "\\brm\\b"
    - "\\bsudo\\b"
    # Add your patterns here
```

### Customize Allowed Domains
```yaml
egress:
  allow_domains:
    - "api.anthropic.com"
    - "github.com"
    # Add your domains here
```

## How It Works

1. Claude Code is configured with `HTTP_PROXY`/`HTTPS_PROXY` pointing to `parachute:8888`
2. All outbound HTTP/HTTPS requests are intercepted by Parachute's forward proxy
3. Domain is checked against the whitelist — blocked if not allowed
4. Request body is scanned for PII patterns
5. Tool calls sent to the reverse proxy are parsed for command extraction
6. Commands are evaluated against risk policies (block/approve/allow)
7. Everything is logged to the structured audit trail
