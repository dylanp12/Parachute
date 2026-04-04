# Multi-Agent Runtime Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all new-user friction issues and add multi-agent runtime support (OpenClaw, NemoClaw, Claude Code, OpenCode, T3Code, generic).

**Architecture:** Refactor from monolithic OpenClaw-only compose to a base Parachute compose + per-runtime agent compose fragments in `agents/`. Convenience `run.sh` wrapper for one-command startup.

**Tech Stack:** Docker Compose, Go, Shell

---

### Task 1: Fix healthchecks across all compose files

**Files:**
- Modify: `docker-compose.demo.yml:25`
- Modify: `docker-compose.broker-demo.yml:25`
- Modify: `tests/integration/docker-compose.test.yml:18`

- [ ] **Step 1: Fix docker-compose.demo.yml**

Change line 25 from:
```yaml
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health"]
```
to:
```yaml
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://127.0.0.1:8080/health"]
```

- [ ] **Step 2: Fix docker-compose.broker-demo.yml**

Same change at line 25.

- [ ] **Step 3: Fix tests/integration/docker-compose.test.yml**

Same change at line 18.

- [ ] **Step 4: Commit**

```bash
git add docker-compose.demo.yml docker-compose.broker-demo.yml tests/integration/docker-compose.test.yml
git commit -m "fix: use 127.0.0.1 in healthchecks (Alpine resolves localhost to IPv6)"
```

---

### Task 2: Fix version endpoint

**Files:**
- Modify: `internal/proxy/proxy.go:563`

- [ ] **Step 1: Add runtime import and fix hardcoded version**

In `internal/proxy/proxy.go`, add `"runtime"` to the import block if not present.

Change line 563 from:
```go
			"goVersion": "go1.21+",
```
to:
```go
			"goVersion": runtime.Version(),
```

- [ ] **Step 2: Verify it compiles**

Run: `make build`

- [ ] **Step 3: Commit**

```bash
git add internal/proxy/proxy.go
git commit -m "fix: version endpoint reports actual Go runtime version"
```

---

### Task 3: Refactor docker-compose.yml to parachute-only base

**Files:**
- Modify: `docker-compose.yml`

- [ ] **Step 1: Rewrite docker-compose.yml**

Remove the `openclaw` service entirely. Keep only `parachute` + networks. Fix port mapping from `18888:8888` to `8888:8888` for consistency.

```yaml
# Parachute Security Sidecar - Base Configuration
#
# This defines only the Parachute service. Compose with an agent runtime:
#   docker compose -f docker-compose.yml -f agents/claude-code/compose.yaml up -d
#
# Or use the convenience wrapper:
#   ./run.sh claude-code
#
# Available agents: openclaw, nemoclaw, claude-code, opencode, t3-code, generic
# See agents/ directory for details.

services:
  parachute:
    build: .
    container_name: parachute
    ports:
      - "8080:8080"
      - "8888:8888"
    volumes:
      - ./parachute.yaml:/etc/parachute/config.yaml:ro
    environment:
      - PARACHUTE_PASSWORD=${PARACHUTE_PASSWORD:-changeme}
    networks:
      - public-net
      - agent-net
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://127.0.0.1:8080/health"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s

networks:
  public-net:
    driver: bridge
  agent-net:
    driver: bridge
    internal: true
```

- [ ] **Step 2: Update docker-compose.hardened.yml**

Remove the `openclaw:` service block (lines 41-65). Keep only the `parachute:` hardening. Update the header comment to mention agent-specific hardening can be added per-runtime.

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yml docker-compose.hardened.yml
git commit -m "refactor: make base compose parachute-only, agents move to agents/"
```

---

### Task 4: Create agents/openclaw/

**Files:**
- Create: `agents/openclaw/compose.yaml`
- Create: `agents/openclaw/openclaw.example.json`
- Create: `agents/openclaw/README.md`

- [ ] **Step 1: Create agents/openclaw/compose.yaml**

```yaml
# OpenClaw Agent Runtime
#
# Usage:
#   docker compose -f docker-compose.yml -f agents/openclaw/compose.yaml up -d
#
# Required env vars:
#   ANTHROPIC_API_KEY - Your Anthropic API key

services:
  openclaw:
    image: alpine/openclaw:latest
    container_name: openclaw
    networks:
      - agent-net
      - public-net
    ports:
      - "18789:18789"
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - OPENCLAW_GATEWAY_TOKEN=${OPENCLAW_GATEWAY_TOKEN:-215e65a893e0bf9463e20dc60ef2f87bc3f403919d3bca86}
      - HTTP_PROXY=http://parachute:8888
      - HTTPS_PROXY=http://parachute:8888
      - http_proxy=http://parachute:8888
      - https_proxy=http://parachute:8888
      - NO_PROXY=localhost,127.0.0.1,parachute
      - no_proxy=localhost,127.0.0.1,parachute
    volumes:
      - ../../workspace:/workspace
      - ./openclaw.example.json:/home/node/.openclaw/openclaw.json:ro
    depends_on:
      parachute:
        condition: service_healthy
    restart: unless-stopped
```

- [ ] **Step 2: Create agents/openclaw/openclaw.example.json**

Minimal OpenClaw config that works out of the box:

```json
{
  "auth": {
    "mode": "token"
  },
  "models": {
    "default": {
      "provider": "anthropic",
      "model": "claude-sonnet-4-20250514"
    }
  },
  "tools": {
    "profile": "coding"
  }
}
```

- [ ] **Step 3: Create agents/openclaw/README.md**

```markdown
# OpenClaw + Parachute

[OpenClaw](https://openclaw.ai) is an open-source AI assistant runtime (v2026.4.x).

## Quick Start

    export ANTHROPIC_API_KEY="your-key"
    export PARACHUTE_PASSWORD="your-password"
    docker compose -f docker-compose.yml -f agents/openclaw/compose.yaml up -d

## Ports

| Port | Service |
|------|---------|
| 8080 | Parachute dashboard |
| 8888 | Parachute forward proxy |
| 18789 | OpenClaw gateway WebSocket |

## Configuration

- `openclaw.example.json` - OpenClaw config (copy to `openclaw.json` to customize)
- Edit `parachute.yaml` at repo root for egress rules, PII patterns, etc.

## What Parachute adds to OpenClaw

OpenClaw has built-in exec security (allowlists, approval flows, safe-bin profiles).
Parachute adds the network layer OpenClaw doesn't cover:

- Domain-level egress whitelisting (OpenClaw has no outbound network control)
- PII detection in outbound traffic
- Centralized audit dashboard
- Forward proxy for all HTTP/HTTPS traffic
```

- [ ] **Step 4: Commit**

```bash
git add agents/openclaw/
git commit -m "feat: add OpenClaw agent runtime profile"
```

---

### Task 5: Create agents/nemoclaw/

**Files:**
- Create: `agents/nemoclaw/compose.yaml`
- Create: `agents/nemoclaw/openclaw.example.json`
- Create: `agents/nemoclaw/README.md`

- [ ] **Step 1: Create agents/nemoclaw/compose.yaml**

```yaml
# NemoClaw (NVIDIA) Agent Runtime
#
# NemoClaw wraps OpenClaw in a hardened sandbox (Landlock + seccomp + netns).
# Parachute adds application-layer egress control on top.
#
# NOTE: NemoClaw requires Linux with Landlock support (kernel 5.13+).
#       It will NOT work on macOS or Windows (use standard OpenClaw instead).
#
# Usage:
#   docker compose -f docker-compose.yml -f agents/nemoclaw/compose.yaml up -d
#
# Required env vars:
#   ANTHROPIC_API_KEY - Your Anthropic API key (or NVIDIA_API_KEY for NIM)

services:
  nemoclaw:
    image: ghcr.io/nvidia/openshell-community/sandboxes/openclaw:latest
    container_name: nemoclaw
    networks:
      - agent-net
      - public-net
    ports:
      - "18789:18789"
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - NVIDIA_API_KEY=${NVIDIA_API_KEY:-}
      - HTTP_PROXY=http://parachute:8888
      - HTTPS_PROXY=http://parachute:8888
      - http_proxy=http://parachute:8888
      - https_proxy=http://parachute:8888
      - NO_PROXY=localhost,127.0.0.1,parachute
      - no_proxy=localhost,127.0.0.1,parachute
    volumes:
      - ../../workspace:/workspace
      - ./openclaw.example.json:/sandbox/.openclaw/openclaw.json:ro
    depends_on:
      parachute:
        condition: service_healthy
    restart: unless-stopped
    # NemoClaw's OpenShell manages its own seccomp/Landlock;
    # these Docker-level options are additional defense-in-depth.
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
```

- [ ] **Step 2: Create agents/nemoclaw/openclaw.example.json**

```json
{
  "auth": {
    "mode": "token"
  },
  "models": {
    "default": {
      "provider": "anthropic",
      "model": "claude-sonnet-4-20250514"
    },
    "nvidia": {
      "provider": "nvidia",
      "model": "nvidia/nemotron-3-super-120b-a12b"
    }
  },
  "tools": {
    "profile": "coding"
  }
}
```

- [ ] **Step 3: Create agents/nemoclaw/README.md**

```markdown
# NemoClaw (NVIDIA) + Parachute

[NemoClaw](https://github.com/NVIDIA/NemoClaw) wraps OpenClaw in NVIDIA's
OpenShell sandbox (Landlock + seccomp + network namespaces).

## Requirements

- **Linux only** (kernel 5.13+ for Landlock LSM support)
- Docker with access to GHCR

## Quick Start

    export ANTHROPIC_API_KEY="your-key"
    export PARACHUTE_PASSWORD="your-password"
    docker compose -f docker-compose.yml -f agents/nemoclaw/compose.yaml up -d

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
```

- [ ] **Step 4: Commit**

```bash
git add agents/nemoclaw/
git commit -m "feat: add NemoClaw (NVIDIA) agent runtime profile"
```

---

### Task 6: Create agents/claude-code/

**Files:**
- Create: `agents/claude-code/compose.yaml`
- Create: `agents/claude-code/README.md`

- [ ] **Step 1: Create agents/claude-code/compose.yaml**

```yaml
# Claude Code Agent Runtime
#
# Anthropic's AI coding agent, routed through Parachute for egress control.
#
# Usage:
#   docker compose -f docker-compose.yml -f agents/claude-code/compose.yaml up -d
#
# Required env vars:
#   ANTHROPIC_API_KEY - Your Anthropic API key

services:
  claude-code:
    image: ${CLAUDE_CODE_IMAGE:-node:22-slim}
    container_name: claude-code
    command: ["sh", "-c", "npm install -g @anthropic-ai/claude-code && claude"]
    stdin_open: true
    tty: true
    networks:
      - agent-net
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - HTTP_PROXY=http://parachute:8888
      - HTTPS_PROXY=http://parachute:8888
      - http_proxy=http://parachute:8888
      - https_proxy=http://parachute:8888
      - NO_PROXY=localhost,127.0.0.1,parachute
      - no_proxy=localhost,127.0.0.1,parachute
    volumes:
      - ../../workspace:/workspace
    working_dir: /workspace
    depends_on:
      parachute:
        condition: service_healthy
    restart: unless-stopped
```

- [ ] **Step 2: Create agents/claude-code/README.md**

```markdown
# Claude Code + Parachute

[Claude Code](https://claude.ai/claude-code) is Anthropic's AI coding agent.

## Quick Start

    export ANTHROPIC_API_KEY="your-key"
    export PARACHUTE_PASSWORD="your-password"
    docker compose -f docker-compose.yml -f agents/claude-code/compose.yaml up -d

## What Parachute adds

All Claude Code HTTP traffic (API calls, package installs, git operations)
routes through Parachute's forward proxy:

- Egress domain whitelisting
- PII detection (blocks API keys, private keys in outbound traffic)
- Audit logging of all network requests
- Dashboard at http://localhost:8080/dashboard/

## Custom image

To use a custom Claude Code image:

    export CLAUDE_CODE_IMAGE="your-registry/claude-code:latest"
```

- [ ] **Step 3: Commit**

```bash
git add agents/claude-code/
git commit -m "feat: add Claude Code agent runtime profile"
```

---

### Task 7: Create agents/opencode/ and agents/t3-code/

**Files:**
- Create: `agents/opencode/compose.yaml`
- Create: `agents/opencode/README.md`
- Create: `agents/t3-code/compose.yaml`
- Create: `agents/t3-code/README.md`

- [ ] **Step 1: Create agents/opencode/compose.yaml**

```yaml
# OpenCode Agent Runtime
#
# Open-source coding agent, routed through Parachute for egress control.
#
# Usage:
#   docker compose -f docker-compose.yml -f agents/opencode/compose.yaml up -d
#
# Required env vars:
#   ANTHROPIC_API_KEY or OPENAI_API_KEY

services:
  opencode:
    image: ${OPENCODE_IMAGE:-node:22-slim}
    container_name: opencode
    command: ["sh", "-c", "npm install -g opencode && opencode"]
    stdin_open: true
    tty: true
    networks:
      - agent-net
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
      - OPENAI_API_KEY=${OPENAI_API_KEY:-}
      - HTTP_PROXY=http://parachute:8888
      - HTTPS_PROXY=http://parachute:8888
      - http_proxy=http://parachute:8888
      - https_proxy=http://parachute:8888
      - NO_PROXY=localhost,127.0.0.1,parachute
      - no_proxy=localhost,127.0.0.1,parachute
    volumes:
      - ../../workspace:/workspace
    working_dir: /workspace
    depends_on:
      parachute:
        condition: service_healthy
    restart: unless-stopped
```

- [ ] **Step 2: Create agents/opencode/README.md**

```markdown
# OpenCode + Parachute

[OpenCode](https://github.com/opencode-ai/opencode) is an open-source AI coding agent.

## Quick Start

    export ANTHROPIC_API_KEY="your-key"  # or OPENAI_API_KEY
    export PARACHUTE_PASSWORD="your-password"
    docker compose -f docker-compose.yml -f agents/opencode/compose.yaml up -d

## Custom image

    export OPENCODE_IMAGE="your-registry/opencode:latest"
```

- [ ] **Step 3: Create agents/t3-code/compose.yaml**

```yaml
# T3 Code Agent Runtime
#
# T3 coding agent, routed through Parachute for egress control.
#
# Usage:
#   docker compose -f docker-compose.yml -f agents/t3-code/compose.yaml up -d
#
# Required env vars:
#   ANTHROPIC_API_KEY or OPENAI_API_KEY

services:
  t3-code:
    image: ${T3_CODE_IMAGE:-node:22-slim}
    container_name: t3-code
    command: ["sh", "-c", "npm install -g t3-code && t3-code"]
    stdin_open: true
    tty: true
    networks:
      - agent-net
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
      - OPENAI_API_KEY=${OPENAI_API_KEY:-}
      - HTTP_PROXY=http://parachute:8888
      - HTTPS_PROXY=http://parachute:8888
      - http_proxy=http://parachute:8888
      - https_proxy=http://parachute:8888
      - NO_PROXY=localhost,127.0.0.1,parachute
      - no_proxy=localhost,127.0.0.1,parachute
    volumes:
      - ../../workspace:/workspace
    working_dir: /workspace
    depends_on:
      parachute:
        condition: service_healthy
    restart: unless-stopped
```

- [ ] **Step 4: Create agents/t3-code/README.md**

```markdown
# T3 Code + Parachute

T3 Code is a coding agent runtime.

## Quick Start

    export ANTHROPIC_API_KEY="your-key"  # or OPENAI_API_KEY
    export PARACHUTE_PASSWORD="your-password"
    docker compose -f docker-compose.yml -f agents/t3-code/compose.yaml up -d

## Custom image

    export T3_CODE_IMAGE="your-registry/t3-code:latest"
```

- [ ] **Step 5: Commit**

```bash
git add agents/opencode/ agents/t3-code/
git commit -m "feat: add OpenCode and T3 Code agent runtime profiles"
```

---

### Task 8: Create agents/generic/

**Files:**
- Create: `agents/generic/compose.yaml`
- Create: `agents/generic/README.md`

- [ ] **Step 1: Create agents/generic/compose.yaml**

```yaml
# Generic Agent Runtime (Bring Your Own Agent)
#
# Template for any agent that needs HTTP traffic routed through Parachute.
# Customize the image, command, and environment for your agent.
#
# Usage:
#   docker compose -f docker-compose.yml -f agents/generic/compose.yaml up -d

services:
  agent:
    image: ${AGENT_IMAGE:-python:3.13-slim}
    container_name: agent
    networks:
      - agent-net
    environment:
      - HTTP_PROXY=http://parachute:8888
      - HTTPS_PROXY=http://parachute:8888
      - http_proxy=http://parachute:8888
      - https_proxy=http://parachute:8888
      - NO_PROXY=localhost,127.0.0.1,parachute
      - no_proxy=localhost,127.0.0.1,parachute
    volumes:
      - ../../workspace:/workspace
    working_dir: /workspace
    depends_on:
      parachute:
        condition: service_healthy
    restart: unless-stopped
```

- [ ] **Step 2: Create agents/generic/README.md**

```markdown
# Generic Agent + Parachute

Template for running any AI agent through Parachute's security sidecar.

## Quick Start

    export AGENT_IMAGE="your-agent-image:latest"
    export PARACHUTE_PASSWORD="your-password"
    docker compose -f docker-compose.yml -f agents/generic/compose.yaml up -d

## How it works

The agent container routes all HTTP/HTTPS traffic through Parachute's forward
proxy via the `HTTP_PROXY` / `HTTPS_PROXY` environment variables. This gives you:

- Domain-level egress whitelisting
- PII detection in outbound traffic
- Audit logging
- HITL approval dashboard at http://localhost:8080/dashboard/

## Customizing

Edit `compose.yaml` to:
- Change the image to your agent's Docker image
- Add agent-specific environment variables
- Mount agent-specific config files
- Adjust resource limits
```

- [ ] **Step 3: Commit**

```bash
git add agents/generic/
git commit -m "feat: add generic BYOA agent runtime profile"
```

---

### Task 9: Create run.sh convenience wrapper

**Files:**
- Create: `run.sh`

- [ ] **Step 1: Create run.sh**

```bash
#!/usr/bin/env bash
set -euo pipefail

AGENTS_DIR="$(cd "$(dirname "$0")/agents" && pwd)"
COMPOSE_BASE="$(dirname "$0")/docker-compose.yml"

usage() {
    echo "Usage: ./run.sh <agent-runtime> [docker compose args...]"
    echo ""
    echo "Available agents:"
    for dir in "$AGENTS_DIR"/*/; do
        name=$(basename "$dir")
        echo "  $name"
    done
    echo ""
    echo "Examples:"
    echo "  ./run.sh claude-code              # Start Claude Code + Parachute"
    echo "  ./run.sh openclaw                 # Start OpenClaw + Parachute"
    echo "  ./run.sh nemoclaw                 # Start NemoClaw + Parachute"
    echo "  ./run.sh claude-code --build      # Rebuild and start"
    echo "  ./run.sh claude-code down          # Stop the stack"
    echo "  ./run.sh claude-code logs -f       # Follow logs"
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

AGENT="$1"
shift

AGENT_COMPOSE="$AGENTS_DIR/$AGENT/compose.yaml"

if [ ! -f "$AGENT_COMPOSE" ]; then
    echo "Error: Unknown agent '$AGENT'"
    echo ""
    usage
fi

# Default action is 'up -d' if no additional args
if [ $# -eq 0 ]; then
    set -- up -d
fi

exec docker compose -f "$COMPOSE_BASE" -f "$AGENT_COMPOSE" "$@"
```

- [ ] **Step 2: Make executable**

```bash
chmod +x run.sh
```

- [ ] **Step 3: Commit**

```bash
git add run.sh
git commit -m "feat: add run.sh convenience wrapper for agent selection"
```

---

### Task 10: Disable install.sh

**Files:**
- Modify: `install.sh`

- [ ] **Step 1: Replace install.sh with redirect message**

Replace the entire file with:

```bash
#!/bin/sh
# Parachute Installer (disabled)
#
# The install script is being reworked for multi-agent runtime support.
# Please use the Quick Start instructions instead.

echo ""
echo "  Parachute - The Seatbelt for Your AI Agent"
echo ""
echo "  The install script is being reworked."
echo "  Please follow the Quick Start instructions:"
echo ""
echo "    git clone https://github.com/dylanp12/parachute.git"
echo "    cd parachute"
echo "    cp parachute.example.yaml parachute.yaml"
echo "    export PARACHUTE_PASSWORD=\"your-password\""
echo "    export ANTHROPIC_API_KEY=\"your-key\""
echo "    ./run.sh claude-code"
echo ""
echo "  See README.md for all supported agent runtimes."
echo "  https://github.com/dylanp12/parachute"
echo ""
exit 1
```

- [ ] **Step 2: Commit**

```bash
git add install.sh
git commit -m "fix: disable broken install.sh, redirect to Quick Start"
```

---

### Task 11: Remove examples/ directory

**Files:**
- Delete: `examples/` (entire directory)

- [ ] **Step 1: Remove examples/**

The content has been migrated to `agents/`. The langchain example code (app.py, requirements.txt) is agent-framework specific, not a runtime profile -- it can be referenced from docs if needed but doesn't belong in the agents/ directory structure.

```bash
git rm -r examples/
```

- [ ] **Step 2: Commit**

```bash
git commit -m "refactor: remove examples/ (migrated to agents/)"
```

---

### Task 12: Update README.md

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Rewrite README.md**

Full rewrite with new Quick Start, agent table, updated architecture, updated project structure. See implementation for full content -- key changes:

- Quick Start uses `run.sh` with agent selection
- Supported Agents table with all 6 runtimes
- Architecture diagram becomes agent-agnostic
- Project structure reflects `agents/` directory
- Demo mode section (no API keys needed)
- Remove install.sh references
- Add `ANTHROPIC_API_KEY` to env vars prominently

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: update README for multi-agent runtime support"
```

---

### Task 13: Create workspace directory with .gitkeep

**Files:**
- Create: `workspace/.gitkeep`

- [ ] **Step 1: Create workspace/.gitkeep**

```bash
mkdir -p workspace
touch workspace/.gitkeep
```

- [ ] **Step 2: Commit**

```bash
git add workspace/.gitkeep
git commit -m "chore: add workspace directory for agent volume mounts"
```

---

### Task 14: End-to-end verification

- [ ] **Step 1: Build parachute**

Run: `make build`
Expected: Binary compiles successfully.

- [ ] **Step 2: Test version endpoint**

```bash
export PARACHUTE_PASSWORD=test
./build/parachute --config parachute.yaml &
curl -s http://localhost:8080/version
kill %1
```

Expected: `goVersion` shows `go1.25.0`, not `go1.21+`.

- [ ] **Step 3: Test docker compose with claude-code agent**

```bash
export PARACHUTE_PASSWORD=test
export ANTHROPIC_API_KEY=sk-test
docker compose -f docker-compose.yml -f agents/claude-code/compose.yaml up -d
docker compose -f docker-compose.yml -f agents/claude-code/compose.yaml ps
```

Expected: parachute container is healthy.

- [ ] **Step 4: Test run.sh**

```bash
./run.sh claude-code down
./run.sh claude-code
./run.sh claude-code ps
./run.sh claude-code down
```

Expected: All commands work.

- [ ] **Step 5: Test demo**

```bash
docker compose -f docker-compose.demo.yml up --build -d
# Wait for healthy
docker compose -f docker-compose.demo.yml ps
docker compose -f docker-compose.demo.yml down -v
```

Expected: Demo starts successfully (healthcheck passes with 127.0.0.1 fix).
