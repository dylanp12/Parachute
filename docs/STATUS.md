# Parachute Security Audit Status Report

**Date:** 2026-02-01
**Version:** 1.0 MVP
**Audit Scope:** Complete codebase review for security gaps and implementation status

---

## Executive Summary

Parachute is a security sidecar for AI agents with a **partially implemented security model**. While authentication, PII detection, and command interception are functional, several critical security features are either incomplete or missing entirely. The most significant gap is that **egress domain filtering is dead code** - the configured allow_domains list is never enforced.

---

## 1. HTTP Routes & Endpoint Security

### Route Inventory

| Endpoint | Method | Auth Applied | IP Whitelist | Rate Limit |
|----------|--------|--------------|--------------|------------|
| `/health` | GET | ❌ No (intentional) | ❌ No | ❌ No |
| `/dashboard/*` | GET | ⚠️ Conditional | ⚠️ Conditional | ❌ No |
| `/api/pending` | GET | ⚠️ Conditional | ⚠️ Conditional | ❌ No |
| `/api/pending/:id` | GET | ⚠️ Conditional | ⚠️ Conditional | ❌ No |
| `/api/approve/:id` | POST | ⚠️ Conditional | ⚠️ Conditional | ❌ No |
| `/api/deny/:id` | POST | ⚠️ Conditional | ⚠️ Conditional | ❌ No |
| `/proxy/*` | ALL | ⚠️ Conditional | ⚠️ Conditional | ❌ No |

### Issues Found

1. **Authentication is conditional** - only applied if `auth.username` or `auth.token` is set in config
   - If both empty, all protected routes are publicly accessible
   - Location: `cmd/parachute/main.go:68-84`

2. **No rate limiting anywhere** - approval endpoints can be brute-forced
   - Critical for `/api/approve/:id` and `/api/deny/:id`

3. **CORS allows all origins** - `cors.New()` with default config
   - Location: `cmd/parachute/main.go:64`

4. **Password comparison is not constant-time**
   - Uses `==` operator for password check
   - Location: `internal/middleware/auth.go:50`

---

## 2. Proxy Implementation Analysis

### Architecture: Reverse Proxy (NOT Forward Proxy)

**Type:** Fixed-upstream reverse proxy
**Location:** `internal/proxy/proxy.go`

```
Client → Parachute (:8080) → OpenClaw Agent (fixed upstream, e.g. http://openclaw:3000)
```

### HTTPS CONNECT Support

**Status: ❌ NOT IMPLEMENTED**

- No handler for HTTP CONNECT method
- Uses standard `http.NewRequestWithContext()` for all requests
- Cannot act as HTTPS tunneling proxy

### Request Flow

1. Receive client request
2. Check for PII in body (✅ Working)
3. Check for risky tool calls (✅ Working)
4. Forward to upstream with copied headers
5. Return upstream response

### Issues Found

1. **No hop-by-hop header filtering** - `Connection`, `Transfer-Encoding`, etc. forwarded verbatim
   - Location: `internal/proxy/proxy.go:83-85`

2. **No response filtering** - upstream response returned without PII scan

3. **Full response buffered in memory** - no streaming, DoS risk with large responses
   - Location: `internal/proxy/proxy.go:94`

---

## 3. Tool Execution Interception

### Location
`internal/interceptor/interceptor.go`

### Recognized Tool Names
```go
"execute_bash", "run_command", "bash", "shell",
"terminal", "execute", "run", "command"
```

### Command Argument Names Checked
```go
"command", "cmd", "script", "code", "input", "CommandLine"
```

### Supported JSON Formats
1. Standard: `{"name": "bash", "args": {"command": "..."}}`
2. LangChain: `{"tool_name": "...", "tool_input": {...}}`
3. Anthropic: `{"type": "tool_use", "name": "...", "input": {...}}`

### Issues Found

1. **No shell wrapper detection** - commands like `bash -c "rm -rf /"` are not unwrapped
   - `bash -c 'dangerous_command'` checked as literal string
   - Nested commands not parsed

2. **No command separator handling** - `;`, `&&`, `||`, newlines not parsed
   - `safe_cmd ; dangerous_cmd` treated as single string

3. **No command substitution detection** - `$(...)` and backticks not detected

4. **Non-JSON payloads silently bypass** - JSON parse error = request allowed
   - Location: `internal/proxy/proxy.go:111-112`

5. **Case-sensitive tool names** - `Execute_Bash` bypasses detection

---

## 4. Approval Queue Storage

### Location
`internal/approval/approval.go`

### Storage Type: In-Memory Only

```go
type Queue struct {
    mu      sync.RWMutex
    pending map[string]*PendingCommand
    timeout time.Duration
}
```

### TTL Handling

- **Per-command expiration:** 5 minutes (configurable)
- **Cleanup goroutine:** Runs every 30 seconds
- **Gap:** Commands can linger up to 30 seconds after expiration

### Issues Found

1. **❌ No persistence** - all pending approvals lost on restart
   - No database, no file-based storage

2. **✅ Idempotent operations** - `sync.Once` prevents double-execution

3. **⚠️ No audit trail** - no record of what was approved/denied

4. **⚠️ Webhooks not wired** - `webhooks := []approval.WebhookConfig{}` hardcoded empty
   - Location: `cmd/parachute/main.go:49`

---

## 5. Egress Filtering Enforceability

### CRITICAL FINDING: Domain Whitelist is Dead Code

**Configured in `parachute.yaml`:**
```yaml
egress:
  allow_domains:
    - "api.anthropic.com"
    - "github.com"
    - "*.githubusercontent.com"
```

**Reality:** These domains are **NEVER CHECKED**

### Code Analysis

| Method | Location | Status |
|--------|----------|--------|
| `CheckURL()` | `internal/egress/egress.go:28` | ❌ Defined but never called |
| `ExtractURLsFromCommand()` | `internal/egress/egress.go:56` | ❌ Defined but never called |
| `CheckContent()` (PII) | `internal/egress/egress.go:47` | ✅ Called from proxy |

**Evidence:** Grep for `CheckURL(` returns only the definition, no call sites.

### Docker Network Isolation

**Current docker-compose.yml:**
```yaml
networks:
  agent-net:
    driver: bridge
```

**Issues:**

1. **Agent container not configured** - OpenClaw section is commented out
2. **No network isolation enforced** - both containers would have internet access
3. **No HTTP_PROXY configuration** - agent wouldn't route through Parachute
4. **No HTTPS CONNECT support** - agent HTTPS requests would fail through proxy

### Can OpenClaw Bypass Parachute?

**YES** - With current configuration:
- If OpenClaw has internet access, it can directly call any domain
- Docker bridge network provides default internet routing
- No iptables rules to block direct egress
- No HTTP_PROXY forced on agent container

---

## 6. Summary of Gaps by Priority

### Critical (Security Bypass Possible)

| Gap | Description | Location |
|-----|-------------|----------|
| **Egress filtering dead code** | `allow_domains` config completely ignored | `internal/proxy/proxy.go` |
| **No network isolation** | Agent can bypass Parachute entirely | `docker-compose.yml` |
| **Auth optional** | Empty config = no authentication | `cmd/parachute/main.go:68-84` |
| **Shell wrapper bypass** | `bash -c "dangerous"` not parsed | `internal/interceptor/interceptor.go` |

### High (Operational Risk)

| Gap | Description | Location |
|-----|-------------|----------|
| **No persistence** | Approvals lost on restart | `internal/approval/approval.go` |
| **No rate limiting** | Brute force possible | N/A |
| **Webhooks not wired** | Notifications don't work | `cmd/parachute/main.go:49` |
| **Non-constant-time comparison** | Timing attack on password | `internal/middleware/auth.go:50` |

### Medium (Defense in Depth)

| Gap | Description | Location |
|-----|-------------|----------|
| **No response PII scanning** | Data exfil via response | `internal/proxy/proxy.go:94-105` |
| **No structured audit log** | Incident response difficult | N/A |
| **No header filtering** | Info leak via headers | `internal/proxy/proxy.go:83-85` |
| **No HTTPS CONNECT** | Can't proxy HTTPS | N/A |

---

## 7. Recommended Next Steps

### Phase 1: Critical Security Fixes

1. **B1 - Enforce Egress Control**
   - Implement HTTP forward proxy with CONNECT support
   - Update docker-compose with isolated network
   - Wire `CheckURL()` to proxy flow

2. **B2 - Harden Ingress**
   - Enforce auth on all routes (or explicit opt-out)
   - Add rate limiting middleware
   - Use constant-time comparison for secrets

3. **B3 - Robust Command Interception**
   - Parse shell wrappers (`sh -c`, `bash -c`)
   - Split on command separators
   - Detect command substitution

### Phase 2: Operational Improvements

4. **B4 - Persistent Approval Queue**
   - Add SQLite/BoltDB storage
   - Implement TTL enforcement
   - Ensure idempotency across restarts

5. **B5 - Audit Logging**
   - Structured JSON logs
   - Correlation IDs per request
   - Log all security decisions

6. **B6 - Integration Tests**
   - Dummy agent container
   - Test safe/blocked/approval flows
   - Test egress allow/deny

---

## 8. Files Modified in This Audit

This document was generated by auditing:

- `cmd/parachute/main.go`
- `internal/proxy/proxy.go`
- `internal/egress/egress.go`
- `internal/interceptor/interceptor.go`
- `internal/approval/approval.go`
- `internal/approval/notifier.go`
- `internal/middleware/auth.go`
- `internal/config/config.go`
- `internal/dashboard/dashboard.go`
- `docker-compose.yml`
- `parachute.yaml`
