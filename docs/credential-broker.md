# Credential Broker

The credential broker lets AI agents access managed APIs (like GitHub) without
holding any credentials. The agent sends requests through the broker gateway,
which resolves credentials from a secure source and injects them into the
upstream request. The agent never sees, stores, or transmits the actual token.

## Architecture

```
Agent Container (no credentials)
     |
     | GET /broker/github/repos/org/repo/issues
     v
Parachute Broker Gateway (:8081)
     |
     | 1. Match integration: "github"
     | 2. Classify route: "issues_read"
     | 3. Resolve credential (DevStatic or Pro)
     | 4. Inject Authorization header
     v
Target API (api.github.com or mock)
     |
     | 200 OK + response body
     v
Agent receives response (credential-free)
```

The broker gateway runs on a dedicated port (default `:8081`) and uses its own
HTTP client with direct dialing. It does not route through the forward proxy,
so it can reach external APIs even when the agent network is isolated.

## Managed-Host Blocking

When the broker is in `enforce` mode, the forward proxy (:8888) blocks direct
access to any host listed in a broker integration. If an agent tries to reach
`api.github.com` through the proxy instead of the broker, the request is
rejected with a 403 and a guidance message pointing the agent to the broker URL.

This prevents credential bypass: even if an agent has its own GitHub token,
all access must flow through the broker for auditing and policy enforcement.

## Quickstart

Run the self-contained broker demo with Docker Compose:

```bash
docker compose -f docker-compose.broker-demo.yml up --build
```

This starts three containers:

| Container | Role | Network |
|-----------|------|---------|
| `parachute` | Broker gateway + forward proxy | public + agent |
| `mock-github` | Simulated GitHub API (port 9090) | public |
| `broker-simulator` | Scripted agent scenarios | agent (internal) |

The simulator runs through five scenarios in a loop:

1. Brokered `GET /user` -- credential injected, returns 200
2. Brokered `GET /repos/demo-org/demo-repo` -- returns 200
3. Brokered `GET /repos/.../issues` -- returns 200
4. Brokered `GET /repos/.../pulls` -- returns 200
5. Direct proxy access to `api.github.com` -- blocked with 403

Watch the logs to see credential injection and managed-host blocking in action.
The Parachute dashboard is available at `http://localhost:8080/dashboard/`.

## Configuration Reference

The `broker` section in `parachute.yaml` controls the credential broker:

```yaml
broker:
  enabled: true
  listen: ":8081"          # Dedicated listener for broker gateway
  mode: "enforce"          # "off", "record", or "enforce"
  fail_behavior: "closed"  # "closed" (deny on error) or "open" (allow on error)
  integrations:
    - name: "github"
      hosts: ["api.github.com"]
      enabled: true
      credential_source: "dev_static"    # or "pro"
      static_token_env: "GITHUB_TOKEN"   # env var for dev_static source
      header_name: "Authorization"       # default
      token_prefix: "Bearer "            # default
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Master switch for the broker gateway |
| `listen` | string | Bind address for the broker listener (default `:8081`) |
| `mode` | string | `off` disables, `record` logs only, `enforce` blocks and injects |
| `fail_behavior` | string | `closed` denies when credential resolution fails; `open` allows passthrough |
| `integrations` | list | One entry per managed API integration |

### Integration Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Integration identifier used in URLs (`/broker/{name}/...`) |
| `hosts` | list | Hostnames to match for this integration |
| `enabled` | bool | Per-integration toggle |
| `credential_source` | string | `dev_static` (env var) or `pro` (Pro control plane) |
| `static_token_env` | string | Environment variable holding the token (dev_static only) |
| `header_name` | string | HTTP header for credential injection (default: `Authorization`) |
| `token_prefix` | string | Prefix before token value (default: `Bearer `) |

## Route Classification

The broker classifies each request into a route class for auditing and policy.
For GitHub, the classifier recognizes these classes:

| Route Class | Example Paths |
|-------------|---------------|
| `repo_metadata_read` | `GET /repos/{owner}/{repo}`, `GET /user` |
| `issues_read` | `GET /repos/{owner}/{repo}/issues` |
| `issues_write` | `POST /repos/{owner}/{repo}/issues` |
| `pulls_read` | `GET /repos/{owner}/{repo}/pulls` |
| `pulls_write` | `POST /repos/{owner}/{repo}/pulls` |
| `admin` | `DELETE /repos/{owner}/{repo}` |
| `unknown` | Unrecognized paths |

Route classes are used by the Pro control plane for fine-grained access control.
In OSS mode with `dev_static`, all route classes are allowed.

## Credential Sources

### DevStatic (Development)

Reads a token from an environment variable. Suitable for local development and
demos. The token is injected as-is with the configured prefix.

```yaml
credential_source: "dev_static"
static_token_env: "GITHUB_TOKEN"
```

Set the env var in your shell or docker-compose environment section.

### Pro (Production)

Calls the Parachute Pro control plane API to resolve credentials. Pro manages
token rotation, scoping, and per-agent access policies.

```yaml
credential_source: "pro"
```

Requires `broker.pro_url` and `broker.api_key_env` to be configured.
See the Pro documentation for setup instructions.

## Egress Integration

When the broker is enabled in `enforce` mode, add deny rules for managed hosts
in the egress config to prevent agents from bypassing the broker:

```yaml
egress:
  mode: "enforce"
  rules:
    - domains: ["api.github.com"]
      label: "github-managed"
      action: "deny"
```

This ensures all GitHub API traffic flows through the broker gateway where
credentials are injected and requests are audited.
