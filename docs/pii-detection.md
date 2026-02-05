# PII Detection in Parachute

Parachute includes pattern-based detection of Personally Identifiable Information (PII) and sensitive data to prevent data exfiltration from AI agents.

## What Parachute Can Scan

### ✅ Scanned Traffic

1. **Reverse Proxy Requests** (`/proxy/*`)
   - All request bodies sent through the reverse proxy
   - JSON payloads including tool invocations
   - Form data and other content types

2. **Plaintext HTTP via Forward Proxy**
   - HTTP (not HTTPS) requests through the forward proxy on port 8888
   - Request bodies in non-encrypted connections

3. **Tool Call Arguments**
   - Command strings in tool invocations
   - Arguments passed to shell/execute tools

### ❌ NOT Scanned (HTTPS Limitation)

**HTTPS CONNECT Tunnels**: When the agent makes HTTPS requests through the forward proxy, Parachute establishes a CONNECT tunnel. The traffic inside this tunnel is **end-to-end encrypted** and **cannot be inspected** without TLS interception (MITM).

This means:
- HTTPS requests to `api.anthropic.com` - content NOT scanned
- HTTPS requests to `pypi.org` - content NOT scanned
- Any other HTTPS destination - content NOT scanned

## Configured PII Patterns

Default patterns in `parachute.yaml`:

```yaml
egress:
  pii_patterns:
    # Credit card numbers (Visa, Mastercard, Amex)
    - "\\b4[0-9]{12}(?:[0-9]{3})?\\b"           # Visa
    - "\\b5[1-5][0-9]{14}\\b"                   # Mastercard
    - "\\b3[47][0-9]{13}\\b"                    # Amex

    # Cryptographic keys
    - "-----BEGIN.*PRIVATE KEY-----"            # Private keys
    - "-----BEGIN PGP PRIVATE KEY BLOCK-----"   # PGP keys

    # Cloud provider credentials
    - "AKIA[0-9A-Z]{16}"                        # AWS Access Key ID
    - "(?i)aws.?secret.?access.?key"            # AWS Secret patterns

    # Other sensitive patterns
    - "\\b\\d{3}-\\d{2}-\\d{4}\\b"             # US SSN
    - "ghp_[a-zA-Z0-9]{36}"                     # GitHub Personal Token
    - "gho_[a-zA-Z0-9]{36}"                     # GitHub OAuth Token
```

## Security Model

### Defense in Depth

PII detection is ONE layer in a defense-in-depth strategy:

1. **Network Isolation** - Agent on internal-only network
2. **Domain Whitelist** - Only allowed domains reachable
3. **Command Interception** - Shell commands inspected
4. **PII Detection** - Plaintext content scanned
5. **Human Approval** - High-risk operations require approval

### Threat Model

| Threat | Mitigation | Effectiveness |
|--------|-----------|---------------|
| Agent sends PII via HTTP | PII scanning | ✅ High |
| Agent sends PII via HTTPS | Domain whitelist | ⚠️ Medium |
| Agent encodes PII (base64) | Pattern detection | ⚠️ Limited |
| Agent exfils via allowed domain | Trust + monitoring | ⚠️ Limited |

## Recommendations

### For Production Deployments

1. **Minimize HTTPS Allowlist**
   ```yaml
   egress:
     allow_domains:
       - "api.anthropic.com"  # Required for agent
       # Avoid wildcards - be specific
   ```

2. **Add Custom PII Patterns**
   Add patterns specific to your data:
   ```yaml
   egress:
     pii_patterns:
       - "CUSTOMER_ID_[A-Z0-9]{10}"  # Internal IDs
       - "(?i)internal.*secret"       # Internal markers
   ```

3. **Monitor Audit Logs**
   Watch for `pii_scrub` events:
   ```bash
   tail -f /var/log/parachute/audit.log | jq 'select(.event_type=="pii_scrub")'
   ```

### Optional: TLS Interception (Advanced)

For environments requiring HTTPS content inspection:

1. **Deploy a MITM proxy** (e.g., mitmproxy) between Parachute and the internet
2. **Install CA certificates** in the agent container
3. **Route Parachute's egress** through the MITM proxy

⚠️ **Warning**: TLS interception adds complexity and may break certificate pinning. Only use in controlled environments where you own all endpoints.

## API

### Check Content for PII

```go
import "github.com/parachute-security/parachute/internal/egress"

filter := egress.New(&config.Egress)
result := filter.CheckContent(content)
if !result.Allowed {
    log.Printf("PII detected: %s (pattern: %s)", result.Reason, result.Pattern)
}
```

### Events

PII detection events in audit log:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "event_type": "pii_scrub",
  "correlation_id": "abc12345",
  "client_ip": "10.0.0.5",
  "pattern": "AKIA[0-9A-Z]{16}",
  "reason": "AWS access key detected"
}
```

## Limitations Summary

| Limitation | Reason | Workaround |
|-----------|--------|------------|
| HTTPS content not scanned | E2E encryption | Domain whitelist + TLS MITM |
| Encoded content may bypass | Pattern-based | Add encoding-aware patterns |
| High false positive rate | Regex matching | Tune patterns for your data |
| Performance impact | Regex on all content | Limit body size scanning |
