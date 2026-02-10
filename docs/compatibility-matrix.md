# Framework Compatibility Matrix

Parachute operates at the network layer, making it compatible with any AI agent framework that uses HTTP/HTTPS for API communication. This matrix documents tested frameworks and supported features.

## Tested Frameworks

| Framework | Egress Control | Command Interception | HITL Approval | PII Detection | MCP Support | Example Config |
|-----------|:-------------:|:-------------------:|:-------------:|:-------------:|:-----------:|:--------------:|
| Claude Code | Yes | Yes | Yes | Yes | Planned | `examples/claude-code/` |
| OpenAI Codex CLI | Yes | Yes | Yes | Yes | Planned | `examples/openai-codex/` |
| LangChain / LangGraph | Yes | Yes | Yes | Yes | Planned | `examples/langchain/` |
| CrewAI | Yes | Yes | Yes | Yes | Planned | `examples/crewai/` |
| AutoGen | Yes | Yes | Yes | Yes | Planned | `examples/crewai/` |
| OpenClaw | Yes | Yes | Yes | Yes | N/A | `docker-compose.yml` |
| Custom HTTP Agents | Yes | Yes | Yes | Yes | Planned | See docs |

## Feature Details

### Egress Control
Works with any framework via `HTTP_PROXY`/`HTTPS_PROXY` environment variables. Python (`requests`, `httpx`, `urllib3`), Node.js (`node-fetch`, `axios`), and Go (`net/http`) all support proxy environment variables.

### Command Interception
Recognized tool names: `execute_bash`, `run_command`, `bash`, `shell`, `terminal`, `execute`, `run`, `command`. Recognized argument fields: `command`, `cmd`, `script`, `code`, `input`, `CommandLine`.

### HITL Approval
Tool calls matching `require_approval` patterns are held in the approval queue. Works identically across all frameworks.

### PII Detection
Scans outbound HTTP request bodies for sensitive patterns. HTTPS CONNECT tunnels are domain-filtered only (content is encrypted end-to-end).

### MCP Support
Native Model Context Protocol interception. Policy-gates MCP `tools/call` requests with per-server and per-tool policies.

## Adding a New Framework

Parachute requires no framework-specific code. To integrate any agent framework:

1. Run the agent container on an isolated Docker network
2. Set `HTTP_PROXY` and `HTTPS_PROXY` to point to Parachute's forward proxy
3. Configure domain whitelist for the APIs your agent needs
4. Optionally route tool calls through the reverse proxy for command interception

See `docker-compose.yml` for the reference sidecar architecture.

## Known Limitations

- HTTPS CONNECT tunnels: Domain filtering works, but request body inspection is not possible (traffic is encrypted end-to-end)
- WebSocket connections: Proxied but not content-inspected
- Non-HTTP protocols: Not supported (e.g., raw TCP, gRPC without HTTP/2 proxy support)
