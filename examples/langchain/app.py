"""
LangChain Agent with Parachute Security Sidecar

This example shows how to run a LangChain agent with all HTTP traffic
routed through Parachute for security inspection.

The HTTP_PROXY and HTTPS_PROXY environment variables are set in docker-compose.yml,
so all outbound HTTP requests from LangChain automatically flow through Parachute's
forward proxy for egress control, PII detection, and audit logging.

For tool call interception (command blocking, HITL approval), tool calls can be
routed through Parachute's reverse proxy API.
"""

import os
import requests


def check_proxy():
    """Verify that Parachute proxy is configured."""
    http_proxy = os.environ.get("HTTP_PROXY", os.environ.get("http_proxy"))
    https_proxy = os.environ.get("HTTPS_PROXY", os.environ.get("https_proxy"))

    print(f"HTTP_PROXY:  {http_proxy}")
    print(f"HTTPS_PROXY: {https_proxy}")

    if not http_proxy:
        print("WARNING: No HTTP proxy configured. Traffic is NOT flowing through Parachute.")
        return False
    return True


def send_tool_call(tool_name: str, command: str) -> dict:
    """
    Send a tool call through Parachute's reverse proxy for interception.

    This allows Parachute to:
    - Block dangerous commands (rm -rf /, fork bombs)
    - Require HITL approval for risky commands (rm, sudo, git push)
    - Log all tool invocations for audit
    """
    parachute_url = os.environ.get("PARACHUTE_URL", "http://parachute:8080")
    auth_user = os.environ.get("PARACHUTE_USER", "admin")
    auth_pass = os.environ.get("PARACHUTE_PASSWORD", "changeme")

    payload = {
        "name": tool_name,
        "args": {"command": command},
    }

    resp = requests.post(
        f"{parachute_url}/proxy/tool_call",
        json=payload,
        auth=(auth_user, auth_pass),
        timeout=30,
    )

    if resp.status_code == 403:
        raise PermissionError(f"Command blocked by Parachute: {resp.text}")
    elif resp.status_code == 202:
        print(f"Command requires approval: {command}")
        # In a real integration, you would poll for approval
    return resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"status": resp.status_code}


if __name__ == "__main__":
    print("LangChain + Parachute Integration Example")
    print("=" * 50)

    if check_proxy():
        print("\nAll LangChain HTTP requests will flow through Parachute.")
        print("This includes API calls to OpenAI, tool downloads, etc.")
        print("\nPaarchute dashboard: http://localhost:8080/dashboard/")
