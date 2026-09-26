"""AI-facing MCP facade: no approve, reject, promote, shell, or credential tools."""

import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from harness.errors import Forbidden
from harness.secrets import EnvironmentSecretProvider


def create_server() -> FastMCP:
    server = FastMCP("Cloud Security Harness")
    base_url = os.environ.get("HARNESS_API_URL", "http://127.0.0.1:8000")
    token = EnvironmentSecretProvider().get_secret("HARNESS_OPERATOR_TOKEN")

    async def request(method, path, data=None):
        async with httpx.AsyncClient(
            base_url=base_url,
            timeout=60,
            follow_redirects=False,
            headers={"Authorization": f"Bearer {token}"},
        ) as client:
            response = await client.request(method, path, json=data)
            if response.is_error:
                # Never relay raw transport bodies or exception strings to the model.
                raise Forbidden(f"Harness request denied or failed (HTTP {response.status_code})")
            return response.json()

    @server.tool()
    async def list_agents() -> list[dict]:
        """List available declarative agents."""
        return await request("GET", "/v1/agents")

    @server.tool()
    async def list_tools() -> list[dict]:
        """List locally reviewed tool schemas and risks; does not execute tools."""
        return await request("GET", "/v1/tools")

    @server.tool()
    async def run_agent(
        prompt: str, agent_id: str = "cloud-security-agent", session_id: str | None = None
    ) -> dict[str, Any]:
        """Run a governed mock-model task; return session ID, result or pending approval."""
        return await request(
            "POST",
            "/v1/agent/run",
            {"prompt": prompt, "agent_id": agent_id, "session_id": session_id},
        )

    @server.tool()
    async def propose_action(
        session_id: str, tool: str, arguments: dict, agent_id: str = "cloud-security-agent"
    ) -> dict[str, Any]:
        """Propose an action; the harness independently authorizes it. Cannot approve writes."""
        return await request(
            "POST",
            "/v1/actions/propose",
            {"session_id": session_id, "agent_id": agent_id, "tool": tool, "arguments": arguments},
        )

    @server.tool()
    async def learn(
        session_id: str, statement: str | None = None, agent_id: str = "cloud-security-agent"
    ) -> dict[str, Any]:
        """Create a candidate for human review. Never updates trusted knowledge directly."""
        return await request(
            "POST",
            "/v1/learn",
            {"session_id": session_id, "agent_id": agent_id, "statement": statement},
        )

    return server


def main():
    create_server().run(transport="stdio")
