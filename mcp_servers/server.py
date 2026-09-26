"""Credential-free provider MCP servers with exact catalog schemas."""
import asyncio
import os

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from harness.errors import HarnessError
from harness.tools.catalog import create_registry
from harness.tools.gateway import InProcessMockGateway


def create_server(provider: str) -> Server:
    registry = create_registry()
    gateway = InProcessMockGateway(state_path=os.environ.get("MOCK_STATE_PATH"))
    server = Server(f"cloud-security-mock-{provider}", version="1.0.0")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [types.Tool(name=tool.name, description=tool.description,
                           inputSchema=tool.input_schema, outputSchema=tool.output_schema)
                for tool in registry.list() if tool.provider == provider]

    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict) -> dict | types.CallToolResult:
        try:
            tool = registry.resolve(name)
            if tool.provider != provider:
                raise HarnessError("Tool provider mismatch")
            args = registry.validate_input(name, arguments)
            result = await gateway.call(tool, args)
            return registry.validate_output(name, result)
        except HarnessError:
            return types.CallToolResult(isError=True, content=[types.TextContent(
                type="text", text="Mock tool request rejected; validate arguments and resource revision")])

    return server


async def serve(provider: str) -> None:
    server = create_server(provider)
    async with stdio_server() as (reader, writer):
        await server.run(reader, writer, server.create_initialization_options())


def main(provider: str) -> None:
    asyncio.run(serve(provider))
