"""Exercise the entire VS Code-style MCP -> HTTP -> governed-runtime path."""

import asyncio
import json
import shutil
import socket
import sys
import threading
import time
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

import pytest
import uvicorn
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from harness.api.app import create_app
from harness.config import Settings
from harness.runtime.container import Container
from harness.tools.gateway import InProcessMockGateway

ROOT = Path(__file__).resolve().parents[1]
OPERATOR_TOKEN = "operator-" + "a" * 40
REVIEWER_TOKEN = "reviewer-" + "b" * 40


@pytest.fixture
def live_api(tmp_path, monkeypatch):
    for folder in ["config", "agents", "skills", "policies", "knowledge"]:
        shutil.copytree(ROOT / folder, tmp_path / folder)
    monkeypatch.setenv("HARNESS_OPERATOR_TOKEN", OPERATOR_TOKEN)
    monkeypatch.setenv("HARNESS_REVIEWER_TOKEN", REVIEWER_TOKEN)
    container = Container(
        Settings(
            root=tmp_path, database_url=f"sqlite:///{tmp_path / 'harness.db'}", trace_console=False
        ),
        gateway=InProcessMockGateway(),
    )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    address = f"http://127.0.0.1:{listener.getsockname()[1]}"
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(container=container),
            log_config=None,
            log_level="critical",
            access_log=False,
            lifespan="on",
            timeout_graceful_shutdown=2,
        )
    )
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            threading.Event().wait(0.01)
        assert server.started, "Loopback harness API failed to start within five seconds"
        yield container, address, tmp_path
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()
        container.close()
        assert not thread.is_alive(), "Loopback API thread failed to stop"


@asynccontextmanager
async def facade_client(base_url, stderr_path, token=OPERATOR_TOKEN):
    environment = {"HARNESS_API_URL": base_url}
    if token is not None:
        environment["HARNESS_OPERATOR_TOKEN"] = token
    # The MCP SDK adds only its basic safe environment allowlist. In particular,
    # the review credential in the parent test process is never sent to this AI client.
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-c", "from harness.api.mcp import main; main()"],
        env=environment,
        cwd=ROOT,
    )
    assert "HARNESS_REVIEWER_TOKEN" not in parameters.env
    async with asyncio.timeout(20):
        with stderr_path.open("w") as errors:
            async with stdio_client(parameters, errlog=errors) as (reader, writer):
                async with ClientSession(
                    reader, writer, read_timeout_seconds=timedelta(seconds=10)
                ) as session:
                    await session.initialize()
                    yield session


def structured(result):
    assert not result.isError, result.content
    assert isinstance(result.structuredContent, dict)
    return result.structuredContent


async def test_mcp_facade_governed_read_write_proposals_and_candidate_learning(live_api):
    container, address, root = live_api
    async with facade_client(address, root / "facade.stderr") as session:
        listed = await session.list_tools()
        names = {tool.name for tool in listed.tools}
        assert names == {"list_agents", "list_tools", "run_agent", "propose_action", "learn"}
        assert not any(
            "approve" in name or "execute" in name or "promote" in name for name in names
        )

        read = structured(
            await session.call_tool(
                "run_agent",
                {
                    "prompt": "Check whether sg-12345 allows SSH from the internet.",
                },
            )
        )
        assert read["status"] == "completed"
        assert read["policy_decision"] == "ALLOW"
        assert read["tool"] == "aws.get_security_group"
        assert read["data"]["revision"] == 1
        assert "allows SSH" in read["message"]

        write_arguments = {
            "account_id": "111111111111",
            "region": "us-east-1",
            "security_group_id": "sg-12345",
            "expected_revision": 1,
            "remove_rule": {"cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22, "protocol": "tcp"},
        }
        for tool, arguments, risk in [
            ("aws.modify_security_group", write_arguments, "HIGH_RISK_WRITE"),
            (
                "gitlab.create_issue",
                {
                    "project_id": 42,
                    "title": "Review public SSH",
                    "description": "Review production security group sg-12345.",
                },
                "LOW_RISK_WRITE",
            ),
        ]:
            proposed = structured(
                await session.call_tool(
                    "propose_action",
                    {
                        "session_id": read["session_id"],
                        "tool": tool,
                        "arguments": arguments,
                    },
                )
            )
            assert proposed["status"] == "approval_required"
            assert proposed["policy_decision"] == "APPROVAL_REQUIRED"
            approval = container.approvals.get(proposed["approval_id"])
            assert approval["status"] == "PENDING"
            assert approval["payload"]["risk"] == risk
            assert approval["payload"]["arguments"] == arguments

        candidate = structured(
            await session.call_tool(
                "learn",
                {
                    "session_id": read["session_id"],
                    "statement": "MCP investigation observed public SSH ingress on sg-12345.",
                },
            )
        )
        assert candidate["status"] == "candidate"
        assert candidate["id"] not in {
            document["id"] for document in container.knowledge.retrieve("MCP investigation")
        }
    assert [name for name, _ in container.gateway.calls] == ["aws.get_security_group"]
    assert len(container.approvals.list()) == 2
    assert container.audit.verify()
    errors = (root / "facade.stderr").read_text()
    assert OPERATOR_TOKEN not in errors
    assert REVIEWER_TOKEN not in errors


async def test_mcp_facade_missing_and_invalid_auth_fail_without_exposing_tokens(live_api):
    container, address, root = live_api
    wrong_token = "invalid-" + "c" * 40
    async with facade_client(address, root / "invalid.stderr", token=wrong_token) as session:
        result = await session.call_tool("run_agent", {"prompt": "Inspect sg-12345"})
        assert result.isError
        rendered = json.dumps(result.model_dump(mode="json"))
        assert "Harness request denied or failed (HTTP 403)" in rendered
        assert wrong_token not in rendered
        assert OPERATOR_TOKEN not in rendered
        assert REVIEWER_TOKEN not in rendered

    with pytest.raises(Exception) as startup_error:
        async with facade_client(address, root / "missing.stderr", token=None):
            pytest.fail("The MCP facade started without its required operator credential")
    errors = (root / "missing.stderr").read_text()
    assert "Required credential is not configured" in errors
    combined = errors + (root / "invalid.stderr").read_text() + str(startup_error.value)
    assert all(token not in combined for token in [OPERATOR_TOKEN, REVIEWER_TOKEN, wrong_token])
    assert container.gateway.calls == []
