import sys
from pathlib import Path

import pytest

from harness.errors import Invalid
from harness.tools.catalog import create_registry
from harness.tools.executor import ToolExecutionError, ToolExecutor
from harness.tools.gateway import StdioMCPGateway, StdioServerConfig

ROOT = Path(__file__).parents[1]
SG_ARGS = {"account_id": "111111111111", "region": "us-east-1", "security_group_id": "sg-12345"}


def gateway(tmp_path):
    return StdioMCPGateway(
        {
            provider: StdioServerConfig(
                command=sys.executable,
                args=("-m", f"mcp_servers.mock_{provider}"),
                cwd=ROOT,
                mock_state_path=tmp_path / f"{provider}.db",
            )
            for provider in ("aws", "azure", "gitlab")
        }
    )


@pytest.mark.parametrize(
    "provider,count,name,arguments",
    [
        ("aws", 9, "aws.get_security_group", SG_ARGS),
        ("azure", 4, "azure.list_subscriptions", {}),
        ("gitlab", 4, "gitlab.get_project", {"project_id": 42}),
    ],
)
async def test_real_stdio_tools_list_and_call(tmp_path, provider, count, name, arguments):
    adapter = gateway(tmp_path)
    listed = await adapter.list_tools(provider)
    assert len(listed) == count
    assert all(tool["inputSchema"]["additionalProperties"] is False for tool in listed)
    registry = create_registry()
    result = await ToolExecutor(registry, adapter).execute(name, arguments)
    registry.validate_output(name, result)


async def test_stdio_mock_write_survives_server_restart(tmp_path):
    executor = ToolExecutor(create_registry(), gateway(tmp_path))
    result = await executor.execute(
        "aws.modify_security_group",
        {
            **SG_ARGS,
            "expected_revision": 1,
            "remove_rule": {"cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22, "protocol": "tcp"},
        },
    )
    assert result["changed"]
    group = await executor.execute("aws.get_security_group", SG_ARGS)
    assert group["revision"] == 2
    assert len(group["ingress"]) == 1


async def test_stdio_server_rejects_malformed_input(tmp_path):
    adapter = gateway(tmp_path)
    with pytest.raises(ToolExecutionError):
        await adapter.call(
            create_registry().resolve("aws.get_security_group"), {"ignore_policy": True}
        )


def test_subprocess_configuration_does_not_inherit_harness_credentials(monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "never-leak")
    monkeypatch.setenv("HARNESS_REVIEWER_TOKEN", "never-leak")
    params = gateway(tmp_path)._parameters("aws")
    from mcp.client.stdio import get_default_environment

    effective_environment = {**get_default_environment(), **params.env}
    assert "AWS_SECRET_ACCESS_KEY" not in effective_environment
    assert "HARNESS_REVIEWER_TOKEN" not in effective_environment


def test_stdio_executable_must_be_trusted_absolute_path():
    with pytest.raises(Invalid):
        StdioServerConfig(command="python", args=("-m", "mcp_servers.mock_aws"))
