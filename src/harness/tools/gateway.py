"""Transport boundary for untrusted MCP results and credential-free local mocks."""

import copy
import json
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from harness.errors import Conflict, Invalid, NotFound
from harness.schemas import ToolDefinition


class MCPGateway(Protocol):
    async def call(self, tool: ToolDefinition, arguments: dict) -> dict: ...


ACCOUNT = "111111111111"
REGION = "us-east-1"
SUBSCRIPTION = "sub-production-001"
TAGS = {"owner": "cloud-security", "cost_center": "SEC-100"}
PUBLIC_SSH = {"cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22, "protocol": "tcp"}


class InProcessMockGateway:
    """Deterministic cloud simulators. Optional SQLite state survives process restarts.

    This adapter is deliberately internal. Production adapters must use scoped,
    short-lived credentials supplied by a secret provider outside the model.
    """

    def __init__(self, state_path: Path | str | None = None):
        self.state_path = Path(state_path) if state_path else None
        self.calls: list[tuple[str, dict]] = []
        self._state: dict[str, dict] = {}
        if self.state_path:
            self.state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with sqlite3.connect(self.state_path) as db:
                db.execute(
                    "CREATE TABLE IF NOT EXISTS mock_resources (id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
                )
            self.state_path.chmod(0o600)

    @staticmethod
    def _initial_sg(args: dict) -> dict:
        if args["security_group_id"] not in {"sg-12345", "sg-123"}:
            raise NotFound("Mock security group not found")
        return {
            "security_group_id": args["security_group_id"],
            "account_id": args["account_id"],
            "region": args["region"],
            "name": "production-web",
            "environment": "production",
            "revision": 1,
            "ingress": [
                copy.deepcopy(PUBLIC_SSH),
                {"cidr": "0.0.0.0/0", "from_port": 443, "to_port": 443, "protocol": "tcp"},
            ],
            "tags": copy.deepcopy(TAGS),
        }

    def _security_group(self, args: dict, modify: bool = False) -> dict:
        key = f"sg:{args['account_id']}:{args['region']}:{args['security_group_id']}"

        def update(value: dict) -> dict:
            if not modify:
                return copy.deepcopy(value)
            if value["revision"] != args["expected_revision"]:
                raise Conflict("Resource revision changed; investigate and request a new approval")
            filtered = [rule for rule in value["ingress"] if rule != args["remove_rule"]]
            changed = filtered != value["ingress"]
            value["ingress"] = filtered
            if changed:
                value["revision"] += 1
            return {
                "security_group_id": value["security_group_id"],
                "revision": value["revision"],
                "changed": changed,
                "ingress": copy.deepcopy(filtered),
            }

        if self.state_path:
            with sqlite3.connect(self.state_path, timeout=5) as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT payload FROM mock_resources WHERE id=?", (key,)).fetchone()
                value = json.loads(row[0]) if row else self._initial_sg(args)
                result = update(value)
                db.execute(
                    "INSERT INTO mock_resources(id,payload) VALUES (?,?) "
                    "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
                    (key, json.dumps(value)),
                )
                return result
        if key not in self._state:
            self._state[key] = self._initial_sg(args)
        return update(self._state[key])

    @staticmethod
    def _instance(args: dict) -> dict:
        return {
            "instance_id": args.get("instance_id", "i-0123456789abcdef0"),
            "account_id": args["account_id"],
            "region": args["region"],
            "state": "running",
            "private_ip": "10.0.1.24",
            "public_ip": "203.0.113.24",
            "security_group_ids": ["sg-12345"],
            "tags": copy.deepcopy(TAGS),
        }

    async def call(self, tool: ToolDefinition, arguments: dict) -> dict:
        args = copy.deepcopy(arguments)
        self.calls.append((tool.name, args))
        # These are deterministic mock responses, not authorization decisions.
        if tool.provider == "aws" and "account_id" in args:
            if args["account_id"] != ACCOUNT or args["region"] != REGION:
                raise NotFound("Mock AWS account or region not found")
        name = tool.name
        if name == "aws.list_accounts":
            return {
                "accounts": [
                    {"account_id": ACCOUNT, "name": "production", "environment": "production"}
                ]
            }
        if name == "aws.list_instances":
            return {"instances": [self._instance(args)]}
        if name == "aws.get_instance":
            return self._instance(args)
        if name in {"aws.get_security_group", "aws.modify_security_group"}:
            return self._security_group(args, modify=name == "aws.modify_security_group")
        if name == "aws.get_bucket":
            return {
                **args,
                "environment": "production",
                "encryption": "aws:kms",
                "public_access_block": {
                    "block_public_acls": True,
                    "ignore_public_acls": True,
                    "block_public_policy": False,
                    "restrict_public_buckets": False,
                },
                "tags": copy.deepcopy(TAGS),
            }
        if name == "aws.get_bucket_policy":
            return {
                "bucket_name": args["bucket_name"],
                "policy_version": "2012-10-17",
                "statements": [
                    {
                        "effect": "Allow",
                        "principal": "*",
                        "actions": ["s3:GetObject"],
                        "resources": [f"arn:aws:s3:::{args['bucket_name']}/*"],
                    }
                ],
            }
        if name == "aws.get_cloudtrail_events":
            return {
                "events": [
                    {
                        "event_id": "c2fd2b1e-a22d-4220-bbaa-0123456789ab",
                        "event_time": "2026-09-19T06:30:00Z",
                        "event_name": "AuthorizeSecurityGroupIngress",
                        "principal": f"arn:aws:iam::{ACCOUNT}:role/platform-deploy",
                        "resource_id": args["resource_id"],
                        "source_ip": "198.51.100.10",
                    }
                ]
            }
        if name == "aws.delete_bucket":
            return {"bucket_name": args["bucket_name"], "deleted": True}
        if name == "azure.list_subscriptions":
            return {
                "subscriptions": [
                    {
                        "subscription_id": SUBSCRIPTION,
                        "name": "production",
                        "environment": "production",
                    }
                ]
            }
        if name == "azure.get_vm":
            return {
                **args,
                "location": "eastus",
                "power_state": "running",
                "private_ip": "10.10.1.24",
                "tags": copy.deepcopy(TAGS),
            }
        if name == "azure.get_storage_account":
            return {
                **args,
                "location": "eastus",
                "allow_blob_public_access": False,
                "https_only": True,
                "minimum_tls_version": "TLS1_2",
                "network_default_action": "Deny",
                "tags": copy.deepcopy(TAGS),
            }
        if name == "azure.get_network_security_group":
            return {
                **args,
                "rules": [
                    {
                        "name": "AllowSSH",
                        "priority": 100,
                        "direction": "Inbound",
                        "access": "Allow",
                        "protocol": "Tcp",
                        "source_address_prefix": "Internet",
                        "destination_port_range": "22",
                    }
                ],
            }
        if name == "gitlab.get_project":
            return {
                **args,
                "path_with_namespace": "platform/cloud-infrastructure",
                "visibility": "private",
                "default_branch": "main",
                "archived": False,
                "web_url": "https://gitlab.example.test/platform/cloud-infrastructure",
            }
        if name == "gitlab.get_pipeline":
            return {
                **args,
                "status": "success",
                "ref": "main",
                "sha": "a" * 40,
                "jobs": [
                    {"name": "secrets-scan", "stage": "security", "status": "success"},
                    {"name": "terraform-plan", "stage": "validate", "status": "success"},
                ],
            }
        if name == "gitlab.get_merge_request":
            return {
                **args,
                "title": "Restrict public SSH ingress",
                "state": "opened",
                "source_branch": "security/restrict-ssh",
                "target_branch": "main",
                "author": "platform-bot",
            }
        if name == "gitlab.create_issue":
            return {
                "project_id": args["project_id"],
                "issue_iid": 101,
                "title": args["title"],
                "web_url": f"https://gitlab.example.test/projects/{args['project_id']}/-/issues/101",
            }
        raise NotFound("Mock tool not implemented")


@dataclass(frozen=True)
class StdioServerConfig:
    """Trusted operator configuration. Never construct from an LLM tool request."""

    command: str
    args: tuple[str, ...]
    cwd: Path | None = None
    mock_state_path: Path | None = None

    def __post_init__(self) -> None:
        if not Path(self.command).is_absolute() or not Path(self.command).is_file():
            raise Invalid("MCP executable must be an existing absolute path")


class StdioMCPGateway:
    """Real MCP stdio transport using the official SDK.

    A fresh, scoped client session is created for every call. Server metadata is
    not imported into the trusted registry. No shell interpolation is involved.
    """

    def __init__(self, servers: dict[str, StdioServerConfig]):
        self._servers = dict(servers)

    def _parameters(self, provider: str):
        from mcp import StdioServerParameters

        if provider not in self._servers:
            raise NotFound("MCP provider is not configured")
        config = self._servers[provider]
        # The SDK inherits only its documented allowlist (HOME/PATH/etc.). It
        # does not inherit AWS_*, HARNESS_*, AZURE_*, GitLab tokens or our env.
        env = {"PYTHONUNBUFFERED": "1"}
        if config.mock_state_path:
            env["MOCK_STATE_PATH"] = str(config.mock_state_path)
        return StdioServerParameters(
            command=config.command, args=list(config.args), env=env, cwd=config.cwd
        )

    async def list_tools(self, provider: str) -> list[dict]:
        from mcp import ClientSession
        from mcp.client.stdio import stdio_client

        params = self._parameters(provider)
        with open(os.devnull, "w") as errlog:
            async with stdio_client(params, errlog=errlog) as (reader, writer):
                async with ClientSession(reader, writer) as session:
                    await session.initialize()
                    result = await session.list_tools()
                    return [tool.model_dump(mode="json", by_alias=True) for tool in result.tools]

    async def call(self, tool: ToolDefinition, arguments: dict) -> dict:
        from mcp import ClientSession
        from mcp.client.stdio import stdio_client

        from harness.tools.executor import ToolExecutionError, ToolTransportError

        params = self._parameters(tool.provider)
        try:
            with open(os.devnull, "w") as errlog:
                async with stdio_client(params, errlog=errlog) as (reader, writer):
                    async with ClientSession(reader, writer) as session:
                        await session.initialize()
                        result = await session.call_tool(tool.name, arguments=arguments)
        except (ToolExecutionError, Invalid):
            raise
        except Exception:
            # Transport/provider details can contain credentials or untrusted
            # text. They must never reach logs, prompts or public exceptions.
            raise ToolTransportError("MCP transport failed") from None
        # Inspect after the anyio task groups close, otherwise Python exception
        # groups can misclassify application rejections as retryable transport errors.
        if result.isError:
            raise ToolExecutionError("MCP server rejected the tool request")
        if not isinstance(result.structuredContent, dict):
            raise Invalid("MCP tool did not return structured object data")
        return result.structuredContent
