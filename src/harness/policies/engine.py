from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field

from harness.agents.loader import AgentDefinition
from harness.errors import Forbidden, Invalid
from harness.schemas import Decision, PolicyDecision, Principal, Risk, StrictModel, ToolDefinition
from harness.util import digest


class Rule(StrictModel):
    id: str
    decision: Decision
    reason: str
    users: list[str] = ["*"]
    agents: list[str] = ["*"]
    tools: list[str] = ["*"]
    actions: list[str] = ["*"]
    environments: list[str] = ["*"]
    resources: list[str] = ["*"]
    risks: list[Risk] = Field(min_length=1)

    def matches(self, user, agent, tool, environment, resource) -> bool:
        values = {
            "users": user.user_id,
            "agents": agent.id,
            "tools": tool.name,
            "actions": tool.name.split(".", 1)[1],
            "environments": environment,
            "resources": resource,
        }
        return tool.risk in self.risks and all(
            any(fnmatchcase(value, p) for p in getattr(self, key)) for key, value in values.items()
        )


class Scope(StrictModel):
    scope_field: str
    environments: dict[str, str]


class EnvironmentConfig(StrictModel):
    scopes: dict[str, Scope]
    catalog_tools: list[str] = []


class RuleConfig(StrictModel):
    rules: list[Rule]


class ApprovalConfig(RuleConfig):
    reviewer_roles: list[Literal["reviewer"]] = Field(default=["reviewer"], min_length=1, max_length=1)


class PolicyEngine:
    """Deterministic, deny-overrides evaluation. Inputs are trusted definitions."""

    def __init__(self, directory: Path):
        self.directory = directory
        self.reload()

    def reload(self):
        raw = {
            p: yaml.safe_load((self.directory / p).read_text())
            for p in ["tool-access.yaml", "approvals.yaml", "environments.yaml"]
        }
        access = RuleConfig.model_validate(raw["tool-access.yaml"])
        approvals = ApprovalConfig.model_validate(raw["approvals.yaml"])
        inventory = EnvironmentConfig.model_validate(raw["environments.yaml"])
        rules = access.rules + approvals.rules
        if len({r.id for r in rules}) != len(rules):
            raise Invalid("Policy IDs must be unique")
        self.inventory = inventory
        self.rules = rules
        self.reviewer_roles = approvals.reviewer_roles
        self.revision = digest(raw)

    def resolve_scope(self, tool: ToolDefinition, arguments: dict) -> tuple[str, str]:
        if tool.name in self.inventory.catalog_tools and tool.risk == Risk.READ:
            return "catalog", f"{tool.provider}:catalog"
        scope = self.inventory.scopes.get(tool.provider)
        if not scope:
            raise Forbidden("Provider has no trusted environment mapping")
        identifier = str(arguments.get(scope.scope_field, ""))
        environment = scope.environments.get(identifier)
        if not environment:
            raise Forbidden("Resource scope is not in the trusted environment inventory")
        parts = [f"{scope.scope_field}={identifier}"]
        for key in tool.resource_fields:
            if key != scope.scope_field:
                if key not in arguments:
                    raise Forbidden("Resource identity is incomplete")
                parts.append(f"{key}={arguments[key]}")
        return environment, f"{tool.provider}:" + "/".join(parts)

    def evaluate(
        self,
        *,
        user: Principal,
        agent: AgentDefinition,
        tool: ToolDefinition,
        arguments: dict[str, Any],
    ) -> PolicyDecision:
        def deny(reason, policy):
            return PolicyDecision(decision=Decision.DENY, reason=reason, policy=policy)

        if user.role not in ("operator", "reviewer"):
            return deny("Principal is not an operator", "PRINCIPAL-DENY")
        if tool.group not in agent.tool_groups and tool.name not in agent.proposal_tools:
            return deny("Agent lacks this capability", "AGENT-LEAST-PRIVILEGE")
        if tool.risk == Risk.DESTRUCTIVE:
            return deny("Agent prohibits destructive operations", "AGENT-DESTRUCTIVE-DENY")
        permission = (
            agent.default_permissions.read
            if tool.risk == Risk.READ
            else agent.default_permissions.write
        )
        if permission == "deny":
            return deny("Agent permission is denied", "AGENT-DENY")
        try:
            environment, resource = self.resolve_scope(tool, arguments)
        except Forbidden as exc:
            return deny(str(exc), "ENVIRONMENT-DENY")
        matches = [r for r in self.rules if r.matches(user, agent, tool, environment, resource)]
        if not matches:
            return deny("No policy grants this action", "DEFAULT-DENY")
        order = {Decision.ALLOW: 0, Decision.APPROVAL_REQUIRED: 1, Decision.DENY: 2}
        rule = max(matches, key=lambda r: order[r.decision])
        if rule.decision == Decision.ALLOW and tool.risk != Risk.READ:
            return PolicyDecision(
                decision=Decision.APPROVAL_REQUIRED,
                reason="Agent writes require human approval",
                policy="AGENT-WRITE-GATE",
            )
        return PolicyDecision(decision=rule.decision, reason=rule.reason, policy=rule.id)
