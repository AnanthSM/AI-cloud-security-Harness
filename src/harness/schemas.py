from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class Risk(StrEnum):
    READ = "READ"
    LOW_RISK_WRITE = "LOW_RISK_WRITE"
    HIGH_RISK_WRITE = "HIGH_RISK_WRITE"
    DESTRUCTIVE = "DESTRUCTIVE"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"


class Principal(StrictModel):
    user_id: str
    role: str = "operator"


class ToolDefinition(StrictModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
    description: str
    provider: str
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    risk: Risk
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    resource_fields: list[str] = []
    sensitive_fields: list[str] = []

    @property
    def group(self) -> str:
        return f"{self.provider}.{'read' if self.risk == Risk.READ else 'write'}"


class PolicyDecision(StrictModel):
    decision: Decision
    reason: str
    policy: str


class RunRequest(StrictModel):
    agent_id: str = "cloud-security-agent"
    prompt: str = Field(min_length=1, max_length=12000)
    session_id: str | None = None


class RunResult(StrictModel):
    session_id: str
    status: str
    message: str
    tool: str | None = None
    policy_decision: str | None = None
    approval_id: str | None = None
    data: Any = None
    knowledge_sources: list[str] = []
