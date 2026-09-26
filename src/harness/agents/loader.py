from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field

from harness.errors import Invalid, NotFound
from harness.schemas import StrictModel


class Permissions(StrictModel):
    read: Literal["allow", "deny"] = "allow"
    write: Literal["approval_required", "deny"] = "approval_required"
    destructive: Literal["deny"] = "deny"


class AgentDefinition(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9-]+$")
    name: str
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    description: str
    skills: list[str] = []
    knowledge_sources: list[str] = []
    tool_groups: list[str] = []
    proposal_tools: list[str] = []
    default_permissions: Permissions = Permissions()


class AgentLoader:
    def __init__(self, directory: Path):
        self.agents: dict[str, AgentDefinition] = {}
        for path in sorted(directory.glob("*.yaml")):
            agent = AgentDefinition.model_validate(yaml.safe_load(path.read_text()))
            if agent.id in self.agents:
                raise Invalid("Duplicate agent id")
            self.agents[agent.id] = agent

    def list(self) -> list[AgentDefinition]:
        return list(self.agents.values())

    def get(self, agent_id: str) -> AgentDefinition:
        if agent_id not in self.agents:
            raise NotFound("Agent not found")
        return self.agents[agent_id].model_copy(deep=True)
