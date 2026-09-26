from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from harness.agents.loader import AgentLoader
from harness.api.app import create_app
from harness.config import Settings
from harness.errors import Invalid, NotFound
from harness.schemas import ToolDefinition
from harness.skills.registry import SkillRegistry
from harness.tools.registry import ToolRegistry

ROOT = Path(__file__).resolve().parents[1]


def test_agent_and_intentionally_empty_skills():
    agent = AgentLoader(ROOT / "agents").get("cloud-security-agent")
    assert agent.skills == []
    assert agent.default_permissions.write == "approval_required"
    assert SkillRegistry(ROOT / "skills").list() == []
    with pytest.raises(NotFound):
        AgentLoader(ROOT / "agents").get("../secret")


def test_health():
    app = create_app(Settings.load(ROOT))
    assert TestClient(app).get("/health").json()["status"] == "ok"


def test_tool_schema_is_closed_and_strict():
    schema = {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"], "additionalProperties": False}
    registry = ToolRegistry([ToolDefinition(name="aws.read", description="read", provider="aws", version="1.0.0", risk="READ", input_schema=schema, output_schema=schema)])
    assert registry.validate_input("aws.read", {"id": "x"}) == {"id": "x"}
    for value in [{"id": 1}, {"id": "x", "risk": "READ"}, {}]:
        with pytest.raises(Invalid):
            registry.validate_input("aws.read", value)
