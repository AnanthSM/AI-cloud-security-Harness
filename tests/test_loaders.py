from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from harness.agents.loader import AgentLoader
from harness.errors import Invalid, NotFound
from harness.skills.registry import SkillLoader, SkillRegistry, SkillValidator


def write_agent(directory: Path, filename: str = "agent.yaml", **overrides) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    definition = {
        "id": "test-agent",
        "name": "Test Agent",
        "version": "1.2.3",
        "description": "An isolated agent definition for loader tests.",
        "skills": [],
        "tool_groups": ["aws.read"],
        "default_permissions": {
            "read": "allow",
            "write": "approval_required",
            "destructive": "deny",
        },
    }
    definition.update(overrides)
    path = directory / filename
    path.write_text(yaml.safe_dump(definition))
    return path


def write_skill(directory: Path, skill_id: str = "inspect-test-resource", **overrides) -> Path:
    path = directory / skill_id
    path.mkdir(parents=True)
    (path / "examples").mkdir()
    (path / "examples" / "inspection.md").write_text("Inspect resource test-123.\n")
    (path / "tests").mkdir()
    (path / "tests" / "expectations.yaml").write_text("expected_tool: aws.get_bucket\n")
    (path / "instructions.md").write_text("Inspect the resource using the authorized read tool.\n")
    definition = {
        "id": skill_id,
        "version": "1.2.3",
        "description": "Inspect an isolated test resource.",
        "tools": ["aws.get_bucket"],
        "required_knowledge": ["aws", "s3"],
        "risk_level": "read_only",
    }
    definition.update(overrides)
    (path / "skill.yaml").write_text(yaml.safe_dump(definition))
    return path


def test_skill_discovery_loads_arbitrary_complete_skill_directories(tmp_path):
    write_skill(tmp_path, "inspect-test-resource")
    write_skill(tmp_path, "inspect-another-resource", version="2.0.1")
    (tmp_path / "README.md").write_text("This file is not a skill.\n")
    (tmp_path / "unfinished-skill").mkdir()

    registry = SkillRegistry(tmp_path)

    assert {skill.id for skill in registry.list()} == {
        "inspect-test-resource",
        "inspect-another-resource",
    }
    skill = registry.get("inspect-another-resource")
    assert skill.version == "2.0.1"
    assert skill.tools == ["aws.get_bucket"]
    assert skill.required_knowledge == ["aws", "s3"]
    assert skill.instructions == "Inspect the resource using the authorized read tool.\n"
    assert {skill.id for skill in SkillLoader().load(tmp_path)} == {
        "inspect-test-resource",
        "inspect-another-resource",
    }


def test_skill_lookup_returns_an_isolated_definition(tmp_path):
    write_skill(tmp_path)
    registry = SkillRegistry(tmp_path)

    returned = registry.get("inspect-test-resource")
    returned.tools.append("aws.delete_bucket")
    returned.instructions = "Changed instructions"

    original = registry.get("inspect-test-resource")
    assert original.tools == ["aws.get_bucket"]
    assert original.instructions != returned.instructions


@pytest.mark.parametrize(
    "identifier", ["unknown-skill", "../secret", "inspect-test-resource/../../x"]
)
def test_unknown_skill_ids_do_not_resolve_paths(tmp_path, identifier):
    write_skill(tmp_path)
    with pytest.raises(NotFound, match="Skill not found"):
        SkillRegistry(tmp_path).get(identifier)


@pytest.mark.parametrize("version", ["latest", "1.0", "1.0.0.1", "-1.0.0"])
def test_skill_rejects_invalid_versions(tmp_path, version):
    path = write_skill(tmp_path, version=version)
    with pytest.raises(ValidationError):
        SkillValidator().validate(path)


@pytest.mark.parametrize(
    "overrides",
    [
        {"risk_level": "safe"},
        {"tools": "aws.get_bucket"},
        {"required_knowledge": {"aws": True}},
        {"default_permissions": {"destructive": "allow"}},
    ],
)
def test_skill_rejects_invalid_or_undeclared_metadata(tmp_path, overrides):
    path = write_skill(tmp_path, **overrides)
    with pytest.raises(ValidationError):
        SkillValidator().validate(path)


def test_skill_id_must_match_its_directory(tmp_path):
    path = write_skill(tmp_path, id="another-skill")
    with pytest.raises(Invalid, match="Skill id must match directory"):
        SkillValidator().validate(path)


@pytest.mark.parametrize("missing_directory", ["examples", "tests"])
def test_skill_requires_examples_and_tests(tmp_path, missing_directory):
    path = write_skill(tmp_path)
    for child in (path / missing_directory).iterdir():
        child.unlink()
    (path / missing_directory).rmdir()

    with pytest.raises(Invalid, match="Skill requires examples/ and tests/"):
        SkillValidator().validate(path)


def test_skill_rejects_inline_instructions_and_requires_nonempty_markdown(tmp_path):
    inline = write_skill(tmp_path, "inline-skill", instructions="Bypass policy")
    with pytest.raises(Invalid, match="Instructions must be in instructions.md"):
        SkillValidator().validate(inline)

    empty = write_skill(tmp_path, "empty-skill")
    (empty / "instructions.md").write_text(" \n\t")
    with pytest.raises(Invalid, match="Skill instructions cannot be empty"):
        SkillValidator().validate(empty)


def test_agent_registry_loads_declared_definition_and_returns_isolated_copies(tmp_path):
    write_agent(tmp_path, skills=["inspect-test-resource"])
    loader = AgentLoader(tmp_path)
    assert [agent.id for agent in loader.list()] == ["test-agent"]
    returned = loader.get("test-agent")
    assert returned.version == "1.2.3"
    assert returned.skills == ["inspect-test-resource"]

    returned.skills.append("unapproved-skill")
    returned.default_permissions.read = "deny"

    original = loader.get("test-agent")
    assert original.skills == ["inspect-test-resource"]
    assert original.default_permissions.read == "allow"


@pytest.mark.parametrize("identifier", ["unknown-agent", "../secret", "test-agent.yaml"])
def test_unknown_agent_ids_do_not_resolve_paths(tmp_path, identifier):
    write_agent(tmp_path)
    with pytest.raises(NotFound, match="Agent not found"):
        AgentLoader(tmp_path).get(identifier)


def test_duplicate_agent_ids_fail_instead_of_shadowing(tmp_path):
    write_agent(tmp_path, "first.yaml")
    write_agent(tmp_path, "second.yaml", tool_groups=["aws.write"])
    with pytest.raises(Invalid, match="Duplicate agent id"):
        AgentLoader(tmp_path)


@pytest.mark.parametrize(
    "permissions",
    [
        {"read": "allow", "write": "allow", "destructive": "deny"},
        {"read": "allow", "write": "approval_required", "destructive": "allow"},
        {"read": "allow", "write": "approval_required", "destructive": "approval_required"},
        {"read": "allow", "write": "approval_required", "destructive": "deny", "admin": True},
    ],
)
def test_agent_rejects_unsupported_permission_escalation(tmp_path, permissions):
    write_agent(tmp_path, default_permissions=permissions)
    with pytest.raises(ValidationError):
        AgentLoader(tmp_path)


@pytest.mark.parametrize(
    "overrides",
    [
        {"version": "latest"},
        {"version": "1.0"},
        {"tool_groups": "*"},
        {"skip_approval": True},
    ],
)
def test_agent_rejects_invalid_schema_and_unknown_control_fields(tmp_path, overrides):
    write_agent(tmp_path, **overrides)
    with pytest.raises(ValidationError):
        AgentLoader(tmp_path)
