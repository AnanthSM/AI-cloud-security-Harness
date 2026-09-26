from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field

from harness.errors import Invalid, NotFound
from harness.schemas import StrictModel


class SkillDefinition(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9-]+$")
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    description: str
    tools: list[str] = []
    required_knowledge: list[str] = []
    risk_level: Literal["read_only", "low_risk_write", "high_risk_write", "destructive"]
    instructions: str = ""


class SkillValidator:
    def validate(self, path: Path) -> SkillDefinition:
        data = yaml.safe_load((path / "skill.yaml").read_text())
        if "instructions" in data:
            raise Invalid("Instructions must be in instructions.md")
        skill = SkillDefinition.model_validate(data)
        if skill.id != path.name:
            raise Invalid("Skill id must match directory")
        if not all((path / n).is_dir() for n in ["examples", "tests"]):
            raise Invalid("Skill requires examples/ and tests/")
        skill.instructions = (path / "instructions.md").read_text()
        if not skill.instructions.strip():
            raise Invalid("Skill instructions cannot be empty")
        return skill


class SkillLoader:
    def load(self, directory: Path) -> list[SkillDefinition]:
        return [SkillValidator().validate(p.parent) for p in sorted(directory.glob("*/skill.yaml"))]


class SkillRegistry:
    def __init__(self, directory: Path):
        self.skills = {s.id: s for s in SkillLoader().load(directory)}

    def list(self) -> list[SkillDefinition]:
        return list(self.skills.values())

    def get(self, skill_id: str) -> SkillDefinition:
        if skill_id not in self.skills:
            raise NotFound("Skill not found")
        return self.skills[skill_id].model_copy(deep=True)
