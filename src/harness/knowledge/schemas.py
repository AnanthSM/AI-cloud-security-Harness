from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator, model_validator

from harness.schemas import StrictModel


class KnowledgeSource(StrictModel):
    type: str = Field(min_length=1, max_length=80)
    reference: str = Field(min_length=1, max_length=1000)

    @field_validator("type", "reference")
    @classmethod
    def not_whitespace(cls, value):
        if not value.strip():
            raise ValueError("Evidence must not be blank")
        return value.strip()


class KnowledgeEntry(StrictModel):
    id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,95}$")
    title: str = Field(min_length=1, max_length=240)
    version: int = Field(ge=1)
    statement: str = Field(min_length=1, max_length=20000)
    scope: dict[str, str] = Field(default_factory=dict)
    sources: list[KnowledgeSource] = Field(min_length=1, max_length=20)
    tags: list[str] = Field(default_factory=list, max_length=40)
    created_at: datetime
    updated_at: datetime
    reviewed_at: datetime | None = None
    reviewed_by: str | None = None
    status: Literal["candidate", "approved", "rejected"]
    confidence: float = Field(default=0.5, ge=0, le=1)
    created_by: str = Field(default="import", min_length=1, max_length=128)
    session_id: str = ""

    @field_validator("title", "statement")
    @classmethod
    def not_whitespace(cls, value):
        if not value.strip():
            raise ValueError("Knowledge text must not be empty")
        return value.strip()

    @model_validator(mode="after")
    def reviewed_provenance(self):
        if self.status in {"approved", "rejected"} and not (self.reviewed_at and self.reviewed_by):
            raise ValueError("Reviewed knowledge requires a reviewer and timestamp")
        if self.status == "candidate" and (self.reviewed_at or self.reviewed_by):
            raise ValueError("Candidates must not claim a completed review")
        return self
