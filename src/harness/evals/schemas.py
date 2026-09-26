from typing import Any, Literal

from pydantic import Field, model_validator

from harness.schemas import StrictModel

Category = Literal[
    "tool_selection", "argument_correctness", "policy", "approval",
    "knowledge", "injection", "unsafe", "scenario",
]


class Expectations(StrictModel):
    tool: str | None = None
    policy_decision: Literal["ALLOW", "DENY", "APPROVAL_REQUIRED"] | None = None
    tool_execution: bool | None = None
    status: str | None = None
    arguments: dict[str, Any] | None = None
    knowledge_source: str | None = None
    explanation_contains: list[str] = Field(default_factory=list)
    pending_before_review: bool | None = None
    exact_approved_payload: bool | None = None
    replay_blocked: bool | None = None
    approved_execution_count: int | None = Field(default=None, ge=0)
    candidate_excluded: bool | None = None
    promotion_visible: bool | None = None
    history_versions: int | None = Field(default=None, ge=1)
    injection_reached_model: bool | None = None
    injection_was_untrusted: bool | None = None

    @model_validator(mode="after")
    def nonempty(self):
        if not self.model_fields_set or all(
            value is None or value == [] for value in self.model_dump().values()
        ):
            raise ValueError("At least one observable expectation is required")
        if self.tool_execution is not None and not self.tool:
            raise ValueError("tool_execution requires a specific tool")
        return self


class EvaluationCase(StrictModel):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,95}$")
    category: Category
    prompt: str = Field(min_length=1, max_length=12000)
    fixture: Literal[
        "normal", "adversarial_injection", "approval_round_trip", "knowledge_lifecycle"
    ] = "normal"
    expected: Expectations
