from typing import Any, Protocol

from pydantic import Field, model_validator

from harness.schemas import StrictModel


class ToolCall(StrictModel):
    name: str
    arguments: dict[str, Any]


class ModelResponse(StrictModel):
    text: str | None = Field(default=None, max_length=32000)
    tool_call: ToolCall | None = None
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def exactly_one_output(self):
        if (self.text is None) == (self.tool_call is None):
            raise ValueError("Model response must contain text or one tool call")
        return self


class ModelProvider(Protocol):
    name: str

    async def generate(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        response_schema: dict | None = None,
    ) -> ModelResponse: ...
