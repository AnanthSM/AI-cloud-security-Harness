import json
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

from harness.errors import Invalid, NotFound
from harness.schemas import ToolDefinition


class ToolRegistry:
    """Trusted, local capability definitions; remote metadata cannot lower risk."""

    def __init__(self, definitions: list[ToolDefinition] | None = None):
        self._tools: dict[str, ToolDefinition] = {}
        for definition in definitions or []:
            self.register(definition)

    def register(self, tool: ToolDefinition) -> None:
        if tool.name in self._tools:
            raise Invalid("Duplicate tool registration")
        for schema in (tool.input_schema, tool.output_schema):
            Draft202012Validator.check_schema(schema)
            if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
                raise Invalid("Tool schemas must be closed objects")
        self._tools[tool.name] = tool.model_copy(deep=True)

    def list(self) -> list[ToolDefinition]:
        return [v.model_copy(deep=True) for v in self._tools.values()]

    def resolve(self, name: str) -> ToolDefinition:
        if name not in self._tools:
            raise NotFound("Tool not registered")
        return self._tools[name].model_copy(deep=True)

    @staticmethod
    def validate(schema: dict, value: Any) -> dict:
        try:
            encoded = json.dumps(value, allow_nan=False)
            if len(encoded) > 100000:
                raise Invalid("Tool payload too large")
            snapshot = json.loads(encoded)
            Draft202012Validator(schema).validate(snapshot)
            return snapshot
        except (ValidationError, ValueError, TypeError):
            raise Invalid("Tool payload does not match the registered schema") from None

    def validate_input(self, name: str, arguments: Any) -> dict:
        return self.validate(self.resolve(name).input_schema, arguments)

    def validate_output(self, name: str, result: Any) -> dict:
        return self.validate(self.resolve(name).output_schema, result)
