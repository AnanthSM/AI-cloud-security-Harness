# Skills

The initial agent intentionally has no skills. Add `skills/<id>/skill.yaml`,
`instructions.md`, `examples/`, and `tests/` to define a reviewed skill.
Metadata requires id, semantic version, description, tools, required_knowledge,
and risk_level (read_only, low_risk_write, high_risk_write, destructive).
Discovery does not grant permission: activate an id in the agent definition;
all tool calls still go through the policy and approval boundary.
