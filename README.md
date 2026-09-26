# Cloud Security Agent Harness

A local, model-neutral execution control plane: **models propose; the harness
authorizes; tools execute**. Python 3.12+, FastAPI, SQLite/SQLAlchemy, typed MCP
capabilities, reviewed knowledge, and an intentionally empty skill set.

## Phase 1 — foundation

```sh
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
harness agent list
harness skill list
harness serve
pytest
```

Run from the repository root or set `HARNESS_ROOT`. The skeleton has a health
endpoint, declarative agents/skills, a strict typed tool registry, and CLI.
Subsequent phase commits add execution, governance, knowledge, orchestration,
telemetry, and evaluations. No cloud credentials are needed.

## Phase 2 — typed mock MCP runtime

The local catalog defines 17 tools across AWS, Azure, and GitLab, including one
blocked destructive tool for security tests. Each has closed input/output schemas,
a version, and a risk classification owned by the harness. Real MCP subprocesses
run with `python -m mcp_servers.mock_aws` (or `mock_azure`, `mock_gitlab`).
`InProcessMockGateway` is the fast default; `StdioMCPGateway` speaks actual MCP.
The executor validates both directions, limits concurrency/rate, bounds read retries,
and never retries writes. Mock security group changes use revision preconditions.
Validation: 39 tool/MCP tests pass, including real stdio round trips.
