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

## Phase 3 — security control plane

Policies load from strict YAML and use deny-overrides evaluation. Environment is
resolved from trusted account/subscription/project inventory, never model text.
Unknown scope or missing grants deny execution. Approval records bind normalized
arguments and control-plane revisions, expire, and can be claimed once. The review
digest must match; the executed payload comes from the stored record. SQLite
triggers prevent payload changes and audit update/delete through normal DB access.
Audit events contain hashes and outcome codes, never raw tool arguments or outputs.
The hash chain detects modification; DB-owner tamper resistance requires an external
append-only destination in production. Validation: 33 security tests pass.
