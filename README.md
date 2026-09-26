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

## Phase 4 — reviewed knowledge and separate memory

Session memory is bounded, owned by a user/agent, and expires. `/learn` copies
investigation evidence into an unverified candidate; normal retrieval excludes
candidates. Human promotion checks the exact candidate hash and version and writes
a new immutable knowledge revision with provenance. Modification creates another
candidate version and invalidates stale reviews. SQL is authoritative; Markdown
exports preserve human-readable versions. The supplied scenario is explicitly a
mock fixture, not organizational policy. Validation: 14 knowledge/memory tests pass.

## Phase 5 — governed agent runtime and interfaces

The bounded provider-neutral loop builds context from selected skills, retrieved
reviewed documents, and isolated session state. A deterministic mock model
supports the SSH investigation/remediation demos; actual model providers implement
the `ModelProvider` port. Every proposal passes through `GovernedTools`, including
external-client proposals. Configuration and resource revisions are rechecked at
execution; queued actions recheck authorization before dispatch.

REST endpoints require separate operator and reviewer tokens. CLI commands assume
a trusted local OS operator. The MCP facade exposes investigation and proposal
capabilities but no approve/promote endpoint. API schemas reject caller-supplied
identity and redact validation errors. End-to-end API/CLI tests verify pending writes,
exact approved execution, replay prevention, and candidate knowledge promotion.
