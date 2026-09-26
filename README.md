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
