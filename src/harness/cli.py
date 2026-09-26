import asyncio
import json
import os
from contextlib import contextmanager
from pathlib import Path

import typer

from harness.errors import HarnessError, Invalid
from harness.schemas import Principal, RunRequest

app = typer.Typer(
    no_args_is_help=True, help="Governed cloud security tools, agents, and reviewed knowledge."
)
agent_app = typer.Typer()
skill_app = typer.Typer()
tool_app = typer.Typer()
approval_app = typer.Typer()
knowledge_app = typer.Typer()
eval_app = typer.Typer()
for name, group in [
    ("agent", agent_app),
    ("skill", skill_app),
    ("tool", tool_app),
    ("approvals", approval_app),
    ("knowledge", knowledge_app),
    ("eval", eval_app),
]:
    app.add_typer(group, name=name)

OPERATOR = Principal(user_id="local-operator")
REVIEWER = Principal(user_id="local-reviewer", role="reviewer")


def emit(value):
    typer.echo(
        json.dumps(
            value.model_dump(mode="json") if hasattr(value, "model_dump") else value,
            indent=2,
            default=str,
        )
    )


@contextmanager
def services():
    from harness.runtime.container import Container

    container = None
    try:
        container = Container()
        yield container
    except HarnessError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1) from None
    finally:
        if container:
            container.close()


@agent_app.command("list")
def agents():
    with services() as c:
        emit([a.model_dump(mode="json") for a in c.agents.list()])


@skill_app.command("list")
def skills():
    with services() as c:
        emit([s.model_dump(mode="json") for s in c.skills.list()])


@tool_app.command("list")
def tools():
    with services() as c:
        emit([t.model_dump(mode="json") for t in c.registry.list()])


@app.command()
def run(agent_id: str, prompt: str, session: str | None = None):
    """Run a bounded agent task; outputs a session ID for continued work or learning."""
    with services() as c:
        result = asyncio.run(
            c.runtime.run(
                RunRequest(agent_id=agent_id, prompt=prompt, session_id=session), OPERATOR
            )
        )
        (c.settings.root / ".state/last-session").write_text(result.session_id)
        emit(result)


@approval_app.command("list")
def approvals():
    with services() as c:
        emit(c.approvals.list())


@approval_app.command("approve")
def approve(approval_id: str, expected_hash: str | None = None):
    """Review and execute the stored exact action once. Local CLI is an operator trust boundary."""
    with services() as c:
        record = c.approvals.get(approval_id)
        emit(record)
        if expected_hash is None:
            typer.confirm("Approve and execute this exact action?", abort=True)
            expected_hash = record["payload_hash"]
        emit(asyncio.run(c.governance.approve(approval_id, REVIEWER, expected_hash)))


@approval_app.command("reject")
def reject(approval_id: str):
    with services() as c:
        c.telemetry.count("approval_rejections_total")
        emit(c.approvals.reject(approval_id, REVIEWER))


@app.command()
def learn(
    session: str | None = None,
    agent_id: str = "cloud-security-agent",
    title: str | None = None,
    statement: str | None = None,
):
    """Create an untrusted candidate from a session, never promote it automatically."""
    with services() as c:
        latest = c.settings.root / ".state/last-session"
        session = session or (latest.read_text().strip() if latest.exists() else None)
        if session is None:
            raise Invalid("Run an investigation first or provide --session")
        emit(c.learning.learn(session, OPERATOR.user_id, agent_id, title, statement))


@knowledge_app.command("candidates")
def candidates():
    with services() as c:
        emit(c.knowledge.list_candidates())


@knowledge_app.command("approve")
def approve_knowledge(
    candidate_id: str, expected_hash: str | None = None, expected_version: int | None = None
):
    with services() as c:
        candidate = c.knowledge.get_candidate(candidate_id)
        emit(candidate)
        if expected_hash is None:
            typer.confirm("Promote this exact candidate to trusted knowledge?", abort=True)
            expected_hash = candidate["payload_hash"]
            expected_version = candidate["version"]
        if expected_version is None:
            raise Invalid("--expected-version is required with --expected-hash")
        emit(c.knowledge.promote(candidate_id, expected_version, expected_hash, REVIEWER))


@knowledge_app.command("reject")
def reject_knowledge(candidate_id: str):
    with services() as c:
        emit(c.knowledge.reject(candidate_id, REVIEWER))


@knowledge_app.command("modify")
def modify_knowledge(candidate_id: str, statement: str, expected_version: int):
    with services() as c:
        emit(c.knowledge.modify(candidate_id, expected_version, {"statement": statement}, REVIEWER))


@app.command()
def audit(limit: int = 100, verify: bool = False):
    with services() as c:
        emit({"valid": c.audit.verify()} if verify else c.audit.list(limit))


@eval_app.command("run")
def evaluate(path: Path | None = None):
    from harness.evals.runner import run_evaluations

    results = asyncio.run(
        run_evaluations(Path(os.environ.get("HARNESS_ROOT", Path.cwd())).resolve(), path)
    )
    emit(results)
    if not all(r["passed"] for r in results):
        raise typer.Exit(1)


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000):
    """Serve the token-authenticated API; binds loopback by default."""
    import uvicorn

    from harness.api.app import create_app

    uvicorn.run(create_app(), host=host, port=port)


@app.command()
def mcp():
    """Expose an operator-only MCP facade backed by the running REST API."""
    from harness.api.mcp import main

    main()
