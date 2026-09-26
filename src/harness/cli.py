import json

import typer

from harness.agents.loader import AgentLoader
from harness.config import Settings
from harness.skills.registry import SkillRegistry

app = typer.Typer(no_args_is_help=True)
agent_app = typer.Typer()
skill_app = typer.Typer()
tool_app = typer.Typer()
app.add_typer(agent_app, name="agent")
app.add_typer(skill_app, name="skill")
app.add_typer(tool_app, name="tool")


@agent_app.command("list")
def agents():
    typer.echo(json.dumps([a.model_dump() for a in AgentLoader(Settings.load().root / "agents").list()], indent=2))


@skill_app.command("list")
def skills():
    typer.echo(json.dumps([s.model_dump() for s in SkillRegistry(Settings.load().root / "skills").list()], indent=2))


@tool_app.command("list")
def tools():
    typer.echo("[]")


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000):
    import uvicorn

    from harness.api.app import create_app
    uvicorn.run(create_app(), host=host, port=port)
