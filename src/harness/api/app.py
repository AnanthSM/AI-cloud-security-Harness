from fastapi import FastAPI

from harness.agents.loader import AgentLoader
from harness.config import Settings
from harness.skills.registry import SkillRegistry
from harness.tools.registry import ToolRegistry


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.load()
    app = FastAPI(title="Cloud Security Harness", version="0.1.0")
    agents = AgentLoader(settings.root / "agents")
    skills = SkillRegistry(settings.root / "skills")
    tools = ToolRegistry()

    @app.get("/health")
    def health():
        return {"status": "ok", "mode": "mock"}

    @app.get("/v1/agents")
    def list_agents():
        return agents.list()

    @app.get("/v1/skills")
    def list_skills():
        return skills.list()

    @app.get("/v1/tools")
    def list_tools():
        return tools.list()

    return app
