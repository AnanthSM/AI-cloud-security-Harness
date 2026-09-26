import logging.config
import sys

import yaml

from harness.agents.loader import AgentLoader
from harness.approvals.service import ApprovalEngine
from harness.audit.service import AuditLog
from harness.config import Settings
from harness.context.manager import ContextManager
from harness.db import Database
from harness.errors import Invalid
from harness.knowledge.store import KnowledgeStore
from harness.learning.service import LearningService
from harness.memory.session import SessionMemory
from harness.models.mock import MockModelProvider
from harness.observability.telemetry import Telemetry
from harness.policies.engine import PolicyEngine
from harness.runtime.agent import AgentRuntime
from harness.runtime.governance import GovernedTools
from harness.skills.registry import SkillRegistry
from harness.tools.catalog import create_registry
from harness.tools.executor import ToolExecutor
from harness.tools.gateway import InProcessMockGateway, StdioMCPGateway, StdioServerConfig


class Container:
    """Composition root. Transport/API adapters do not own business logic."""

    def __init__(
        self, settings: Settings | None = None, *, model=None, gateway=None, telemetry=None
    ):
        self.settings = settings or Settings.load()
        root = self.settings.root
        logging.config.dictConfig(yaml.safe_load((root / "config/logging.yaml").read_text()))
        self.db = Database(self.settings.database_url)
        self.audit = AuditLog(self.db)
        self.telemetry = telemetry or Telemetry(console=self.settings.trace_console)
        self.agents = AgentLoader(root / "agents")
        self.skills = SkillRegistry(root / "skills")
        self.registry = create_registry()
        self.policy = PolicyEngine(root / "policies")
        self.approvals = ApprovalEngine(self.db, self.audit, self.settings.approval_ttl_seconds)
        self.memory = SessionMemory(self.db, self.settings.session_ttl_seconds)
        self.knowledge = KnowledgeStore(self.db, root, self.audit)
        self.learning = LearningService(self.knowledge, self.memory)
        state = root / ".state"
        state.mkdir(exist_ok=True, mode=0o700)
        if gateway is not None:
            self.gateway = gateway
        elif self.settings.transport == "inprocess_mock":
            self.gateway = InProcessMockGateway(state / "mock-cloud.db")
        elif self.settings.transport == "stdio_mock":
            self.gateway = StdioMCPGateway(
                {
                    provider: StdioServerConfig(
                        command=sys.executable,
                        args=("-m", f"mcp_servers.mock_{provider}"),
                        cwd=root,
                        mock_state_path=state / "mock-cloud.db",
                    )
                    for provider in ["aws", "azure", "gitlab"]
                }
            )
        else:
            raise Invalid("Unknown tool transport")
        self.executor = ToolExecutor(
            self.registry,
            self.gateway,
            timeout_seconds=self.settings.tool_timeout_seconds,
            read_retries=self.settings.read_retries,
            max_concurrency=self.settings.max_concurrency,
            requests_per_minute=self.settings.requests_per_minute,
        )
        model_config = yaml.safe_load((root / "config/models.yaml").read_text())
        if model is None and model_config != {"provider": "mock"}:
            raise Invalid("Only the mock model is configured; inject a ModelProvider adapter")
        self.model = model or MockModelProvider()
        self.context = ContextManager(
            self.knowledge, self.memory, self.skills, self.registry, self.settings.context_max_chars
        )
        self.governance = GovernedTools(
            self.agents,
            self.registry,
            self.policy,
            self.approvals,
            self.executor,
            self.audit,
            self.memory,
            self.telemetry,
        )
        self.runtime = AgentRuntime(
            self.agents,
            self.memory,
            self.context,
            self.model,
            self.governance,
            self.learning,
            self.audit,
            self.telemetry,
            self.settings.max_steps,
        )

    def close(self):
        self.telemetry.shutdown()
        self.db.engine.dispose()
