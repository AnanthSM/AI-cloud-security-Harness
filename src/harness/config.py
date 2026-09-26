import os
from pathlib import Path

import yaml
from pydantic import Field

from harness.schemas import StrictModel


class Settings(StrictModel):
    root: Path
    database_url: str
    context_max_chars: int = Field(default=24000, ge=4096, le=200000)
    max_steps: int = Field(default=8, ge=1, le=50)
    session_ttl_seconds: int = Field(default=86400, ge=60)
    approval_ttl_seconds: int = Field(default=900, ge=1)
    tool_timeout_seconds: float = Field(default=10, gt=0)
    read_retries: int = Field(default=2, ge=0, le=5)
    max_concurrency: int = Field(default=4, ge=1)
    requests_per_minute: int = Field(default=120, ge=1)
    transport: str = "inprocess_mock"
    trace_console: bool = True

    @classmethod
    def load(cls, root: Path | None = None) -> "Settings":
        root = (root or Path(os.environ.get("HARNESS_ROOT", Path.cwd()))).resolve()
        data = yaml.safe_load((root / "config/harness.yaml").read_text())
        state = root / ".state"
        state.mkdir(mode=0o700, exist_ok=True)
        return cls(root=root, database_url=os.environ.get(
            "HARNESS_DATABASE_URL", f"sqlite:///{state / 'harness.db'}"),
            trace_console=os.environ.get("HARNESS_TRACE_CONSOLE", "true").lower() == "true",
            **data)
