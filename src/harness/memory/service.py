"""Bounded, expiring task state. No path from memory into trusted knowledge."""

import json
import os
import re
from datetime import timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import Integer, String, Text, delete, text
from sqlalchemy.orm import Mapped, mapped_column

from harness.audit.service import redact
from harness.db import Base, Database
from harness.errors import Invalid, NotFound
from harness.util import canonical, utcnow

QUOTED_SECRET = re.compile(
    r"""(?i)["'](?:password|secret|token|authorization|credential|api[_-]?key|private[_-]?key)["']\s*:\s*(?:"[^"\n]*"|'[^'\n]*'|[^\s,;}]+)"""
)


def sanitize(value: Any) -> Any:
    """Defense in depth for accidental secrets; known local credentials are also scrubbed."""
    value = redact(value)
    if isinstance(value, dict):
        return {k: sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(v) for v in value]
    if isinstance(value, str):
        value = QUOTED_SECRET.sub("[REDACTED]", value)
        for name, secret in os.environ.items():
            if name.startswith("HARNESS_") and ("TOKEN" in name or "SECRET" in name) and secret:
                value = value.replace(secret, "[REDACTED]")
    return value


class SessionRow(Base):
    __tablename__ = "session_memory"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(128))
    agent_id: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[str] = mapped_column(String(40))
    expires_at: Mapped[str] = mapped_column(String(40), index=True)
    payload: Mapped[str] = mapped_column(Text)
    revision: Mapped[int] = mapped_column(Integer, default=1)


class SessionMemory:
    MAX_MESSAGES = 40
    MAX_MESSAGE_CHARS = 6000
    MAX_MEMORY_CHARS = 32000
    MAX_STATE_CHARS = 8000

    def __init__(self, db: Database, ttl_seconds: int = 86400):
        if ttl_seconds <= 0:
            raise Invalid("Session TTL must be positive")
        self.db, self.ttl_seconds = db, ttl_seconds
        db.create_all()

    def create(self, user_id: str, agent_id: str) -> str:
        if not user_id or not agent_id:
            raise Invalid("Session owner and agent are required")
        now = utcnow()
        row = SessionRow(
            id="SES-" + uuid4().hex,
            user_id=user_id,
            agent_id=agent_id,
            created_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=self.ttl_seconds)).isoformat(),
            payload=canonical({"messages": [], "state": {}}),
            revision=1,
        )
        with self.db.sessions.begin() as unit:
            unit.execute(delete(SessionRow).where(SessionRow.expires_at <= now.isoformat()))
            unit.add(row)
        return row.id

    def _row(self, unit, session_id, user_id, agent_id):
        row = unit.get(SessionRow, session_id)
        if (
            row is None
            or row.user_id != user_id
            or row.agent_id != agent_id
            or row.expires_at <= utcnow().isoformat()
        ):
            raise NotFound("Session not found or expired")
        return row

    def get(self, session_id: str, user_id: str, agent_id: str) -> dict:
        with self.db.sessions() as unit:
            row = self._row(unit, session_id, user_id, agent_id)
            data = sanitize(json.loads(row.payload))
            return {
                "id": row.id,
                "session_id": row.id,
                "user_id": row.user_id,
                "agent_id": row.agent_id,
                "created_at": row.created_at,
                "expires_at": row.expires_at,
                **data,
                "last_resource": data["state"].get("last_resource"),
            }

    def append(self, session_id: str, user_id: str, agent_id: str, role: str, content: Any) -> dict:
        if role not in {"user", "assistant", "tool"}:
            raise Invalid("Memory accepts user, assistant, and tool data only")
        content = sanitize(content)
        if not isinstance(content, str):
            content = canonical(content)
        message = {
            "role": role,
            "content": content[: self.MAX_MESSAGE_CHARS],
            "timestamp": utcnow().isoformat(),
            "trusted": False,
        }
        with self.db.sessions() as unit:
            if self.db.engine.dialect.name == "sqlite":
                unit.execute(text("BEGIN IMMEDIATE"))
            row = self._row(unit, session_id, user_id, agent_id)
            data = json.loads(row.payload)
            data["messages"] = (data["messages"] + [message])[-self.MAX_MESSAGES :]
            while len(canonical(data)) > self.MAX_MEMORY_CHARS and len(data["messages"]) > 1:
                data["messages"].pop(0)
            row.payload = canonical(data)
            row.revision += 1
            unit.commit()
        return self.get(session_id, user_id, agent_id)

    def set_state(
        self,
        session_id: str,
        user_id: str,
        agent_id: str,
        state: dict | None = None,
        **updates: Any,
    ) -> dict:
        incoming = sanitize({**(state or {}), **updates})
        with self.db.sessions() as unit:
            if self.db.engine.dialect.name == "sqlite":
                unit.execute(text("BEGIN IMMEDIATE"))
            row = self._row(unit, session_id, user_id, agent_id)
            data = json.loads(row.payload)
            data["state"].update(incoming)
            if len(canonical(data["state"])) > self.MAX_STATE_CHARS:
                raise Invalid("Session state exceeds the bounded memory limit")
            while len(canonical(data)) > self.MAX_MEMORY_CHARS and data["messages"]:
                data["messages"].pop(0)
            row.payload = canonical(data)
            row.revision += 1
            unit.commit()
        return self.get_state(session_id, user_id, agent_id)

    def get_state(self, session_id: str, user_id: str, agent_id: str) -> dict:
        return self.get(session_id, user_id, agent_id)["state"]

    def purge_expired(self) -> int:
        with self.db.sessions.begin() as unit:
            return unit.execute(
                delete(SessionRow).where(SessionRow.expires_at <= utcnow().isoformat())
            ).rowcount
