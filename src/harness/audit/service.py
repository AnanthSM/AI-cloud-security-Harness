import os
import re
import threading
from typing import Any

from pydantic import Field
from sqlalchemy import Integer, String, Text, event, select, text
from sqlalchemy.orm import Mapped, Session, mapped_column

from harness.db import Base, Database
from harness.schemas import StrictModel
from harness.util import canonical, digest, utcnow

SECRET_KEYS = re.compile(
    r"password|secret|token|authorization|credential|api.?key|private.?key", re.I
)
SECRET_TEXT = re.compile(
    r"(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)|bearer\s+\S+|(?:password|secret|token|api[_-]?key)\s*[:=]\s*[^\s,;]+|AKIA[A-Z0-9]{16})"
)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: "[REDACTED]" if SECRET_KEYS.search(str(k)) else redact(v) for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        for name, secret in os.environ.items():
            if name.startswith("HARNESS_") and SECRET_KEYS.search(name) and secret:
                value = value.replace(secret, "[REDACTED]")
        return SECRET_TEXT.sub("[REDACTED]", value)
    return value


class AuditEvent(StrictModel):
    event: str
    timestamp: str = Field(default_factory=lambda: utcnow().isoformat())
    trace_id: str = ""
    session_id: str = ""
    user_id: str = ""
    agent_id: str = ""
    agent_version: str = ""
    skill: list[str] = []
    tool: str = ""
    tool_version: str = ""
    arguments_hash: str = ""
    policy_decision: str = ""
    approval_result: str = ""
    execution_result: str = ""
    knowledge_sources: list[str] = []
    latency_ms: float = 0
    model: str = ""
    # No arbitrary metadata, arguments, tool results, prompts, or exceptions.


class AuditRow(Base):
    __tablename__ = "audit_events"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    payload: Mapped[str] = mapped_column(Text)
    previous_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64))


@event.listens_for(AuditRow, "before_update")
@event.listens_for(AuditRow, "before_delete")
def immutable(*_):
    raise ValueError("Audit events are append-only")


class AuditLog:
    def __init__(self, database: Database):
        self.db = database
        self._lock = threading.RLock()
        self.db.create_all()
        if self.db.engine.dialect.name == "sqlite":
            with self.db.engine.begin() as conn:
                for action in ["UPDATE", "DELETE"]:
                    conn.execute(
                        text(
                            f"CREATE TRIGGER IF NOT EXISTS audit_no_{action.lower()} BEFORE {action} ON audit_events BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END"
                        )
                    )

    def record(self, event: AuditEvent, session: Session | None = None) -> None:
        if session is not None:
            self._append(session, event)
            return
        with self._lock, self.db.sessions() as unit:
            if self.db.engine.dialect.name == "sqlite":
                unit.execute(text("BEGIN IMMEDIATE"))
            self._append(unit, event)
            unit.commit()

    def _append(self, unit: Session, event: AuditEvent):
        if self.db.engine.dialect.name == "sqlite":
            # Obtain the transaction's write lock before reading the chain head,
            # including when the caller supplied an existing unit of work. No
            # rows are changed, so the append-only triggers remain effective.
            unit.execute(text("UPDATE audit_events SET sequence = sequence WHERE 1 = 0"))
        previous = unit.scalar(select(AuditRow).order_by(AuditRow.sequence.desc()).limit(1))
        previous_hash = previous.event_hash if previous else "0" * 64
        payload = canonical(redact(event.model_dump()))
        unit.add(
            AuditRow(
                payload=payload,
                previous_hash=previous_hash,
                event_hash=digest({"previous": previous_hash, "payload": payload}),
            )
        )
        unit.flush()

    def list(self, limit: int = 100, session_id: str | None = None) -> list[dict]:
        import json

        with self.db.sessions() as unit:
            rows = unit.scalars(select(AuditRow).order_by(AuditRow.sequence)).all()
            items = [
                {
                    "sequence": r.sequence,
                    **json.loads(r.payload),
                    "previous_hash": r.previous_hash,
                    "event_hash": r.event_hash,
                }
                for r in rows
            ]
        if session_id:
            items = [i for i in items if i["session_id"] == session_id]
        return items[-min(max(limit, 1), 1000) :]

    def verify(self) -> bool:
        previous = "0" * 64
        with self.db.sessions() as unit:
            for row in unit.scalars(select(AuditRow).order_by(AuditRow.sequence)):
                if row.previous_hash != previous or row.event_hash != digest(
                    {"previous": previous, "payload": row.payload}
                ):
                    return False
                previous = row.event_hash
        return True
