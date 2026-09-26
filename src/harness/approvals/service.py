import json
from datetime import timedelta
from typing import Callable
from uuid import uuid4

from sqlalchemy import String, Text, select, text, update
from sqlalchemy.orm import Mapped, mapped_column

from harness.audit.service import AuditEvent, AuditLog
from harness.db import Base, Database
from harness.errors import Conflict, Forbidden, NotFound
from harness.schemas import Principal, Risk, StrictModel
from harness.util import canonical, digest, utcnow


class ActionEnvelope(StrictModel):
    session_id: str
    user_id: str
    agent_id: str
    agent_version: str
    agent_digest: str
    tool: str
    tool_version: str
    tool_digest: str
    arguments: dict
    environment: str
    resource: str
    risk: Risk
    policy_revision: str
    proposed_action: str
    knowledge_sources: list[str] = []
    trace_id: str = ""


class ApprovalRow(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload: Mapped[str] = mapped_column(Text)
    payload_hash: Mapped[str] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="PENDING")
    execution_status: Mapped[str] = mapped_column(String(16), default="NOT_STARTED")
    created_at: Mapped[str] = mapped_column(String(40))
    expires_at: Mapped[str] = mapped_column(String(40))
    reviewer_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)


class ApprovalEngine:
    def __init__(self, db: Database, audit: AuditLog, ttl_seconds=900):
        self.db, self.audit, self.ttl_seconds = db, audit, ttl_seconds
        db.create_all()
        if db.engine.dialect.name == "sqlite":
            with db.engine.begin() as conn:
                conn.execute(text("CREATE TRIGGER IF NOT EXISTS approval_payload_immutable BEFORE UPDATE OF payload, payload_hash, reason, created_at, expires_at ON approvals BEGIN SELECT RAISE(ABORT, 'approval payload is immutable'); END"))

    @staticmethod
    def _view(row: ApprovalRow) -> dict:
        return {"id": row.id, "payload": json.loads(row.payload), "payload_hash": row.payload_hash,
                "reason": row.reason, "status": row.status, "execution_status": row.execution_status,
                "created_at": row.created_at, "expires_at": row.expires_at,
                "reviewer_id": row.reviewer_id, "result": json.loads(row.result) if row.result else None}

    def create(self, envelope: ActionEnvelope, reason: str) -> dict:
        now = utcnow()
        payload = canonical(envelope.model_dump(mode="json"))
        row = ApprovalRow(id="APR-" + uuid4().hex[:16], payload=payload,
                          payload_hash=digest(json.loads(payload)), reason=reason, status="PENDING",
                          execution_status="NOT_STARTED", created_at=now.isoformat(),
                          expires_at=(now + timedelta(seconds=self.ttl_seconds)).isoformat())
        with self.db.sessions.begin() as unit:
            unit.add(row)
            self.audit.record(self._event(row, "approval.requested", envelope.user_id), unit)
        return self._view(row)

    @staticmethod
    def _event(row, event, user_id):
        payload = json.loads(row.payload)
        return AuditEvent(event=event, trace_id=payload["trace_id"], user_id=user_id,
                          session_id=payload["session_id"], agent_id=payload["agent_id"],
                          agent_version=payload["agent_version"], tool=payload["tool"],
                          tool_version=payload["tool_version"], arguments_hash=digest(payload["arguments"]),
                          approval_result=row.status, execution_result=row.execution_status,
                          knowledge_sources=payload["knowledge_sources"])

    def _expire(self):
        with self.db.sessions() as unit:
            if self.db.engine.dialect.name == "sqlite":
                unit.execute(text("BEGIN IMMEDIATE"))
            rows = unit.scalars(select(ApprovalRow).where(ApprovalRow.status == "PENDING", ApprovalRow.expires_at <= utcnow().isoformat())).all()
            for row in rows:
                changed = unit.execute(update(ApprovalRow).where(
                    ApprovalRow.id == row.id, ApprovalRow.status == "PENDING",
                    ApprovalRow.execution_status == "NOT_STARTED",
                ).values(status="EXPIRED"))
                if changed.rowcount == 1:
                    unit.refresh(row)
                    self.audit.record(self._event(row, "approval.expired", "system"), unit)
            unit.commit()

    def list(self) -> list[dict]:
        self._expire()
        with self.db.sessions() as unit:
            return [self._view(r) for r in unit.scalars(select(ApprovalRow).order_by(ApprovalRow.created_at))]

    def get(self, approval_id: str) -> dict:
        self._expire()
        with self.db.sessions() as unit:
            row = unit.get(ApprovalRow, approval_id)
            if not row:
                raise NotFound("Approval not found")
            return self._view(row)

    def claim(self, approval_id: str, reviewer: Principal, expected_hash: str,
              validator: Callable[[ActionEnvelope], None]) -> ActionEnvelope:
        if reviewer.role != "reviewer":
            raise Forbidden("A human reviewer credential is required")
        self._expire()
        with self.db.sessions() as unit:
            if self.db.engine.dialect.name == "sqlite":
                unit.execute(text("BEGIN IMMEDIATE"))
            row = unit.get(ApprovalRow, approval_id)
            if not row:
                raise NotFound("Approval not found")
            if row.status != "PENDING" or row.execution_status != "NOT_STARTED":
                raise Conflict("Approval is no longer pending")
            self._require_unexpired(unit, row)
            if expected_hash != row.payload_hash or digest(json.loads(row.payload)) != row.payload_hash:
                raise Conflict("Approval payload changed or review digest is stale")
            envelope = ActionEnvelope.model_validate_json(row.payload)
            # Validation cannot rewrite the action that the reviewer approved.
            validator(envelope.model_copy(deep=True))
            self._require_unexpired(unit, row)
            changed = unit.execute(update(ApprovalRow).where(
                ApprovalRow.id == approval_id, ApprovalRow.status == "PENDING",
                ApprovalRow.execution_status == "NOT_STARTED",
                ApprovalRow.expires_at > utcnow().isoformat()).values(
                status="APPROVED", execution_status="CLAIMED", reviewer_id=reviewer.user_id))
            if changed.rowcount != 1:
                raise Conflict("Approval was already claimed")
            unit.refresh(row)
            self.audit.record(self._event(row, "approval.approved", reviewer.user_id), unit)
            unit.commit()
            return envelope

    def _require_unexpired(self, unit, row):
        if row.expires_at <= utcnow().isoformat():
            changed = unit.execute(update(ApprovalRow).where(
                ApprovalRow.id == row.id, ApprovalRow.status == "PENDING",
                ApprovalRow.execution_status == "NOT_STARTED",
            ).values(status="EXPIRED"))
            if changed.rowcount == 1:
                unit.refresh(row)
                self.audit.record(self._event(row, "approval.expired", "system"), unit)
            unit.commit()
            raise Conflict("Approval has expired")

    def reject(self, approval_id: str, reviewer: Principal) -> dict:
        if reviewer.role != "reviewer":
            raise Forbidden("A human reviewer credential is required")
        self._expire()
        with self.db.sessions.begin() as unit:
            changed = unit.execute(update(ApprovalRow).where(ApprovalRow.id == approval_id,
                ApprovalRow.status == "PENDING").values(status="REJECTED", reviewer_id=reviewer.user_id))
            if changed.rowcount != 1:
                raise Conflict("Approval is no longer pending")
            row = unit.get(ApprovalRow, approval_id)
            self.audit.record(self._event(row, "approval.rejected", reviewer.user_id), unit)
            return self._view(row)

    def complete(self, approval_id: str, result: dict | None, status: str):
        if status not in {"SUCCEEDED", "FAILED", "UNKNOWN"}:
            raise ValueError("Invalid execution state")
        with self.db.sessions.begin() as unit:
            changed = unit.execute(update(ApprovalRow).where(ApprovalRow.id == approval_id,
                ApprovalRow.execution_status == "CLAIMED").values(execution_status=status,
                result=canonical(result) if result is not None else None))
            if changed.rowcount != 1:
                raise Conflict("Execution is not claimed")
            row = unit.get(ApprovalRow, approval_id)
            self.audit.record(self._event(row, "approval.execution_completed", row.reviewer_id), unit)
