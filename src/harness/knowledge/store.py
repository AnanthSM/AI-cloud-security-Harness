"""Versioned knowledge with explicit reviewed promotion and fail-closed file import.

SQL records are authoritative. Markdown exports are immutable review artifacts;
editing a file never replaces an existing database version.
"""
import json
import math
import re
from pathlib import Path
from uuid import uuid4

import yaml
from pydantic import ValidationError
from sqlalchemy import Integer, String, Text, event, select, text
from sqlalchemy.orm import Mapped, mapped_column

from harness.audit.service import AuditEvent, AuditLog
from harness.db import Base, Database
from harness.errors import Conflict, Forbidden, Invalid, NotFound
from harness.knowledge.schemas import KnowledgeEntry
from harness.memory.service import sanitize
from harness.schemas import Principal
from harness.util import canonical, digest, utcnow

FOLDERS = {"approved", "candidates", "scenarios", "policies"}
TRUSTED = {"approved", "scenarios", "policies"}


class KnowledgeRow(Base):
    __tablename__ = "knowledge_versions"
    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    payload: Mapped[str] = mapped_column(Text)
    payload_hash: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(32))


class KnowledgeHead(Base):
    __tablename__ = "knowledge_heads"
    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    version: Mapped[int] = mapped_column(Integer)


@event.listens_for(KnowledgeRow, "before_update")
@event.listens_for(KnowledgeRow, "before_delete")
def immutable_versions(*_):
    raise ValueError("Knowledge versions are immutable")


class KnowledgeStore:
    def __init__(self, db: Database, root: Path, audit: AuditLog):
        self.db, self.audit = db, audit
        root = Path(root).absolute()
        self.root = root if root.name == "knowledge" else root / "knowledge"
        if self.root.is_symlink():
            raise Invalid("Knowledge root cannot be a symlink")
        self.root.mkdir(parents=True, exist_ok=True)
        self.root = self.root.resolve()
        for folder in FOLDERS:
            self._folder(folder).mkdir(exist_ok=True)
        db.create_all()
        if db.engine.dialect.name == "sqlite":
            with db.engine.begin() as conn:
                for action in ["UPDATE", "DELETE"]:
                    conn.execute(text(f"CREATE TRIGGER IF NOT EXISTS knowledge_no_{action.lower()} BEFORE {action} ON knowledge_versions BEGIN SELECT RAISE(ABORT, 'knowledge versions are immutable'); END"))
        self.import_documents()

    def _folder(self, folder: str) -> Path:
        if folder not in FOLDERS:
            raise Invalid("Unknown knowledge source")
        path = self.root / folder
        if path.is_symlink() or path.resolve().parent != self.root:
            raise Invalid("Knowledge folders must remain inside the knowledge root")
        return path

    @staticmethod
    def _view(row: KnowledgeRow) -> dict:
        data = json.loads(row.payload)
        return {**data, "source": f"knowledge/{row.source}",
                "content": data["statement"], "payload_hash": row.payload_hash,
                "trusted": data["status"] == "approved" and row.source in TRUSTED}

    @staticmethod
    def _validate(data: dict) -> KnowledgeEntry:
        try:
            entry = KnowledgeEntry.model_validate(data)
        except ValidationError:
            raise Invalid("Knowledge metadata or content is invalid") from None
        clean = entry.model_dump(mode="json")
        if sanitize(clean) != clean:
            raise Invalid("Knowledge contains sensitive information; remove secrets before proposing it")
        if len(canonical(clean)) > 40000:
            raise Invalid("Knowledge entry exceeds the storage limit")
        return entry

    def _begin(self, unit):
        if self.db.engine.dialect.name == "sqlite":
            unit.execute(text("BEGIN IMMEDIATE"))

    def _head(self, unit, knowledge_id: str) -> KnowledgeRow:
        head = unit.scalar(select(KnowledgeHead).where(
            KnowledgeHead.id == knowledge_id).with_for_update())
        if not head:
            raise NotFound("Knowledge entry not found")
        return unit.get(KnowledgeRow, (knowledge_id, head.version))

    def _append(self, unit, entry: KnowledgeEntry, source: str,
                operation: str, actor: str) -> KnowledgeRow:
        payload = entry.model_dump(mode="json")
        row = KnowledgeRow(id=entry.id, version=entry.version, payload=canonical(payload),
                           payload_hash=digest(payload), source=source)
        unit.add(row)
        head = unit.get(KnowledgeHead, entry.id)
        if head:
            head.version = entry.version
        else:
            unit.add(KnowledgeHead(id=entry.id, version=entry.version))
        self.audit.record(AuditEvent(event=operation, user_id=actor,
            session_id=entry.session_id, arguments_hash=row.payload_hash,
            knowledge_sources=[f"knowledge/{source}/{entry.id}@{entry.version}"],
            execution_result=entry.status.upper()), unit)
        return row

    def propose(self, title: str, statement: str, scope: dict, sources: list,
                tags: list[str], user_id: str, session_id: str = "",
                target_id: str | None = None) -> dict:
        now = utcnow()
        with self.db.sessions() as unit:
            self._begin(unit)
            previous = self._head(unit, target_id) if target_id else None
            data = {"id": target_id or "candidate-" + uuid4().hex[:20], "title": title,
                    "version": previous.version + 1 if previous else 1,
                    "statement": statement, "scope": scope, "sources": sources,
                    "tags": tags, "created_at": now.isoformat(), "updated_at": now.isoformat(),
                    "status": "candidate", "created_by": user_id, "session_id": session_id}
            if previous:
                old = json.loads(previous.payload)
                if old["status"] == "candidate":
                    raise Conflict("Modify the pending candidate before proposing another revision")
                data["created_at"] = old["created_at"]
            entry = self._validate(data)
            row = self._append(unit, entry, "candidates", "knowledge.proposed", user_id)
            unit.commit()
            result = self._view(row)
        self.export(result)
        return result

    def list_candidates(self) -> list[dict]:
        with self.db.sessions() as unit:
            rows = unit.scalars(select(KnowledgeRow).join(KnowledgeHead,
                (KnowledgeHead.id == KnowledgeRow.id) & (KnowledgeHead.version == KnowledgeRow.version)))
            return [self._view(r) for r in rows if json.loads(r.payload)["status"] == "candidate"]

    def get_candidate(self, knowledge_id: str) -> dict:
        with self.db.sessions() as unit:
            row = self._head(unit, knowledge_id)
            if json.loads(row.payload)["status"] != "candidate":
                raise Conflict("Knowledge entry is no longer a candidate")
            return self._view(row)

    def history(self, knowledge_id: str) -> list[dict]:
        with self.db.sessions() as unit:
            return [self._view(r) for r in unit.scalars(select(KnowledgeRow).where(
                KnowledgeRow.id == knowledge_id).order_by(KnowledgeRow.version))]

    def modify(self, knowledge_id: str, expected_version: int, changes: dict,
               reviewer: Principal | None = None) -> dict:
        allowed = {"title", "statement", "scope", "sources", "tags", "confidence"}
        if not changes or not set(changes) <= allowed:
            raise Invalid("Only candidate content and provenance may be modified")
        with self.db.sessions() as unit:
            self._begin(unit)
            row = self._head(unit, knowledge_id)
            data = json.loads(row.payload)
            if row.version != expected_version or data["status"] != "candidate":
                raise Conflict("Candidate review is stale or no longer pending")
            data.update(changes)
            data.update(version=row.version + 1, updated_at=utcnow().isoformat())
            actor = reviewer.user_id if reviewer else data["created_by"]
            entry = self._validate(data)
            result = self._view(self._append(unit, entry, "candidates", "knowledge.modified", actor))
            unit.commit()
        self.export(result)
        return result

    @staticmethod
    def _reviewer(reviewer: Principal):
        if reviewer.role != "reviewer":
            raise Forbidden("Knowledge review requires a human reviewer credential")

    def promote(self, knowledge_id: str, expected_version: int,
                expected_hash: str, reviewer: Principal) -> dict:
        self._reviewer(reviewer)
        with self.db.sessions() as unit:
            self._begin(unit)
            row = self._head(unit, knowledge_id)
            data = json.loads(row.payload)
            if (row.version != expected_version or row.payload_hash != expected_hash
                    or digest(data) != row.payload_hash or data["status"] != "candidate"):
                raise Conflict("Candidate changed after review or is no longer pending")
            now = utcnow().isoformat()
            data.update(version=row.version + 1, status="approved", updated_at=now,
                        reviewed_at=now, reviewed_by=reviewer.user_id)
            entry = self._validate(data)
            previous = unit.scalars(select(KnowledgeRow).where(
                KnowledgeRow.id == knowledge_id).order_by(KnowledgeRow.version.desc())).all()
            source = next((r.source for r in previous if r.source in TRUSTED), "approved")
            result = self._view(self._append(unit, entry, source, "knowledge.promoted", reviewer.user_id))
            unit.commit()
        self.export(result)
        return result

    def reject(self, knowledge_id: str, reviewer: Principal) -> dict:
        self._reviewer(reviewer)
        with self.db.sessions() as unit:
            self._begin(unit)
            row = self._head(unit, knowledge_id)
            data = json.loads(row.payload)
            if data["status"] != "candidate":
                raise Conflict("Knowledge entry is no longer pending")
            now = utcnow().isoformat()
            data.update(version=row.version + 1, status="rejected", updated_at=now,
                        reviewed_at=now, reviewed_by=reviewer.user_id)
            entry = self._validate(data)
            result = self._view(self._append(unit, entry, "candidates", "knowledge.rejected", reviewer.user_id))
            unit.commit()
        self.export(result)
        return result

    def export(self, entry: dict) -> Path:
        """Export an authoritative stored revision, never an arbitrary caller payload."""
        with self.db.sessions() as unit:
            row = unit.get(KnowledgeRow, (entry["id"], entry["version"]))
            if row is None:
                raise NotFound("Knowledge revision not found")
            metadata = json.loads(row.payload)
            folder = row.source
        body = metadata.pop("statement")
        destination = self._folder(folder) / f"{row.id}-v{row.version}.md"
        if destination.is_symlink():
            raise Invalid("Knowledge export cannot follow symlinks")
        rendered = "---\n" + yaml.safe_dump(metadata, sort_keys=False) + "---\n\n" + body + "\n"
        if destination.exists():
            if destination.read_text(encoding="utf-8") != rendered:
                raise Conflict("Knowledge export already exists with different content")
        else:
            with destination.open("x", encoding="utf-8") as file:
                file.write(rendered)
        return destination

    def import_documents(self) -> int:
        count = 0
        for folder in sorted(FOLDERS):
            for path in sorted(self._folder(folder).glob("*.md")):
                if path.name == "README.md":
                    continue
                if path.is_symlink() or path.resolve().parent != self._folder(folder):
                    raise Invalid("Knowledge import cannot follow paths outside its source folder")
                if path.stat().st_size > 50000:
                    raise Invalid("Knowledge document exceeds the import limit")
                raw = path.read_text(encoding="utf-8")
                parts = raw.split("---", 2)
                if len(parts) != 3 or parts[0].strip():
                    raise Invalid("Knowledge documents require YAML frontmatter")
                try:
                    metadata = yaml.safe_load(parts[1])
                except yaml.YAMLError:
                    raise Invalid("Invalid knowledge YAML") from None
                if not isinstance(metadata, dict) or "statement" in metadata:
                    raise Invalid("Knowledge frontmatter is invalid")
                entry = self._validate({**metadata, "statement": parts[2].strip()})
                if ((folder in TRUSTED and entry.status != "approved")
                        or (folder == "candidates" and entry.status == "approved")):
                    raise Invalid("Knowledge source folder and review status disagree")
                with self.db.sessions() as unit:
                    self._begin(unit)
                    existing = unit.get(KnowledgeRow, (entry.id, entry.version))
                    if existing:
                        if existing.payload_hash != digest(entry.model_dump(mode="json")) or existing.source != folder:
                            raise Conflict("Imported knowledge conflicts with an immutable stored revision")
                        continue
                    head = unit.get(KnowledgeHead, entry.id)
                    if head:
                        # Changes to an existing identity go through propose/modify/review.
                        raise Conflict("New versions of existing knowledge require the review workflow")
                    self._append(unit, entry, folder, "knowledge.imported", "local-config")
                    unit.commit()
                    count += 1
        return count

    def retrieve(self, query: str, include_candidates: bool = False, limit: int = 5,
                 allowed_sources: list[str] | None = None) -> list[dict]:
        if not 1 <= limit <= 50:
            raise Invalid("Retrieval limit must be between 1 and 50")
        allowed = set(FOLDERS if allowed_sources is None else
                      [s.removeprefix("knowledge/").rstrip("/") for s in allowed_sources])
        if not allowed <= FOLDERS:
            raise Invalid("Retrieval source is not an allowed knowledge folder")
        with self.db.sessions() as unit:
            rows = unit.scalars(select(KnowledgeRow).order_by(KnowledgeRow.version)).all()
            latest = {}
            for row in rows:
                item = self._view(row)
                if row.source in allowed and item["trusted"]:
                    latest[(row.id, "approved")] = item
            if include_candidates:
                heads = {h.id: h.version for h in unit.scalars(select(KnowledgeHead))}
                for row in rows:
                    item = self._view(row)
                    if (row.source in allowed and heads[row.id] == row.version
                            and item["status"] == "candidate"):
                        latest[(row.id, "candidate")] = item
        items = list(latest.values())
        def words(value: str) -> list[str]:
            return re.findall(r"[a-z0-9]+", value.lower())
        terms = set(words(query))
        documents = [words(i["title"] + " " + i["content"] + " " + " ".join(i["tags"])) for i in items]
        average = sum(map(len, documents)) / max(len(documents), 1)
        scored = []
        for item, tokens in zip(items, documents):
            score = 0.0
            for term in terms:
                frequency = tokens.count(term)
                if frequency:
                    df = sum(term in doc for doc in documents)
                    inverse = math.log(1 + (len(items) - df + 0.5) / (df + 0.5))
                    score += inverse * frequency * 2.2 / (frequency + 1.2 * (0.25 + 0.75 * len(tokens) / max(average, 1)))
            if score > 0:
                scored.append({**item, "score": round(score, 6)})
        scored.sort(key=lambda i: (-i["score"], i["id"], -i["version"]))
        result = scored[:limit]
        self.audit.record(AuditEvent(event="knowledge.retrieved", knowledge_sources=[
            f"{i['source']}/{i['id']}@{i['version']}" for i in result], execution_result="SUCCEEDED"))
        return result
