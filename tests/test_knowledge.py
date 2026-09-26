from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError

from harness.audit.service import AuditLog
from harness.db import Database
from harness.errors import Conflict, Forbidden, Invalid
from harness.knowledge.store import KnowledgeStore
from harness.learning.service import LearningService
from harness.memory.service import SessionMemory
from harness.schemas import Principal


@pytest.fixture
def store(tmp_path):
    db = Database("sqlite:///:memory:")
    return KnowledgeStore(db, tmp_path, AuditLog(db))


def propose(store, **kwargs):
    return store.propose(
        title="Public SSH",
        statement="Inspect public SSH rules before remediation.",
        scope={"provider": "aws"},
        sources=[{"type": "incident", "reference": "INC-42"}],
        tags=["ssh"],
        user_id="alice",
        **kwargs,
    )


def approve(store, entry):
    return store.promote(
        entry["id"],
        entry["version"],
        entry["payload_hash"],
        Principal(user_id="reviewer", role="reviewer"),
    )


def test_candidate_exclusion_review_and_history(store):
    candidate = propose(store)
    assert candidate["status"] == "candidate"
    assert store.retrieve("SSH") == []
    assert store.retrieve("SSH", include_candidates=True)[0]["trusted"] is False
    approved = approve(store, candidate)
    assert approved["version"] == 2
    assert approved["reviewed_by"] == "reviewer"
    assert store.retrieve("SSH")[0]["trusted"] is True
    assert [x["status"] for x in store.history(candidate["id"])] == ["candidate", "approved"]
    assert store.list_candidates() == []
    assert store.audit.verify()
    assert any(e["event"] == "knowledge.promoted" for e in store.audit.list())


def test_review_requires_role_and_exact_revision(store):
    candidate = propose(store)
    with pytest.raises(Forbidden):
        store.promote(candidate["id"], 1, candidate["payload_hash"], Principal(user_id="alice"))
    with pytest.raises(Conflict):
        store.promote(candidate["id"], 1, "wrong", Principal(user_id="human", role="reviewer"))
    updated = store.modify(
        candidate["id"], 1, {"statement": "Require evidence before changing SSH."}
    )
    with pytest.raises(Conflict):
        approve(store, candidate)
    assert approve(store, updated)["statement"] == updated["statement"]
    with pytest.raises(Conflict):
        approve(store, updated)


def test_reviewed_updates_keep_old_trusted_version_until_review(store):
    first = approve(store, propose(store))
    second = propose(store, target_id=first["id"])
    modified = store.modify(
        second["id"], second["version"], {"statement": "SSH requires owner review."}
    )
    assert store.retrieve("SSH")[0]["version"] == first["version"]
    approved = approve(store, modified)
    assert store.retrieve("SSH")[0]["version"] == approved["version"]
    assert len(store.history(first["id"])) == 5
    with store.db.engine.connect() as conn, pytest.raises(DatabaseError):
        conn.execute(text("UPDATE knowledge_versions SET payload='{}'"))


def test_rejection_never_becomes_retrievable(store):
    candidate = propose(store)
    rejected = store.reject(candidate["id"], Principal(user_id="reviewer", role="reviewer"))
    assert rejected["status"] == "rejected"
    assert store.retrieve("SSH", include_candidates=True) == []
    with pytest.raises(Conflict):
        approve(store, candidate)


def test_evidence_and_secret_rejection(store, monkeypatch):
    with pytest.raises(Invalid):
        store.propose("x", "SSH", {}, [], [], "alice")
    monkeypatch.setenv("HARNESS_OPERATOR_TOKEN", "confidential-operator-credential")
    for statement in [
        "password=verysecret",
        "confidential-operator-credential",
        '{"token": "secret-json-value"}',
    ]:
        with pytest.raises(Invalid):
            store.propose("x", statement, {}, [{"type": "incident", "reference": "x"}], [], "alice")
    assert store.list_candidates() == []


def test_modification_cannot_set_review_state_or_identity(store):
    candidate = propose(store)
    for changes in [{"status": "approved"}, {"id": "../elsewhere"}, {"reviewed_by": "alice"}]:
        with pytest.raises(Invalid):
            store.modify(candidate["id"], 1, changes)


def test_import_is_confined_and_requires_review_metadata(tmp_path):
    db = Database("sqlite:///:memory:")
    knowledge = tmp_path / "knowledge"
    knowledge.mkdir()
    (knowledge / "approved").symlink_to(tmp_path)
    with pytest.raises(Invalid):
        KnowledgeStore(db, tmp_path, AuditLog(db))


def test_import_cannot_trust_candidate_based_on_folder(store):
    candidate = propose(store)
    exported = store.export(candidate)
    (store.root / "approved" / "misplaced.md").write_text(exported.read_text())
    with pytest.raises(Invalid):
        store.import_documents()
    assert store.retrieve("SSH") == []


def test_imported_scenario_requires_full_review_provenance(store):
    root = Path(__file__).resolve().parents[1]
    fixture = root / "knowledge/scenarios/aws-security-group-exposure.md"
    path = store.root / "scenarios/mock.md"
    path.write_text(fixture.read_text())
    assert store.import_documents() == 1
    docs = store.retrieve("SSH internet", allowed_sources=["knowledge/scenarios"])
    assert docs[0]["source"] == "knowledge/scenarios"
    assert docs[0]["trusted"]
    assert store.import_documents() == 0
    path.write_text(
        fixture.read_text().replace(
            "reviewed_by: repository-fixture-maintainer", "reviewed_by: null"
        )
    )
    with pytest.raises(Invalid):
        store.import_documents()


def test_import_rejects_silent_existing_version_edits(store):
    candidate = propose(store)
    path = store.export(candidate)
    path.write_text(
        path.read_text().replace("Inspect public SSH", "Automatically remove public SSH")
    )
    with pytest.raises(Conflict):
        store.import_documents()
    assert store.get_candidate(candidate["id"])["statement"].startswith("Inspect")


def test_learning_is_candidate_only_and_session_bound(store):
    memory = SessionMemory(store.db)
    learning = LearningService(store, memory)
    session = memory.create("alice", "agent")
    with pytest.raises(Invalid):
        learning.learn(session, "alice", "agent")
    memory.append(session, "alice", "agent", "assistant", "SSH is publicly exposed in sg-12345.")
    candidate = learning.learn(session, "alice", "agent")
    assert candidate["status"] == "candidate"
    assert candidate["sources"] == [{"type": "session", "reference": session}]
    assert "Unverified" in candidate["statement"]
    assert store.retrieve("SSH") == []
    assert store.retrieve("SSH", include_candidates=True)
    with pytest.raises(Invalid):
        learning.learn("", "alice", "agent", statement="SSH")
