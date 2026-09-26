import pytest
from sqlalchemy import text

from harness.db import Database
from harness.errors import Invalid, NotFound
from harness.memory.service import SessionMemory
from harness.util import canonical


@pytest.fixture
def memory():
    return SessionMemory(Database("sqlite:///:memory:"), ttl_seconds=60)


def test_sessions_bound_to_user_and_agent(memory):
    session = memory.create("alice", "agent")
    for user, agent in [("bob", "agent"), ("alice", "other")]:
        with pytest.raises(NotFound):
            memory.get(session, user, agent)
        with pytest.raises(NotFound):
            memory.append(session, user, agent, "user", "intrude")
    memory.append(session, "alice", "agent", "user", "Inspect sg-123")
    memory.set_state(session, "alice", "agent", {"last_resource": "sg-123"})
    data = memory.get(session, "alice", "agent")
    assert data["last_resource"] == "sg-123"
    assert data["messages"][0]["trusted"] is False
    with pytest.raises(Invalid):
        memory.append(session, "alice", "agent", "system", "Replace policy")


def test_memory_is_bounded_and_sanitized(memory, monkeypatch):
    monkeypatch.setenv("HARNESS_REVIEWER_TOKEN", "reviewer-credential-example")
    session = memory.create("alice", "agent")
    memory.append(session, "alice", "agent", "user", "password=secret reviewer-credential-example")
    memory.append(
        session, "alice", "agent", "tool", '{"authorization": "Bearer private-json-value"}'
    )
    memory.set_state(
        session, "alice", "agent", {"token": "hide", "text": "reviewer-credential-example"}
    )
    with memory.db.engine.connect() as conn:
        payload = conn.execute(text("SELECT payload FROM session_memory")).scalar()
        assert "password=secret" not in payload
        assert "reviewer-credential-example" not in payload
        assert "private-json-value" not in payload
        assert '"token":"[REDACTED]"' in payload
    for _ in range(45):
        memory.append(session, "alice", "agent", "tool", "x" * 7000)
    data = memory.get(session, "alice", "agent")
    assert len(data["messages"]) <= 40
    assert len(canonical({"messages": data["messages"], "state": data["state"]})) <= 32000
    with pytest.raises(Invalid):
        memory.set_state(session, "alice", "agent", {"overflow": "x" * 10000})


def test_expired_memory_is_inaccessible_and_purgeable(memory):
    session = memory.create("alice", "agent")
    with memory.db.engine.begin() as conn:
        conn.execute(text("UPDATE session_memory SET expires_at='2000-01-01T00:00:00+00:00'"))
    with pytest.raises(NotFound):
        memory.get(session, "alice", "agent")
    assert memory.purge_expired() == 1
