"""Conservative local candidate extraction; a session is evidence, not proof."""
from harness.errors import Invalid
from harness.knowledge.store import KnowledgeStore
from harness.memory.service import SessionMemory


class LearningService:
    def __init__(self, store: KnowledgeStore, memory: SessionMemory):
        self.store, self.memory = store, memory

    def learn(self, session_id: str, user_id: str, agent_id: str,
              title: str | None = None, statement: str | None = None,
              sources: list | None = None) -> dict:
        if not session_id:
            raise Invalid("Learning requires an existing task session")
        session = self.memory.get(session_id, user_id, agent_id)
        if not statement:
            messages = [m for m in session["messages"]
                        if m["role"] in {"assistant", "tool"} and m["content"].strip()]
            if not messages:
                raise Invalid("Complete an investigation or provide a candidate statement first")
            excerpts = "\n\n".join(f"{m['role']}: {m['content']}" for m in messages[-3:])
            statement = ("Unverified investigation notes. Review the evidence before adoption.\n\n"
                         + excerpts[:16000])
        return self.store.propose(
            title=title or "Investigation lesson awaiting review", statement=statement,
            scope={"agent": agent_id}, sources=sources or [{"type": "session", "reference": session_id}],
            tags=["learned", "requires-review"], user_id=user_id, session_id=session_id)
