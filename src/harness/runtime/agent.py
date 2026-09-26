import asyncio
import time

from harness.audit.service import AuditEvent, redact
from harness.errors import Invalid
from harness.models.base import ModelResponse
from harness.schemas import RunResult


class AgentRuntime:
    """Bounded model loop. There is no direct model-to-gateway execution path."""

    def __init__(
        self, agents, memory, context, provider, governance, learning, audit, telemetry, max_steps=8
    ):
        self.agents, self.memory, self.context = agents, memory, context
        self.provider, self.governance, self.learning = provider, governance, learning
        self.audit, self.telemetry, self.max_steps = audit, telemetry, max_steps

    async def run(self, request, principal):
        with self.telemetry.span("agent.request", agent=request.agent_id):
            self.telemetry.count("agent_requests_total")
            agent = self.governance._agents().get(request.agent_id)
            session_id = request.session_id or self.memory.create(principal.user_id, agent.id)
            session = self.memory.get(session_id, principal.user_id, agent.id)
            if request.prompt.strip() == "/learn":
                candidate = self.learning.learn(session_id, principal.user_id, agent.id)
                return RunResult(
                    session_id=session_id,
                    status="candidate_created",
                    message="Candidate knowledge created; human review is required before promotion.",
                    data=candidate,
                )
            self.memory.append(session_id, principal.user_id, agent.id, "user", request.prompt)
            with self.telemetry.span("context.construction"):
                context = self.context.build(agent, request, session)
            self.audit.record(
                AuditEvent(
                    event="agent.started",
                    trace_id=self.telemetry.trace_id(),
                    session_id=session_id,
                    user_id=principal.user_id,
                    agent_id=agent.id,
                    agent_version=agent.version,
                    skill=context.skill_ids,
                    knowledge_sources=context.knowledge_sources,
                    model=self.provider.name,
                )
            )
            last = None
            for _ in range(self.max_steps):
                start = time.monotonic()
                try:
                    with self.telemetry.span("model.request", model=self.provider.name):
                        response = await asyncio.wait_for(
                            self.provider.generate(
                                context.messages,
                                tools=context.tools,
                                response_schema=ModelResponse.model_json_schema(),
                            ),
                            timeout=30,
                        )
                    with self.telemetry.span("model.response", model=self.provider.name):
                        response = ModelResponse.model_validate(response)
                except Exception:
                    self.audit.record(
                        AuditEvent(
                            event="model.failed",
                            trace_id=self.telemetry.trace_id(),
                            session_id=session_id,
                            user_id=principal.user_id,
                            agent_id=agent.id,
                            model=self.provider.name,
                            execution_result="INVALID_OR_FAILED_RESPONSE",
                        )
                    )
                    raise Invalid("Model request failed or returned an invalid response") from None
                self.telemetry.observe("model_latency", (time.monotonic() - start) * 1000)
                self.telemetry.count(
                    "model_tokens_total", response.input_tokens + response.output_tokens
                )
                if response.tool_call:
                    call = response.tool_call
                    last = await self.governance.propose(
                        principal,
                        agent.id,
                        session_id,
                        call.name,
                        call.arguments,
                        context.knowledge_sources,
                    )
                    if last.status != "completed":
                        self.memory.append(
                            session_id, principal.user_id, agent.id, "assistant", last.message
                        )
                        return last
                    context.add_tool_result(call.name, last.data)
                    self.memory.append(
                        session_id,
                        principal.user_id,
                        agent.id,
                        "tool",
                        {"tool": call.name, "data": last.data},
                    )
                    if "security_group_id" in call.arguments:
                        self.memory.set_state(
                            session_id,
                            principal.user_id,
                            agent.id,
                            {"last_resource": call.arguments},
                        )
                else:
                    message = redact(response.text)
                    self.memory.append(
                        session_id, principal.user_id, agent.id, "assistant", message
                    )
                    self.audit.record(
                        AuditEvent(
                            event="agent.completed",
                            trace_id=self.telemetry.trace_id(),
                            session_id=session_id,
                            user_id=principal.user_id,
                            agent_id=agent.id,
                            agent_version=agent.version,
                            knowledge_sources=context.knowledge_sources,
                            model=self.provider.name,
                            execution_result="COMPLETED",
                        )
                    )
                    return RunResult(
                        session_id=session_id,
                        status="completed",
                        message=message,
                        tool=last.tool if last else None,
                        policy_decision=last.policy_decision if last else None,
                        data=last.data if last else None,
                        knowledge_sources=context.knowledge_sources,
                    )
            raise Invalid("Model exceeded the bounded execution step budget")
