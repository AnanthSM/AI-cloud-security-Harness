import asyncio
import time

from harness.approvals.service import ActionEnvelope
from harness.audit.service import AuditEvent, redact
from harness.errors import Conflict, Forbidden, HarnessError
from harness.schemas import Decision, Principal, Risk, RunResult
from harness.tools.executor import ToolUncertainOutcome
from harness.util import digest, utcnow


class GovernedTools:
    """The only application path to tool execution. Models may call propose only."""

    def __init__(self, agents, registry, policy, approvals, executor, audit, memory, telemetry):
        self.agents, self.registry, self.policy = agents, registry, policy
        self.approvals, self.executor, self.audit = approvals, executor, audit
        self.memory, self.telemetry = memory, telemetry

    def _agents(self):
        # Agent files are trusted control-plane configuration. Reload to revoke stale approvals.
        from harness.agents.loader import AgentLoader

        return (
            AgentLoader(self.agents.directory) if hasattr(self.agents, "directory") else self.agents
        )

    async def propose(
        self,
        user: Principal,
        agent_id: str,
        session_id: str,
        name: str,
        arguments: dict,
        knowledge_sources: list[str] | None = None,
    ) -> RunResult:
        with self.telemetry.span("harness.operation"):
            return await self._propose(
                user, agent_id, session_id, name, arguments, knowledge_sources
            )

    async def _propose(
        self,
        user: Principal,
        agent_id: str,
        session_id: str,
        name: str,
        arguments: dict,
        knowledge_sources: list[str] | None = None,
    ) -> RunResult:
        session = agent = tool = None
        try:
            session = self.memory.get(session_id, user.user_id, agent_id)
            agent = self._agents().get(agent_id)
            tool = self.registry.resolve(name)
            args = self.registry.validate_input(name, arguments)
            # Secrets belong to credential providers, never model-supplied tool parameters.
            if redact(args) != args or tool.sensitive_fields:
                raise Forbidden("Model tool arguments must not contain credentials")
            self.policy.reload()
        except HarnessError as error:
            # Unknown names and malformed arguments are untrusted data. Record
            # only identifiers already resolved from trusted control-plane state.
            self.audit.record(
                AuditEvent(
                    event="tool.proposal_rejected",
                    trace_id=self.telemetry.trace_id(),
                    user_id=user.user_id,
                    session_id=session["id"] if session else "",
                    agent_id=agent.id if agent else "",
                    agent_version=agent.version if agent else "",
                    tool=tool.name if tool else "",
                    tool_version=tool.version if tool else "",
                    execution_result=type(error).__name__,
                )
            )
            raise
        with self.telemetry.span("policy.evaluation", tool=name):
            decision = self.policy.evaluate(user=user, agent=agent, tool=tool, arguments=args)
        event = AuditEvent(
            event="policy.evaluated",
            trace_id=self.telemetry.trace_id(),
            session_id=session_id,
            user_id=user.user_id,
            agent_id=agent.id,
            agent_version=agent.version,
            skill=agent.skills,
            tool=name,
            tool_version=tool.version,
            arguments_hash=digest(args),
            policy_decision=decision.decision.value,
            knowledge_sources=knowledge_sources or [],
        )
        self.audit.record(event)
        if decision.decision == Decision.DENY:
            self.telemetry.count("policy_denials_total")
            return RunResult(
                session_id=session_id,
                status="denied",
                message=decision.reason,
                tool=name,
                policy_decision=decision.decision.value,
            )
        if decision.decision == Decision.APPROVAL_REQUIRED:
            environment, resource = self.policy.resolve_scope(tool, args)
            envelope = ActionEnvelope(
                session_id=session_id,
                user_id=user.user_id,
                agent_id=agent.id,
                agent_version=agent.version,
                agent_digest=digest(agent.model_dump(mode="json")),
                tool=name,
                tool_version=tool.version,
                tool_digest=digest(tool.model_dump(mode="json")),
                arguments=args,
                environment=environment,
                resource=resource,
                risk=tool.risk,
                policy_revision=self.policy.revision,
                proposed_action=tool.description,
                knowledge_sources=knowledge_sources or [],
                trace_id=self.telemetry.trace_id(),
            )
            with self.telemetry.span("approval.request", tool=name):
                approval = self.approvals.create(envelope, decision.reason)
            self.telemetry.count("approval_requests_total")
            return RunResult(
                session_id=session_id,
                status="approval_required",
                message=f"{name} requested. Risk: {tool.risk.value}. Environment: {environment}. Human approval required; no change performed.",
                tool=name,
                policy_decision=decision.decision.value,
                approval_id=approval["id"],
                data={"approval": approval},
            )
        # A defense in depth invariant independent of prompt/model cooperation.
        if tool.risk != Risk.READ:
            raise Forbidden("Writes cannot execute without an approval claim")

        def validate_dispatch():
            self.memory.get(session_id, user.user_id, agent_id)
            self.policy.reload()
            current_agent = self._agents().get(agent_id)
            current_tool = self.registry.resolve(name)
            if digest(current_tool.model_dump(mode="json")) != digest(tool.model_dump(mode="json")):
                raise Conflict("Tool configuration changed before dispatch")
            current = self.policy.evaluate(
                user=user, agent=current_agent, tool=current_tool, arguments=args
            )
            if current.decision != Decision.ALLOW or current_tool.risk != Risk.READ:
                self.telemetry.count("policy_denials_total")
                self.audit.record(
                    event.model_copy(
                        update={
                            "event": "policy.dispatch_denied",
                            "policy_decision": current.decision.value,
                        }
                    )
                )
                raise Forbidden("Current policy does not allow this read action")

        result = await self._execute(name, args, event, before_dispatch=validate_dispatch)
        return RunResult(
            session_id=session_id,
            status="completed",
            message="Tool completed",
            tool=name,
            policy_decision=decision.decision.value,
            data=result,
        )

    def _validate_approval(self, action: ActionEnvelope):
        self.memory.get(action.session_id, action.user_id, action.agent_id)
        self.policy.reload()
        agent = self._agents().get(action.agent_id)
        tool = self.registry.resolve(action.tool)
        args = self.registry.validate_input(action.tool, action.arguments)
        environment, resource = self.policy.resolve_scope(tool, args)
        if (
            digest(agent.model_dump(mode="json")) != action.agent_digest
            or digest(tool.model_dump(mode="json")) != action.tool_digest
            or self.policy.revision != action.policy_revision
            or environment != action.environment
            or resource != action.resource
            or tool.risk != action.risk
        ):
            raise Conflict("Authorization configuration changed; submit a new proposal")
        decision = self.policy.evaluate(
            user=Principal(user_id=action.user_id), agent=agent, tool=tool, arguments=args
        )
        if decision.decision == Decision.DENY:
            raise Forbidden("Current policy denies the approved action")

    async def approve(self, approval_id: str, reviewer: Principal, expected_hash: str) -> dict:
        with self.telemetry.span("approval.review"):
            return await self._approve(approval_id, reviewer, expected_hash)

    async def _approve(self, approval_id: str, reviewer: Principal, expected_hash: str) -> dict:
        action = self.approvals.claim(approval_id, reviewer, expected_hash, self._validate_approval)
        deadline = self.approvals.get(approval_id)["expires_at"]

        def validate_dispatch():
            if deadline <= utcnow().isoformat():
                raise Conflict("Approval execution deadline expired; submit a new proposal")
            self._validate_approval(action.model_copy(deep=True))

        event = AuditEvent(
            event="tool.execution",
            trace_id=self.telemetry.trace_id(),
            session_id=action.session_id,
            user_id=action.user_id,
            agent_id=action.agent_id,
            agent_version=action.agent_version,
            tool=action.tool,
            tool_version=action.tool_version,
            arguments_hash=digest(action.arguments),
            policy_decision="APPROVAL_REQUIRED",
            approval_result="APPROVED",
            knowledge_sources=action.knowledge_sources,
        )
        try:
            result = await self._execute(
                action.tool,
                action.arguments,
                event,
                before_dispatch=validate_dispatch,
            )
        except ToolUncertainOutcome:
            self.approvals.complete(approval_id, None, "UNKNOWN")
            raise
        except asyncio.CancelledError:
            self.approvals.complete(approval_id, None, "UNKNOWN")
            raise
        except HarnessError:
            self.approvals.complete(approval_id, None, "FAILED")
            raise
        self.approvals.complete(approval_id, redact(result), "SUCCEEDED")
        self.memory.append(
            action.session_id,
            action.user_id,
            action.agent_id,
            "tool",
            {"tool": action.tool, "data": redact(result)},
        )
        return self.approvals.get(approval_id)

    async def _execute(self, name, arguments, event, before_dispatch=None):
        self.telemetry.count("tool_requests_total", tool=name)
        started = time.monotonic()
        # Persist intent before side effects. Audit failure prevents execution.
        self.audit.record(
            event.model_copy(update={"event": "tool.started", "execution_result": "STARTED"})
        )
        try:
            with self.telemetry.span("tool.execution", tool=name):
                result = await self.executor.execute(
                    name, arguments, before_dispatch=before_dispatch
                )
        except BaseException as error:
            self.telemetry.count("tool_failures_total", tool=name)
            uncertain = isinstance(error, ToolUncertainOutcome) or (
                isinstance(error, asyncio.CancelledError)
                and self.registry.resolve(name).risk != Risk.READ
            )
            self.audit.record(
                event.model_copy(
                    update={
                        "event": "tool.outcome_unknown" if uncertain else "tool.failed",
                        "execution_result": "UNKNOWN" if uncertain else "FAILED",
                        "latency_ms": (time.monotonic() - started) * 1000,
                    }
                )
            )
            raise
        duration = (time.monotonic() - started) * 1000
        self.telemetry.observe("tool_latency", duration, tool=name)
        self.audit.record(
            event.model_copy(
                update={
                    "event": "tool.completed",
                    "execution_result": "SUCCEEDED",
                    "latency_ms": duration,
                }
            )
        )
        return redact(result)
