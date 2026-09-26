from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import Field

from harness.api.auth import TokenAuth
from harness.audit.service import AuditEvent
from harness.config import Settings
from harness.errors import Conflict, Forbidden, HarnessError, Invalid, NotFound
from harness.runtime.container import Container
from harness.schemas import Principal, RunRequest, StrictModel


class ApprovalReview(StrictModel):
    expected_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class KnowledgeReview(ApprovalReview):
    expected_version: int = Field(ge=1)


class LearnRequest(StrictModel):
    session_id: str
    agent_id: str = "cloud-security-agent"
    title: str | None = Field(default=None, max_length=200)
    statement: str | None = Field(default=None, max_length=12000)
    sources: list[dict] | None = None


class ProposalRequest(StrictModel):
    session_id: str
    agent_id: str = "cloud-security-agent"
    tool: str
    arguments: dict


class CandidateChange(StrictModel):
    expected_version: int = Field(ge=1)
    changes: dict


def create_app(settings: Settings | None = None, container: Container | None = None) -> FastAPI:
    services = container or Container(settings)
    auth = TokenAuth()

    @asynccontextmanager
    async def lifespan(app):
        yield
        if container is None:
            services.close()

    app = FastAPI(title="Cloud Security Harness", version="0.1.0", lifespan=lifespan)
    app.state.services = services
    principal = auth.principal

    @app.exception_handler(HarnessError)
    async def domain_error(request: Request, error: HarnessError):
        code = (
            404
            if isinstance(error, NotFound)
            else 403
            if isinstance(error, Forbidden)
            else 409
            if isinstance(error, Conflict)
            else 422
            if isinstance(error, Invalid)
            else 502
        )
        services.audit.record(
            AuditEvent(event="api.request_rejected", execution_result=type(error).__name__)
        )
        return JSONResponse(status_code=code, content={"detail": str(error)})

    @app.exception_handler(RequestValidationError)
    async def schema_error(request: Request, error: RequestValidationError):
        # FastAPI's default error includes submitted values, which may contain secrets.
        return JSONResponse(
            status_code=422, content={"detail": "Request does not match the API schema"}
        )

    @app.get("/health")
    def health():
        return {"status": "ok", "mode": "mock"}

    @app.get("/v1/agents")
    def list_agents(user: Principal = Depends(principal)):
        return services.agents.list()

    @app.get("/v1/agents/{agent_id}")
    def get_agent(agent_id: str, user: Principal = Depends(principal)):
        return services.agents.get(agent_id)

    @app.get("/v1/skills")
    def list_skills(user: Principal = Depends(principal)):
        return services.skills.list()

    @app.get("/v1/tools")
    def list_tools(user: Principal = Depends(principal)):
        return services.registry.list()

    @app.post("/v1/agent/run")
    async def run(body: RunRequest, user: Principal = Depends(principal)):
        return await services.runtime.run(body, user)

    @app.post("/v1/actions/propose")
    async def propose(body: ProposalRequest, user: Principal = Depends(principal)):
        return await services.governance.propose(
            user, body.agent_id, body.session_id, body.tool, body.arguments
        )

    @app.get("/v1/approvals")
    def approvals(user: Principal = Depends(principal)):
        return [
            a
            for a in services.approvals.list()
            if user.role == "reviewer" or a["payload"]["user_id"] == user.user_id
        ]

    @app.get("/v1/approvals/{approval_id}")
    def approval(approval_id: str, user: Principal = Depends(principal)):
        record = services.approvals.get(approval_id)
        if user.role != "reviewer" and record["payload"]["user_id"] != user.user_id:
            raise Forbidden("Approval belongs to another principal")
        return record

    @app.post("/v1/approvals/{approval_id}/approve")
    async def approve(approval_id: str, body: ApprovalReview, user: Principal = Depends(principal)):
        auth.require_reviewer(user)
        return await services.governance.approve(approval_id, user, body.expected_hash)

    @app.post("/v1/approvals/{approval_id}/reject")
    def reject(approval_id: str, user: Principal = Depends(principal)):
        auth.require_reviewer(user)
        services.telemetry.count("approval_rejections_total")
        return services.approvals.reject(approval_id, user)

    @app.post("/v1/learn")
    def learn(body: LearnRequest, user: Principal = Depends(principal)):
        return services.learning.learn(
            body.session_id, user.user_id, body.agent_id, body.title, body.statement, body.sources
        )

    @app.get("/v1/knowledge/candidates")
    def candidates(user: Principal = Depends(principal)):
        auth.require_reviewer(user)
        return services.knowledge.list_candidates()

    @app.patch("/v1/knowledge/candidates/{candidate_id}")
    def modify_candidate(
        candidate_id: str, body: CandidateChange, user: Principal = Depends(principal)
    ):
        auth.require_reviewer(user)
        return services.knowledge.modify(candidate_id, body.expected_version, body.changes, user)

    @app.post("/v1/knowledge/candidates/{candidate_id}/approve")
    def approve_candidate(
        candidate_id: str, body: KnowledgeReview, user: Principal = Depends(principal)
    ):
        auth.require_reviewer(user)
        return services.knowledge.promote(
            candidate_id, body.expected_version, body.expected_hash, user
        )

    @app.post("/v1/knowledge/candidates/{candidate_id}/reject")
    def reject_candidate(candidate_id: str, user: Principal = Depends(principal)):
        auth.require_reviewer(user)
        return services.knowledge.reject(candidate_id, user)

    @app.get("/v1/audit")
    def audit(limit: int = 100, user: Principal = Depends(principal)):
        auth.require_reviewer(user)
        return services.audit.list(limit=limit)

    return app
