import shutil
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

import harness.approvals.service as approval_module
from harness.agents.loader import AgentLoader
from harness.approvals.service import ActionEnvelope, ApprovalEngine
from harness.audit.service import AuditEvent, AuditLog, AuditRow, redact
from harness.db import Database
from harness.errors import Conflict, Forbidden, Invalid
from harness.policies.engine import PolicyEngine
from harness.schemas import Decision, Principal, Risk, ToolDefinition
from harness.tools.catalog import create_registry
from harness.util import canonical, digest

ROOT = Path(__file__).resolve().parents[1]
OPERATOR = Principal(user_id="engineer", role="operator")
REVIEWER = Principal(user_id="security-reviewer", role="reviewer")


@pytest.fixture
def policy_directory(tmp_path):
    directory = tmp_path / "policies"
    shutil.copytree(ROOT / "policies", directory)
    return directory


@pytest.fixture
def security_state(tmp_path):
    database = Database(f"sqlite:///{tmp_path / 'security.db'}")
    audit = AuditLog(database)
    approvals = ApprovalEngine(database, audit, ttl_seconds=60)
    yield database, audit, approvals
    database.engine.dispose()


def tool(risk=Risk.READ, name="aws.get_security_group"):
    schema = {"type": "object", "properties": {}, "additionalProperties": False}
    return ToolDefinition(
        name=name,
        description="Security group test tool",
        provider="aws",
        version="1.0.0",
        risk=risk,
        input_schema=schema,
        output_schema=schema,
        resource_fields=["account_id", "security_group_id"],
    )


def envelope():
    return ActionEnvelope(
        session_id="session-001",
        user_id=OPERATOR.user_id,
        agent_id="cloud-security-agent",
        agent_version="0.1.0",
        agent_digest="a" * 64,
        tool="aws.modify_security_group",
        tool_version="1.0.0",
        tool_digest="b" * 64,
        arguments={
            "account_id": "111111111111",
            "security_group_id": "sg-12345",
            "change": {"remove_rule": "0.0.0.0/0:22"},
        },
        environment="production",
        resource="aws:account_id=111111111111/security_group_id=sg-12345",
        risk=Risk.HIGH_RISK_WRITE,
        policy_revision="c" * 64,
        proposed_action="Remove the public SSH ingress rule",
        trace_id="trace-001",
    )


def evaluate(directory, *, definition=None, arguments=None, agent=None, user=OPERATOR):
    return PolicyEngine(directory).evaluate(
        user=user,
        agent=agent or AgentLoader(ROOT / "agents").get("cloud-security-agent"),
        tool=definition or tool(),
        arguments=arguments
        if arguments is not None
        else {"account_id": "111111111111", "security_group_id": "sg-12345"},
    )


def test_policy_read_allowed_and_production_write_requires_approval(policy_directory):
    assert evaluate(policy_directory).decision == Decision.ALLOW
    result = evaluate(
        policy_directory, definition=tool(Risk.HIGH_RISK_WRITE, "aws.modify_security_group")
    )
    assert result.decision == Decision.APPROVAL_REQUIRED


@pytest.mark.parametrize(
    "group,permission,write_permission,expected",
    [
        (True, "allow", "approval_required", Decision.ALLOW),
        (False, "allow", "approval_required", Decision.APPROVAL_REQUIRED),
        (True, "approval_required", "approval_required", Decision.APPROVAL_REQUIRED),
        (True, "deny", "approval_required", Decision.DENY),
        (True, "allow", "deny", Decision.DENY),
    ],
)
def test_low_risk_auto_execution_requires_explicit_capability_permission_and_policy(
    policy_directory, group, permission, write_permission, expected
):
    (policy_directory / "tool-access.yaml").write_text(
        yaml.safe_dump(
            {
                "rules": [
                    {
                        "id": "EXPLICIT-ISSUE-ALLOW",
                        "risks": ["LOW_RISK_WRITE"],
                        "decision": "ALLOW",
                        "tools": ["gitlab.create_issue"],
                        "reason": "Reviewed automatic issue creation",
                    }
                ]
            }
        )
    )
    (policy_directory / "approvals.yaml").write_text("rules: []\n")
    agent = AgentLoader(ROOT / "agents").get("cloud-security-agent")
    agent.default_permissions.low_risk_write = permission
    agent.default_permissions.write = write_permission
    if group:
        agent.tool_groups.append("gitlab.write")
    result = evaluate(
        policy_directory,
        agent=agent,
        definition=create_registry().resolve("gitlab.create_issue"),
        arguments={"project_id": 42, "title": "Investigation", "description": "Track remediation"},
    )
    assert result.decision == expected


def test_low_risk_opt_in_cannot_override_a_matching_production_approval_rule(policy_directory):
    agent = AgentLoader(ROOT / "agents").get("cloud-security-agent")
    agent.tool_groups.append("gitlab.write")
    agent.default_permissions.low_risk_write = "allow"
    path = policy_directory / "tool-access.yaml"
    rules = yaml.safe_load(path.read_text())
    rules["rules"].append(
        {
            "id": "SPECIFIC-ISSUE-ALLOW",
            "risks": ["LOW_RISK_WRITE"],
            "tools": ["gitlab.create_issue"],
            "decision": "ALLOW",
            "reason": "Optional opt-in",
        }
    )
    path.write_text(yaml.safe_dump(rules))
    result = evaluate(
        policy_directory,
        agent=agent,
        definition=create_registry().resolve("gitlab.create_issue"),
        arguments={"project_id": 42, "title": "Investigation", "description": "Track remediation"},
    )
    assert result.decision == Decision.APPROVAL_REQUIRED


def test_low_risk_opt_in_cannot_downgrade_a_high_risk_tool(policy_directory):
    (policy_directory / "tool-access.yaml").write_text(
        yaml.safe_dump(
            {
                "rules": [
                    {
                        "id": "HIGH-WRITE-ALLOW",
                        "risks": ["HIGH_RISK_WRITE"],
                        "decision": "ALLOW",
                        "reason": "The high-risk approval floor must still apply",
                    }
                ]
            }
        )
    )
    (policy_directory / "approvals.yaml").write_text("rules: []\n")
    agent = AgentLoader(ROOT / "agents").get("cloud-security-agent")
    agent.tool_groups.append("aws.write")
    agent.default_permissions.low_risk_write = "allow"
    result = evaluate(
        policy_directory,
        agent=agent,
        definition=tool(Risk.HIGH_RISK_WRITE, "aws.modify_security_group"),
    )
    assert result.decision == Decision.APPROVAL_REQUIRED


def test_policy_deny_overrides_allow_independent_of_order(policy_directory):
    path = policy_directory / "tool-access.yaml"
    original = yaml.safe_load(path.read_text())
    denial = {
        "id": "RESTRICTED-RESOURCE",
        "risks": ["READ"],
        "decision": "DENY",
        "reason": "Restricted resource",
        "resources": ["*security_group_id=sg-12345"],
    }
    for rules in [original["rules"] + [denial], [denial] + original["rules"]]:
        path.write_text(yaml.safe_dump({"rules": rules}))
        result = evaluate(policy_directory)
        assert result.decision == Decision.DENY
        assert result.policy == "RESTRICTED-RESOURCE"


def test_policy_no_matching_grant_denies(policy_directory):
    for filename in ["tool-access.yaml", "approvals.yaml"]:
        (policy_directory / filename).write_text("rules: []\n")
    result = evaluate(policy_directory)
    assert result.decision == Decision.DENY
    assert result.policy == "DEFAULT-DENY"


@pytest.mark.parametrize(
    "arguments",
    [
        {"account_id": "999999999999", "security_group_id": "sg-12345"},
        {"security_group_id": "sg-12345", "environment": "production"},
        {"account_id": "111111111111"},
    ],
)
def test_policy_unknown_or_incomplete_scope_denies(policy_directory, arguments):
    result = evaluate(policy_directory, arguments=arguments)
    assert result.decision == Decision.DENY
    assert result.policy == "ENVIRONMENT-DENY"


def test_environment_is_resolved_from_inventory_not_model_content(policy_directory):
    policy = PolicyEngine(policy_directory)
    environment, resource = policy.resolve_scope(
        tool(),
        {
            "account_id": "111111111111",
            "security_group_id": "sg-12345",
            "environment": "development",
            "risk": "READ",
            "approved": True,
        },
    )
    assert environment == "production"
    assert resource == "aws:account_id=111111111111/security_group_id=sg-12345"


def test_agent_capability_and_permission_limits_override_policy_grants(policy_directory):
    agent = AgentLoader(ROOT / "agents").get("cloud-security-agent")
    agent.tool_groups = []
    assert evaluate(policy_directory, agent=agent).policy == "AGENT-LEAST-PRIVILEGE"
    agent.tool_groups = ["aws.read"]
    agent.default_permissions.read = "deny"
    assert evaluate(policy_directory, agent=agent).policy == "AGENT-DENY"
    agent.default_permissions.write = "deny"
    assert (
        evaluate(
            policy_directory,
            agent=agent,
            definition=tool(Risk.HIGH_RISK_WRITE, "aws.modify_security_group"),
        ).decision
        == Decision.DENY
    )


def test_destructive_and_unauthorized_principal_always_denied(policy_directory):
    destructive = evaluate(policy_directory, definition=tool(Risk.DESTRUCTIVE, "aws.delete_bucket"))
    assert destructive.decision == Decision.DENY
    assert destructive.policy == "AGENT-DESTRUCTIVE-DENY"
    assert (
        evaluate(policy_directory, user=Principal(user_id="model", role="model")).decision
        == Decision.DENY
    )


def test_agent_write_gate_survives_an_allow_rule(policy_directory):
    for filename in ["tool-access.yaml", "approvals.yaml"]:
        (policy_directory / filename).write_text("rules: []\n")
    (policy_directory / "tool-access.yaml").write_text(
        yaml.safe_dump(
            {
                "rules": [
                    {
                        "id": "WRITE-ALLOW",
                        "risks": ["HIGH_RISK_WRITE"],
                        "decision": "ALLOW",
                        "reason": "Agent gate must still apply",
                    }
                ]
            }
        )
    )
    result = evaluate(
        policy_directory, definition=tool(Risk.HIGH_RISK_WRITE, "aws.modify_security_group")
    )
    assert result.decision == Decision.APPROVAL_REQUIRED
    assert result.policy == "AGENT-WRITE-GATE"


def test_invalid_policy_reload_cannot_partially_replace_inventory(policy_directory):
    policy = PolicyEngine(policy_directory)
    original_revision = policy.revision
    original_rules = [rule.model_dump() for rule in policy.rules]
    access = yaml.safe_load((policy_directory / "tool-access.yaml").read_text())
    access["rules"].append(access["rules"][0])
    (policy_directory / "tool-access.yaml").write_text(yaml.safe_dump(access))
    (policy_directory / "environments.yaml").write_text("scopes: {}\ncatalog_tools: []\n")

    with pytest.raises(Invalid, match="unique"):
        policy.reload()
    assert policy.revision == original_revision
    assert [rule.model_dump() for rule in policy.rules] == original_rules
    assert "aws" in policy.inventory.scopes


def test_approval_snapshots_payload_and_ignores_mutated_views(security_state):
    _, audit, approvals = security_state
    action = envelope()
    expected = action.model_dump(mode="json")
    created = approvals.create(action, "Production write")
    action.arguments["change"]["remove_rule"] = "all-rules"
    created["payload"]["arguments"]["change"]["remove_rule"] = "another-rule"
    fresh = approvals.get(created["id"])
    assert fresh["payload"] == expected
    assert fresh["payload_hash"] == digest(expected)
    assert [event["event"] for event in audit.list()] == ["approval.requested"]


def test_approval_validator_cannot_change_executed_payload(security_state):
    _, _, approvals = security_state
    created = approvals.create(envelope(), "Production write")

    def mutating_validator(action):
        action.arguments["change"]["remove_rule"] = "all-rules"
        action.environment = "development"

    approved = approvals.claim(created["id"], REVIEWER, created["payload_hash"], mutating_validator)
    assert approved.model_dump(mode="json") == created["payload"]


def test_approval_claim_requires_human_and_matching_review_digest(security_state):
    _, audit, approvals = security_state
    created = approvals.create(envelope(), "Production write")
    with pytest.raises(Forbidden):
        approvals.claim(created["id"], OPERATOR, created["payload_hash"], lambda _: None)
    with pytest.raises(Conflict, match="digest"):
        approvals.claim(created["id"], REVIEWER, "0" * 64, lambda _: None)
    assert approvals.get(created["id"])["status"] == "PENDING"
    assert len(audit.list()) == 1


def test_changed_policy_can_refuse_approval_without_claiming_it(security_state):
    _, _, approvals = security_state
    created = approvals.create(envelope(), "Production write")

    def refuse(_):
        raise Forbidden("Current policy denies this action")

    with pytest.raises(Forbidden, match="Current policy"):
        approvals.claim(created["id"], REVIEWER, created["payload_hash"], refuse)
    pending = approvals.get(created["id"])
    assert pending["status"] == "PENDING"
    assert pending["execution_status"] == "NOT_STARTED"


def test_approval_expiry_is_terminal_and_audited_once(security_state, monkeypatch):
    _, audit, approvals = security_state
    now = datetime(2030, 1, 1, tzinfo=UTC)
    monkeypatch.setattr(approval_module, "utcnow", lambda: now)
    created = approvals.create(envelope(), "Production write")
    now += timedelta(seconds=61)
    with pytest.raises(Conflict):
        approvals.claim(created["id"], REVIEWER, created["payload_hash"], lambda _: None)
    assert approvals.get(created["id"])["status"] == "EXPIRED"
    assert approvals.list()[0]["execution_status"] == "NOT_STARTED"
    assert [event["event"] for event in audit.list()].count("approval.expired") == 1


def test_approval_expiring_during_validation_cannot_execute(security_state, monkeypatch):
    _, audit, approvals = security_state
    now = [datetime(2030, 1, 1, tzinfo=UTC)]
    monkeypatch.setattr(approval_module, "utcnow", lambda: now[0])
    created = approvals.create(envelope(), "Production write")

    def slow_validator(_):
        now[0] += timedelta(seconds=61)

    with pytest.raises(Conflict, match="expired"):
        approvals.claim(created["id"], REVIEWER, created["payload_hash"], slow_validator)
    assert approvals.get(created["id"])["status"] == "EXPIRED"
    assert "approval.approved" not in [event["event"] for event in audit.list()]


def test_approval_rejection_is_terminal_and_requires_reviewer(security_state):
    _, _, approvals = security_state
    created = approvals.create(envelope(), "Production write")
    with pytest.raises(Forbidden):
        approvals.reject(created["id"], OPERATOR)
    assert approvals.reject(created["id"], REVIEWER)["status"] == "REJECTED"
    with pytest.raises(Conflict):
        approvals.claim(created["id"], REVIEWER, created["payload_hash"], lambda _: None)
    with pytest.raises(Conflict):
        approvals.reject(created["id"], REVIEWER)


@pytest.mark.parametrize("outcome", ["SUCCEEDED", "FAILED", "UNKNOWN"])
def test_approval_execution_and_terminal_outcomes_cannot_be_replayed(security_state, outcome):
    _, audit, approvals = security_state
    created = approvals.create(envelope(), "Production write")
    with pytest.raises(Conflict):
        approvals.complete(created["id"], None, outcome)
    approvals.claim(created["id"], REVIEWER, created["payload_hash"], lambda _: None)
    approvals.complete(created["id"], {"message": "Provider outcome"}, outcome)
    with pytest.raises(Conflict):
        approvals.claim(created["id"], REVIEWER, created["payload_hash"], lambda _: None)
    with pytest.raises(Conflict):
        approvals.complete(created["id"], None, outcome)
    assert approvals.get(created["id"])["execution_status"] == outcome
    assert audit.verify()


def test_concurrent_claims_allow_exactly_one_execution(security_state):
    database, audit, approvals = security_state
    created = approvals.create(envelope(), "Production write")
    count = 6
    barrier = threading.Barrier(count)

    def claim_once(_):
        barrier.wait(timeout=10)
        try:
            action = approvals.claim(
                created["id"], REVIEWER, created["payload_hash"], lambda _: None
            )
            return action.model_dump(mode="json")
        except Conflict:
            return None

    with ThreadPoolExecutor(max_workers=count) as pool:
        results = list(pool.map(claim_once, range(count)))
    assert [result for result in results if result is not None] == [created["payload"]]
    assert approvals.get(created["id"])["execution_status"] == "CLAIMED"
    assert [event["event"] for event in audit.list()].count("approval.approved") == 1
    assert audit.verify()


def test_database_blocks_approval_payload_and_expiry_mutation(security_state):
    database, _, approvals = security_state
    created = approvals.create(envelope(), "Production write")
    for field in ["payload", "payload_hash", "reason", "expires_at", "created_at"]:
        with pytest.raises(IntegrityError, match="immutable"):
            with database.engine.begin() as connection:
                connection.execute(
                    text(f"UPDATE approvals SET {field} = :value WHERE id = :id"),
                    {"value": "tampered", "id": created["id"]},
                )
    assert approvals.get(created["id"])["payload_hash"] == created["payload_hash"]


def test_audit_rejects_raw_sql_update_and_delete(security_state):
    database, audit, _ = security_state
    audit.record(AuditEvent(event="test.started", user_id="engineer"))
    for statement in ["UPDATE audit_events SET payload = '{}'", "DELETE FROM audit_events"]:
        with pytest.raises(IntegrityError, match="append-only"):
            with database.engine.begin() as connection:
                connection.execute(text(statement))
    assert audit.verify()


def test_audit_rejects_orm_mutation_and_deletion(security_state):
    database, audit, _ = security_state
    audit.record(AuditEvent(event="test.started"))
    for delete in [False, True]:
        with pytest.raises(ValueError, match="append-only"):
            with database.sessions.begin() as unit:
                row = unit.scalar(select(AuditRow))
                if delete:
                    unit.delete(row)
                else:
                    row.payload = "{}"


def test_audit_redacts_nested_parameters_and_inline_secrets(security_state):
    database, audit, _ = security_state
    secret = "highly-sensitive-value"
    data = {
        "items": [{"client_secret": secret, "nested": {"api_key": secret}}],
        "message": f"Failed with Bearer {secret}",
        "safe": "sg-12345",
    }
    cleaned = redact(data)
    assert secret not in canonical(cleaned)
    assert cleaned["safe"] == "sg-12345"
    audit.record(AuditEvent(event="test.started", execution_result=f"password={secret}"))
    with database.sessions() as unit:
        assert secret not in unit.scalar(select(AuditRow.payload))


@pytest.mark.parametrize(
    "pem",
    [
        "-----BEGIN PRIVATE KEY-----\nSENSITIVEKEYBODY\n-----END PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----\nSENSITIVEKEYBODY\n-----END RSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----\nSENSITIVEKEYBODY",
    ],
)
def test_private_key_redaction_removes_the_entire_key_material(pem):
    assert "SENSITIVEKEYBODY" not in redact({"message": pem})["message"]


def test_audit_redacts_configured_harness_credentials_even_without_labels(
    security_state, monkeypatch
):
    database, audit, _ = security_state
    secret = "unlabelled-sensitive-reviewer-value"
    monkeypatch.setenv("HARNESS_REVIEWER_TOKEN", secret)
    audit.record(AuditEvent(event="test.started", user_id=f"prefix-{secret}-suffix"))
    with database.sessions() as unit:
        payload = unit.scalar(select(AuditRow.payload))
        assert secret not in payload
        assert "prefix-[REDACTED]-suffix" in payload


def test_audit_hash_chain_and_tamper_detection(security_state):
    database, audit, _ = security_state
    audit.record(AuditEvent(event="request.started", session_id="one"))
    audit.record(AuditEvent(event="request.completed", session_id="one"))
    rows = audit.list()
    assert rows[0]["previous_hash"] == "0" * 64
    assert rows[1]["previous_hash"] == rows[0]["event_hash"]
    assert audit.verify()
    # A database owner can bypass local triggers; verification must detect a
    # changed payload even though this is outside the application threat model.
    with database.engine.begin() as connection:
        connection.execute(text("DROP TRIGGER audit_no_update"))
        connection.execute(text("UPDATE audit_events SET payload = '{}' WHERE sequence = 1"))
    assert not audit.verify()


def test_audit_inside_transactions_commits_or_rolls_back_with_state(security_state):
    database, audit, _ = security_state
    with pytest.raises(RuntimeError):
        with database.sessions.begin() as unit:
            audit.record(AuditEvent(event="uncommitted"), unit)
            raise RuntimeError("rollback")
    assert audit.list() == []
    with database.sessions.begin() as unit:
        audit.record(AuditEvent(event="committed"), unit)
    assert [event["event"] for event in audit.list()] == ["committed"]
    assert audit.verify()


def test_concurrent_transactional_audit_events_preserve_one_hash_chain(security_state):
    database, audit, _ = security_state
    count = 8
    barrier = threading.Barrier(count)

    def append(index):
        barrier.wait(timeout=10)
        with database.sessions.begin() as unit:
            audit.record(AuditEvent(event="concurrent.event", session_id=str(index)), unit)

    with ThreadPoolExecutor(max_workers=count) as pool:
        list(pool.map(append, range(count)))
    assert len(audit.list()) == count
    assert audit.verify()
