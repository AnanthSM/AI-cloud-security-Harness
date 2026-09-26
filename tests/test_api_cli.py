import asyncio
import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from harness.api.app import create_app
from harness.api.mcp import create_server
from harness.cli import app
from harness.config import Settings
from harness.runtime.container import Container
from harness.tools.gateway import InProcessMockGateway

ROOT = Path(__file__).resolve().parents[1]
OPERATOR_TOKEN = "operator-" + "a" * 40
REVIEWER_TOKEN = "reviewer-" + "b" * 40


@pytest.fixture
def setup(tmp_path, monkeypatch):
    for folder in ["config", "agents", "skills", "policies", "knowledge"]:
        shutil.copytree(ROOT / folder, tmp_path / folder)
    monkeypatch.setenv("HARNESS_ROOT", str(tmp_path))
    monkeypatch.setenv("HARNESS_TRACE_CONSOLE", "false")
    monkeypatch.setenv("HARNESS_OPERATOR_TOKEN", OPERATOR_TOKEN)
    monkeypatch.setenv("HARNESS_REVIEWER_TOKEN", REVIEWER_TOKEN)
    c = Container(Settings.load(tmp_path), gateway=InProcessMockGateway())
    with TestClient(create_app(container=c)) as client:
        yield c, client, tmp_path
    c.close()


def headers(reviewer=False):
    return {"Authorization": "Bearer " + (REVIEWER_TOKEN if reviewer else OPERATOR_TOKEN)}


def test_api_read_approval_exact_execution_and_replay(setup):
    c, client, _ = setup
    read = client.post(
        "/v1/agent/run",
        headers=headers(),
        json={"prompt": "Check whether sg-12345 allows SSH from the internet."},
    )
    assert read.status_code == 200
    assert read.json()["policy_decision"] == "ALLOW"
    request = client.post(
        "/v1/agent/run",
        headers=headers(),
        json={
            "prompt": "Remove the public SSH rule from sg-12345.",
            "session_id": read.json()["session_id"],
        },
    ).json()
    assert request["status"] == "approval_required"
    assert all(name != "aws.modify_security_group" for name, _ in c.gateway.calls)
    approval = request["data"]["approval"]
    url = f"/v1/approvals/{approval['id']}/approve"
    payload = {"expected_hash": approval["payload_hash"]}
    assert client.post(url, headers=headers(), json=payload).status_code == 403
    assert (
        client.post(url, headers=headers(True), json={**payload, "arguments": {}}).status_code
        == 422
    )
    accepted = client.post(url, headers=headers(True), json=payload)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["execution_status"] == "SUCCEEDED"
    writes = [args for name, args in c.gateway.calls if name == "aws.modify_security_group"]
    assert writes == [approval["payload"]["arguments"]]
    assert client.post(url, headers=headers(True), json=payload).status_code == 409
    assert len([n for n, _ in c.gateway.calls if n == "aws.modify_security_group"]) == 1
    assert c.audit.verify()


def test_api_learn_review_and_candidate_exclusion(setup):
    c, client, _ = setup
    read = client.post(
        "/v1/agent/run", headers=headers(), json={"prompt": "Inspect sg-12345"}
    ).json()
    candidate = client.post(
        "/v1/learn",
        headers=headers(),
        json={
            "session_id": read["session_id"],
            "statement": "Quasar network investigation requires reviewing ingress.",
        },
    ).json()
    assert candidate["status"] == "candidate"
    assert candidate["id"] not in [d["id"] for d in c.knowledge.retrieve("Quasar")]
    url = f"/v1/knowledge/candidates/{candidate['id']}/approve"
    body = {"expected_hash": candidate["payload_hash"], "expected_version": candidate["version"]}
    assert client.post(url, headers=headers(), json=body).status_code == 403
    approved = client.post(url, headers=headers(True), json=body)
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    assert c.knowledge.retrieve("Quasar")


def test_api_identity_is_not_model_controlled_and_validation_redacts(setup):
    c, client, _ = setup
    assert client.get("/health").status_code == 200
    assert client.get("/v1/agents").status_code == 403
    forged = client.post(
        "/v1/agent/run",
        headers=headers(),
        json={
            "prompt": "Inspect",
            "user_id": "api-reviewer",
            "role": "reviewer",
            "secret": REVIEWER_TOKEN,
        },
    )
    assert forged.status_code == 422
    assert REVIEWER_TOKEN not in forged.text
    assert client.get("/v1/audit", headers=headers()).status_code == 403
    assert client.get("/v1/audit", headers=headers(True)).status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_cli_full_workflow_survives_process_boundaries(setup):
    _, _, root = setup
    cli = CliRunner()
    result = cli.invoke(app, ["run", "cloud-security-agent", "Remove public SSH from sg-12345"])
    assert result.exit_code == 0, result.output
    proposed = json.loads(result.stdout)
    approval = proposed["data"]["approval"]
    result = cli.invoke(
        app, ["approvals", "approve", approval["id"], "--expected-hash", approval["payload_hash"]]
    )
    assert result.exit_code == 0, result.output
    assert "SUCCEEDED" in result.stdout
    result = cli.invoke(app, ["run", "cloud-security-agent", "Check SSH from sg-12345"])
    assert result.exit_code == 0
    assert "no public SSH" in result.stdout
    result = cli.invoke(app, ["learn"])
    assert result.exit_code == 0, result.output
    candidate = json.loads(result.stdout)
    assert candidate["status"] == "candidate"
    result = cli.invoke(
        app,
        [
            "knowledge",
            "approve",
            candidate["id"],
            "--expected-hash",
            candidate["payload_hash"],
            "--expected-version",
            str(candidate["version"]),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "approved" in result.stdout
    result = cli.invoke(app, ["audit", "--verify"])
    assert result.exit_code == 0 and json.loads(result.stdout)["valid"]


def test_model_facing_mcp_has_no_review_or_execution_bypass(setup):
    server = create_server()
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    assert names == {"list_agents", "list_tools", "run_agent", "propose_action", "learn"}
    assert not any("approve" in n or "execute" in n or "promote" in n for n in names)
