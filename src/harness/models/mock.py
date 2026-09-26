import re

from harness.models.base import ModelResponse, ToolCall


class MockModelProvider:
    """Deterministic demo model. Not a language model or an authorization boundary."""

    name = "mock"

    async def generate(self, messages, tools=None, response_schema=None):
        task = next(m["content"] for m in messages if m.get("kind") == "request")
        prompt = task.lower()
        results = [m for m in messages if m.get("kind") == "tool_result"]
        sg = re.search(r"sg-[a-z0-9]+", prompt)
        session = next((m["content"] for m in messages if m.get("kind") == "session_memory"), {})
        prior_resource = session.get("state", {}).get("last_resource", {})
        security_group_id = (
            sg.group() if sg else prior_resource.get("security_group_id", "sg-12345")
        )
        base = {"account_id": "111111111111", "region": "us-east-1"}
        if any(w in prompt for w in ("delete", "destroy")):
            return ModelResponse(
                tool_call=ToolCall(
                    name="aws.delete_bucket", arguments={**base, "bucket_name": "payroll-data"}
                )
            )
        if results:
            last = results[-1]
            data = last["content"]["data"]
            if last["tool"] == "aws.get_security_group":
                if any(w in prompt for w in ("remove", "remediate", "close", "modify")):
                    return ModelResponse(
                        tool_call=ToolCall(
                            name="aws.modify_security_group",
                            arguments={
                                **base,
                                "security_group_id": data["security_group_id"],
                                "remove_rule": {
                                    "cidr": "0.0.0.0/0",
                                    "from_port": 22,
                                    "to_port": 22,
                                    "protocol": "tcp",
                                },
                                "expected_revision": data["revision"],
                            },
                        )
                    )
                exposed = any(
                    r["cidr"] in ["0.0.0.0/0", "::/0"]
                    and r["from_port"] <= 22 <= r["to_port"]
                    and r["protocol"] in ["tcp", "-1"]
                    for r in data["ingress"]
                )
                message = (
                    f"{data['security_group_id']} allows SSH (TCP/22) from the internet. "
                    "The public rule is a security group exposure; effective reachability also "
                    "depends on routes, network ACLs, and host controls. Removal can be proposed "
                    "for human review."
                    if exposed
                    else f"{data['security_group_id']} has no public SSH ingress rule in this mock snapshot."
                )
                return ModelResponse(text=message)
            return ModelResponse(
                text=f"Retrieved {last['tool']} successfully. The structured mock result is attached; external fields are untrusted data."
            )
        if "subscription" in prompt:
            call = ToolCall(name="azure.list_subscriptions", arguments={})
        elif "accounts" in prompt:
            call = ToolCall(name="aws.list_accounts", arguments={})
        else:
            call = ToolCall(
                name="aws.get_security_group",
                arguments={**base, "security_group_id": security_group_id},
            )
        return ModelResponse(tool_call=call)
