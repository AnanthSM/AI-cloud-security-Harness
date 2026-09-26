"""Local, reviewed tool contracts. MCP server descriptions never set authorization."""
from typing import Any

from harness.schemas import Risk, ToolDefinition
from harness.tools.registry import ToolRegistry


def obj(properties: dict[str, Any], required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": properties,
            "required": list(properties) if required is None else required,
            "additionalProperties": False}


def string(**extra: Any) -> dict:
    return {"type": "string", "minLength": 1, "maxLength": 4096, **extra}


def array(items: dict) -> dict:
    return {"type": "array", "items": items, "maxItems": 1000}


NUMBER = {"type": "integer", "minimum": 1}
BOOL = {"type": "boolean"}
ACCOUNT = string(pattern=r"^\d{12}$")
REGION = string(pattern=r"^[a-z]{2}(?:-[a-z]+)+-\d+$")
AWS = {"account_id": ACCOUNT, "region": REGION}
RULE = obj({"cidr": string(pattern=r"^[0-9a-fA-F.:]+/\d{1,3}$"),
            "from_port": {"type": "integer", "minimum": 0, "maximum": 65535},
            "to_port": {"type": "integer", "minimum": 0, "maximum": 65535},
            "protocol": {"type": "string", "enum": ["tcp", "udp", "icmp", "-1"]}})
TAGS = obj({"owner": string(), "cost_center": string()})
SG = obj({"security_group_id": string(pattern=r"^sg-[a-zA-Z0-9]+$"), **AWS,
          "name": string(), "environment": string(), "revision": NUMBER,
          "ingress": array(RULE), "tags": TAGS})
INSTANCE = obj({"instance_id": string(), **AWS, "state": string(),
                "private_ip": string(), "public_ip": {"type": ["string", "null"]},
                "security_group_ids": array(string()), "tags": TAGS})
AZURE = {"subscription_id": string(), "resource_group": string()}


def create_registry() -> ToolRegistry:
    definitions: list[ToolDefinition] = []

    def add(name: str, description: str, inputs: dict, outputs: dict,
            risk: Risk = Risk.READ, resource_fields: list[str] | None = None) -> None:
        definitions.append(ToolDefinition(
            name=name, description=description, provider=name.split(".")[0], version="1.0.0",
            risk=risk, input_schema=obj(inputs), output_schema=outputs,
            resource_fields=resource_fields or [],
        ))

    add("aws.list_accounts", "List mock AWS accounts.", {}, obj({"accounts": array(obj({
        "account_id": ACCOUNT, "name": string(), "environment": string()}))}))
    add("aws.list_instances", "List EC2 instances in an account and region.", AWS,
        obj({"instances": array(INSTANCE)}), resource_fields=["account_id", "region"])
    add("aws.get_instance", "Read one EC2 instance.", {**AWS, "instance_id": string()},
        INSTANCE, resource_fields=["account_id", "region", "instance_id"])
    add("aws.get_security_group", "Read security group ingress rules and revision.",
        {**AWS, "security_group_id": SG["properties"]["security_group_id"]}, SG,
        resource_fields=["account_id", "region", "security_group_id"])
    bucket_input = {**AWS, "bucket_name": string(pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")}
    add("aws.get_bucket", "Read bucket ownership, encryption and public-access settings.",
        bucket_input, obj({"bucket_name": string(), **AWS, "environment": string(),
                           "encryption": string(), "public_access_block": obj({
                               "block_public_acls": BOOL, "ignore_public_acls": BOOL,
                               "block_public_policy": BOOL, "restrict_public_buckets": BOOL}),
                           "tags": TAGS}), resource_fields=["account_id", "region", "bucket_name"])
    statement = obj({"effect": {"type": "string", "enum": ["Allow", "Deny"]},
                     "principal": string(), "actions": array(string()), "resources": array(string())})
    add("aws.get_bucket_policy", "Read a normalized S3 bucket policy.", bucket_input,
        obj({"bucket_name": string(), "policy_version": string(), "statements": array(statement)}),
        resource_fields=["account_id", "region", "bucket_name"])
    add("aws.get_cloudtrail_events", "Read mock CloudTrail events for a resource.",
        {**AWS, "resource_id": string()}, obj({"events": array(obj({
            "event_id": string(), "event_time": string(), "event_name": string(),
            "principal": string(), "resource_id": string(), "source_ip": string()}))}),
        resource_fields=["account_id", "region", "resource_id"])
    add("aws.modify_security_group", "Remove an exact ingress rule at an expected revision.",
        {**AWS, "security_group_id": SG["properties"]["security_group_id"],
         "remove_rule": RULE, "expected_revision": NUMBER}, obj({
            "security_group_id": string(), "revision": NUMBER, "changed": BOOL,
            "ingress": array(RULE)}), risk=Risk.HIGH_RISK_WRITE,
        resource_fields=["account_id", "region", "security_group_id"])
    add("aws.delete_bucket", "Delete a mock S3 bucket; destructive and denied by default.",
        bucket_input, obj({"bucket_name": string(), "deleted": BOOL}), risk=Risk.DESTRUCTIVE,
        resource_fields=["account_id", "region", "bucket_name"])
    add("azure.list_subscriptions", "List mock Azure subscriptions.", {},
        obj({"subscriptions": array(obj({"subscription_id": string(), "name": string(),
                                        "environment": string()}))}))
    add("azure.get_vm", "Read an Azure virtual machine.", {**AZURE, "vm_name": string()}, obj({
        **AZURE, "vm_name": string(), "location": string(), "power_state": string(),
        "private_ip": string(), "tags": TAGS}),
        resource_fields=["subscription_id", "resource_group", "vm_name"])
    add("azure.get_storage_account", "Read Azure storage security settings.",
        {**AZURE, "account_name": string()}, obj({**AZURE, "account_name": string(),
            "location": string(), "allow_blob_public_access": BOOL,
            "https_only": BOOL, "minimum_tls_version": string(),
            "network_default_action": string(), "tags": TAGS}),
        resource_fields=["subscription_id", "resource_group", "account_name"])
    add("azure.get_network_security_group", "Read Azure NSG security rules.",
        {**AZURE, "nsg_name": string()}, obj({**AZURE, "nsg_name": string(),
            "rules": array(obj({"name": string(), "priority": NUMBER,
                "direction": string(), "access": string(), "protocol": string(),
                "source_address_prefix": string(), "destination_port_range": string()}))}),
        resource_fields=["subscription_id", "resource_group", "nsg_name"])
    project = {"project_id": NUMBER}
    add("gitlab.get_project", "Read a GitLab project.", project, obj({"project_id": NUMBER,
        "path_with_namespace": string(), "visibility": string(), "default_branch": string(),
        "web_url": string(), "archived": BOOL}), resource_fields=["project_id"])
    add("gitlab.get_pipeline", "Read a GitLab pipeline and its jobs.",
        {**project, "pipeline_id": NUMBER}, obj({"project_id": NUMBER, "pipeline_id": NUMBER,
            "status": string(), "ref": string(), "sha": string(), "jobs": array(obj({
                "name": string(), "stage": string(), "status": string()}))}),
        resource_fields=["project_id", "pipeline_id"])
    add("gitlab.get_merge_request", "Read a GitLab merge request.",
        {**project, "merge_request_iid": NUMBER}, obj({"project_id": NUMBER,
            "merge_request_iid": NUMBER, "title": string(), "state": string(),
            "source_branch": string(), "target_branch": string(), "author": string()}),
        resource_fields=["project_id", "merge_request_iid"])
    add("gitlab.create_issue", "Create a GitLab tracking issue.",
        {**project, "title": string(maxLength=255), "description": string(maxLength=10000)},
        obj({"project_id": NUMBER, "issue_iid": NUMBER, "title": string(), "web_url": string()}),
        risk=Risk.LOW_RISK_WRITE, resource_fields=["project_id"])
    return ToolRegistry(definitions)
