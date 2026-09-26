"""Privacy-preserving OpenTelemetry adapter owned by each application container.

No global provider is installed. Exporters can be injected without coupling the
runtime to OTLP, Splunk, Jaeger, or a particular monitoring deployment.
"""

import asyncio
import json
import logging
import math
import re
import sys
import time
from collections.abc import Collection, Mapping
from contextlib import contextmanager

from opentelemetry import trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import MetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import SpanLimits, TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor, SpanExporter
from opentelemetry.sdk.trace.sampling import ALWAYS_ON
from opentelemetry.trace import Status, StatusCode

from harness.errors import Invalid

logger = logging.getLogger("harness.observability")

SPAN_NAMES = frozenset(
    {
        "agent.request",
        "context.construction",
        "knowledge.retrieval",
        "skill.selection",
        "policy.evaluation",
        "approval.request",
        "approval.review",
        "approval.rejection",
        "tool.execution",
        "model.request",
        "model.response",
        "learning.extraction",
        "knowledge.promotion",
        "harness.operation",
    }
)

# Only reviewed labels are exported. Unknown dynamic values collapse to "other"
# rather than creating unbounded series or accidentally exporting user content.
# Operators can extend these sets with trusted catalog values at composition time.
DEFAULT_ATTRIBUTE_VALUES = {
    "tool": frozenset(
        {
            "aws.list_accounts",
            "aws.list_instances",
            "aws.get_instance",
            "aws.get_security_group",
            "aws.get_bucket",
            "aws.get_bucket_policy",
            "aws.get_cloudtrail_events",
            "aws.modify_security_group",
            "aws.delete_bucket",
            "azure.list_subscriptions",
            "azure.get_vm",
            "azure.get_storage_account",
            "azure.get_network_security_group",
            "gitlab.get_project",
            "gitlab.get_pipeline",
            "gitlab.get_merge_request",
            "gitlab.create_issue",
        }
    ),
    "agent": frozenset({"cloud-security-agent"}),
    "model": frozenset({"mock"}),
    "provider": frozenset({"aws", "azure", "gitlab", "mock"}),
    "environment": frozenset({"production", "staging", "development", "test", "unknown"}),
    "risk": frozenset({"READ", "LOW_RISK_WRITE", "HIGH_RISK_WRITE", "DESTRUCTIVE"}),
    "decision": frozenset({"ALLOW", "DENY", "APPROVAL_REQUIRED"}),
    "status": frozenset({"success", "error", "pending", "approved", "rejected", "expired"}),
}

COUNTERS = {
    "agent_requests_total": ("Agent requests received", "{request}"),
    "tool_requests_total": ("Authorized tool executions attempted", "{request}"),
    "tool_failures_total": ("Tool executions that failed", "{failure}"),
    "policy_denials_total": ("Tool proposals denied by policy", "{denial}"),
    "approval_requests_total": ("Human approval requests created", "{request}"),
    "approval_rejections_total": ("Human approval requests rejected", "{rejection}"),
    "model_tokens_total": ("Model input and output tokens", "{token}"),
}
HISTOGRAMS = {
    "model_latency": ("Model request latency", "ms"),
    "tool_latency": ("Tool execution latency", "ms"),
}


class Telemetry:
    def __init__(
        self,
        console: bool = False,
        *,
        span_exporter: SpanExporter | None = None,
        metric_reader: MetricReader | None = None,
        allowed_attribute_values: Mapping[str, Collection[str]] | None = None,
    ):
        self.console = console
        self._closed = False
        self._allowed_attributes = dict(DEFAULT_ATTRIBUTE_VALUES)
        for key, values in (allowed_attribute_values or {}).items():
            if key not in self._allowed_attributes or isinstance(values, str) or len(values) > 64:
                raise Invalid("Telemetry labels must be bounded, trusted catalog values")
            if any(
                not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", value)
                for value in values
            ):
                raise Invalid("Telemetry labels must be bounded, trusted catalog values")
            self._allowed_attributes[key] = self._allowed_attributes[key] | frozenset(values)

        # Resource.create() would merge arbitrary OTEL_RESOURCE_ATTRIBUTES from
        # the environment. An explicit resource avoids exporting that content.
        resource = Resource({"service.name": "cloud-security-harness", "service.version": "0.1.0"})
        self.meter_provider = MeterProvider(
            metric_readers=[metric_reader] if metric_reader is not None else [],
            resource=resource,
            shutdown_on_exit=False,
        )
        self.tracer_provider = TracerProvider(
            resource=resource,
            sampler=ALWAYS_ON,
            shutdown_on_exit=False,
            span_limits=SpanLimits(max_attributes=16, max_attribute_length=80),
        )
        if span_exporter is not None:
            self.tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))
        if console:
            self.tracer_provider.add_span_processor(
                SimpleSpanProcessor(ConsoleSpanExporter(out=sys.stderr))
            )
        self.tracer = self.tracer_provider.get_tracer("harness", "0.1.0")
        meter = self.meter_provider.get_meter("harness", "0.1.0")
        self.counters = {
            name: meter.create_counter(name, description=description, unit=unit)
            for name, (description, unit) in COUNTERS.items()
        }
        self.histograms = {
            name: meter.create_histogram(name, description=description, unit=unit)
            for name, (description, unit) in HISTOGRAMS.items()
        }

    def _attributes(self, attributes: dict) -> dict[str, str]:
        return {
            key: value if isinstance(value, str) and value in allowed else "other"
            for key, value in attributes.items()
            if (allowed := self._allowed_attributes.get(key)) is not None
        }

    @contextmanager
    def span(self, name: str, **attributes):
        safe_name = name if name in SPAN_NAMES else "harness.operation"
        started = time.monotonic()
        outcome = "success"
        with self.tracer.start_as_current_span(
            safe_name,
            attributes=self._attributes(attributes),
            record_exception=False,
            set_status_on_exception=False,
        ) as active:
            try:
                # Do not expose the raw SDK span through this safe facade.
                yield None
            except BaseException as exc:
                outcome = "error"
                code = (
                    "cancelled" if isinstance(exc, asyncio.CancelledError) else "operation_failed"
                )
                active.set_attribute("error.code", code)
                active.set_status(Status(StatusCode.ERROR, code))
                raise
            else:
                active.set_status(Status(StatusCode.OK))
            finally:
                logger.info(
                    json.dumps(
                        {
                            "event": "operation.completed",
                            "operation": safe_name,
                            "status": outcome,
                            "trace_id": self.trace_id(),
                            "duration_ms": round((time.monotonic() - started) * 1000, 3),
                        },
                        separators=(",", ":"),
                    )
                )

    def count(self, name: str, value: int = 1, **attributes):
        if name not in self.counters or type(value) is not int or value < 0:
            raise Invalid("Unknown counter or invalid measurement")
        self.counters[name].add(value, self._attributes(attributes))

    def observe(self, name: str, value: float, **attributes):
        if (
            name not in self.histograms
            or type(value) not in (int, float)
            or not math.isfinite(value)
            or value < 0
        ):
            raise Invalid("Unknown histogram or invalid measurement")
        self.histograms[name].record(value, self._attributes(attributes))

    def trace_id(self) -> str:
        current = trace.get_current_span().get_span_context()
        return f"{current.trace_id:032x}" if current.is_valid else ""

    def shutdown(self):
        if not self._closed:
            self._closed = True
            self.tracer_provider.shutdown()
            self.meter_provider.shutdown()
