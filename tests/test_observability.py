import asyncio
import json
import logging

import pytest
from opentelemetry import trace
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from harness.errors import Invalid
from harness.observability.telemetry import COUNTERS, HISTOGRAMS, Telemetry


def instrumented(**kwargs):
    exporter = InMemorySpanExporter()
    reader = InMemoryMetricReader()
    return Telemetry(span_exporter=exporter, metric_reader=reader, **kwargs), exporter, reader


def collected_metrics(reader):
    data = reader.get_metrics_data()
    return {
        metric.name: metric
        for resource in data.resource_metrics
        for scope in resource.scope_metrics
        for metric in scope.metrics
    }


def test_spans_preserve_hierarchy_and_trace_id_without_global_provider():
    global_provider = trace.get_tracer_provider()
    telemetry, exporter, _ = instrumented()
    try:
        assert telemetry.trace_id() == ""
        with telemetry.span("agent.request", agent="cloud-security-agent"):
            request_trace_id = telemetry.trace_id()
            with telemetry.span("context.construction"):
                with telemetry.span("knowledge.retrieval"):
                    assert telemetry.trace_id() == request_trace_id
            with telemetry.span("tool.execution", tool="aws.get_security_group"):
                pass
        spans = {span.name: span for span in exporter.get_finished_spans()}
        request = spans["agent.request"]
        assert len(request_trace_id) == 32
        assert request_trace_id == f"{request.context.trace_id:032x}"
        assert spans["context.construction"].parent.span_id == request.context.span_id
        assert spans["tool.execution"].parent.span_id == request.context.span_id
        assert (
            spans["knowledge.retrieval"].parent.span_id
            == spans["context.construction"].context.span_id
        )
        assert request.status.status_code == StatusCode.OK
        assert telemetry.trace_id() == ""
        assert trace.get_tracer_provider() is global_provider
    finally:
        telemetry.shutdown()


def test_all_required_metrics_are_initialized_and_measured():
    telemetry, _, reader = instrumented()
    try:
        assert set(telemetry.counters) == set(COUNTERS)
        assert set(telemetry.histograms) == set(HISTOGRAMS)
        for name in COUNTERS:
            telemetry.count(name, 2, tool="aws.get_security_group", arguments="NEVER-EXPORT")
            telemetry.count(name, 3, tool="aws.get_security_group")
        for name in HISTOGRAMS:
            telemetry.observe(name, 12.5, model="mock")
            telemetry.observe(name, 25, model="mock")
        metrics = collected_metrics(reader)
        assert set(metrics) == set(COUNTERS) | set(HISTOGRAMS)
        for name in COUNTERS:
            point = metrics[name].data.data_points[0]
            assert point.value == 5
            assert dict(point.attributes) == {"tool": "aws.get_security_group"}
        for name in HISTOGRAMS:
            point = metrics[name].data.data_points[0]
            assert point.count == 2
            assert point.sum == 37.5
            assert metrics[name].unit == "ms"
        assert "NEVER-EXPORT" not in str(metrics)
    finally:
        telemetry.shutdown()


def test_no_raw_data_secrets_or_exception_details_in_spans_logs_or_metrics(caplog, monkeypatch):
    secret = "sk-DO-NOT-EXPORT-THIS-CREDENTIAL"
    monkeypatch.setenv("OTEL_RESOURCE_ATTRIBUTES", f"private.token={secret}")
    telemetry, exporter, reader = instrumented()
    caplog.set_level(logging.INFO, logger="harness.observability")
    try:
        with pytest.raises(RuntimeError):
            with telemetry.span(
                "tool.execution",
                tool="aws.get_security_group",
                prompt=secret,
                arguments={"password": secret},
                result=secret,
                model=secret,
            ):
                telemetry.count("tool_requests_total", user=secret, prompt=secret, model=secret)
                raise RuntimeError(f"Provider connection failed: {secret}")
        span = exporter.get_finished_spans()[0]
        assert span.status.status_code == StatusCode.ERROR
        assert span.status.description == "operation_failed"
        assert not span.events
        assert dict(span.attributes) == {
            "tool": "aws.get_security_group",
            "model": "other",
            "error.code": "operation_failed",
        }
        assert secret not in span.to_json()
        assert secret not in str(collected_metrics(reader))
        assert secret not in caplog.text
        records = [
            json.loads(record.message)
            for record in caplog.records
            if record.name == "harness.observability"
        ]
        assert records[0]["event"] == "operation.completed"
        assert records[0]["status"] == "error"
        assert records[0]["trace_id"]
    finally:
        telemetry.shutdown()


def test_dynamic_span_names_and_unknown_labels_cannot_export_user_content():
    telemetry, exporter, reader = instrumented()
    try:
        for i in range(100):
            with telemetry.span(f"user secret {i}", tool=f"dynamic-{i}"):
                telemetry.count("tool_requests_total", tool=f"dynamic-{i}")
        assert {span.name for span in exporter.get_finished_spans()} == {"harness.operation"}
        points = collected_metrics(reader)["tool_requests_total"].data.data_points
        assert len(points) == 1
        assert points[0].value == 100
        assert dict(points[0].attributes) == {"tool": "other"}
    finally:
        telemetry.shutdown()


def test_console_traces_go_to_stderr_only(capsys):
    telemetry = Telemetry(console=True)
    with telemetry.span("model.request", model="mock", prompt="SECRET-PROMPT"):
        pass
    telemetry.shutdown()
    output = capsys.readouterr()
    assert output.out == ""
    exported = json.loads(output.err)
    assert exported["name"] == "model.request"
    assert exported["attributes"] == {"model": "mock"}
    assert "SECRET-PROMPT" not in output.err


def test_independent_containers_do_not_share_spans_or_metrics():
    first, first_exporter, first_reader = instrumented()
    second, second_exporter, second_reader = instrumented()
    try:
        with first.span("agent.request"):
            first.count("agent_requests_total", 1)
        with second.span("tool.execution"):
            second.count("agent_requests_total", 5)
        assert [span.name for span in first_exporter.get_finished_spans()] == ["agent.request"]
        assert [span.name for span in second_exporter.get_finished_spans()] == ["tool.execution"]
        assert (
            collected_metrics(first_reader)["agent_requests_total"].data.data_points[0].value == 1
        )
        assert (
            collected_metrics(second_reader)["agent_requests_total"].data.data_points[0].value == 5
        )
    finally:
        first.shutdown()
        first.shutdown()
        second.shutdown()


async def test_cancelled_span_has_safe_status_and_propagates_cancellation():
    telemetry, exporter, _ = instrumented()
    try:
        with pytest.raises(asyncio.CancelledError):
            with telemetry.span("tool.execution"):
                raise asyncio.CancelledError("SECRET-CANCELLATION-REASON")
        span = exporter.get_finished_spans()[0]
        assert span.status.description == "cancelled"
        assert not span.events
        assert "SECRET-CANCELLATION-REASON" not in span.to_json()
    finally:
        telemetry.shutdown()


def test_extensions_accept_only_explicit_bounded_operator_labels():
    telemetry, exporter, _ = instrumented(allowed_attribute_values={"tool": {"wiz.get_finding"}})
    try:
        with telemetry.span("tool.execution", tool="wiz.get_finding"):
            pass
        assert exporter.get_finished_spans()[0].attributes["tool"] == "wiz.get_finding"
    finally:
        telemetry.shutdown()
    with pytest.raises(Invalid):
        Telemetry(allowed_attribute_values={"prompt": {"data"}})
    with pytest.raises(Invalid):
        Telemetry(allowed_attribute_values={"tool": {str(i) for i in range(100)}})


@pytest.mark.parametrize(
    "kind,name,value",
    [
        ("count", "arbitrary_name", 1),
        ("count", "agent_requests_total", -1),
        ("count", "agent_requests_total", True),
        ("observe", "tool_latency", float("nan")),
        ("observe", "model_latency", -1),
    ],
)
def test_invalid_metric_names_or_values_fail_safely(kind, name, value):
    telemetry = Telemetry()
    try:
        with pytest.raises(Invalid):
            getattr(telemetry, kind)(name, value)
    finally:
        telemetry.shutdown()
