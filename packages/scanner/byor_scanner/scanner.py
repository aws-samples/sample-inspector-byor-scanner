"""SQS-triggered scanner Lambda.

Receives a batch of SQS messages, each describing one image to scan, and
delegates to ``scan_image`` for the per-image pipeline. Per-message
failures are reported back via ``ReportBatchItemFailures`` so SQS only
retries the failed messages, not the whole batch.

Plugin loading happens once at cold start. The selected ``AuthProvider``
fetches its credentials at the top of every invocation ─ fresh secrets
are picked up automatically without redeploy.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from aws_lambda_powertools import Logger, Metrics, single_metric
from aws_lambda_powertools.metrics import MetricUnit
from opentelemetry import trace
from opentelemetry.trace import StatusCode

from byor_scanner.config import config
from byor_scanner.constants import (
    ENV_AUTH_PROVIDER,
    ENV_FINDINGS_BUCKET,
    ENV_REGISTRY_URL,
    METRIC_NAMESPACE,
    SERVICE_SCANNER,
)
from byor_scanner.errors import ScanError, classify_stage
from byor_scanner.plugin_loader import load_plugin
from byor_scanner.protocols import AuthProvider
from byor_scanner.scan import ScanRequest, ensure_policy_json, scan_image

# Tracing is handled by the AWS Distro for OpenTelemetry (ADOT) Lambda layer
# attached by the CDK stack. The layer's exec wrapper auto-creates a root
# span around this handler and auto-instruments boto3 / requests / urllib3.
# Per-stage spans are created with @tracer.start_as_current_span in scan.py
# and friends.

logger = Logger(service=SERVICE_SCANNER)
metrics = Metrics(namespace=METRIC_NAMESPACE, service=SERVICE_SCANNER)

REGISTRY = os.environ.get(ENV_REGISTRY_URL, "")
FINDINGS_BUCKET = os.environ.get(ENV_FINDINGS_BUCKET, "")

# Load auth plugin once per cold start. setup() runs every invocation.
auth: AuthProvider = load_plugin(
    ENV_AUTH_PROVIDER,
    AuthProvider,
    default=config.auth_provider,
)


def _trace_url() -> str:
    """Build a CloudWatch/X-Ray console deep link for the current trace.

    Powertools already logs ``xray_trace_id``; this turns the X-Ray root id
    (from the ``_X_AMZN_TRACE_ID`` env var) into a clickable console URL so the
    dashboard's failure widget can link straight to the trace. Returns an empty
    string when no trace context is present (e.g. tracing disabled).
    """
    header = os.environ.get("_X_AMZN_TRACE_ID", "")
    root = next(
        (p[len("Root=") :] for p in header.split(";") if p.startswith("Root=")),
        "",
    )
    if not root:
        return ""
    region = os.environ.get("AWS_REGION", "")
    return (
        f"https://{region}.console.aws.amazon.com/cloudwatch/home"
        f"?region={region}#xray:traces/{root}"
    )


def _record_failure(error_code: str, source: str) -> None:
    """Emit ImagesFailed four ways.

    1. Aggregate (no extra dims) ─ keeps the existing service-level series.
    2. Dimensioned by ``errorCode`` ─ dashboard drill-down.
    3. Dimensioned by ``stage``     ─ per-operation alarms.
    4. Dimensioned by ``source``    ─ per-trigger failure rate on dashboards.

    The dimensioned copies are emitted via ``single_metric`` so the
    dimensions don't bleed onto the other metrics emitted during this
    invocation.
    """
    metrics.add_metric(name="ImagesFailed", unit=MetricUnit.Count, value=1)
    metrics.add_metadata(key="errorCode", value=error_code)
    with single_metric(
        namespace=METRIC_NAMESPACE,
        name="ImagesFailed",
        unit=MetricUnit.Count,
        value=1,
    ) as metric:
        metric.add_dimension(name="errorCode", value=error_code)
    with single_metric(
        namespace=METRIC_NAMESPACE,
        name="ImagesFailed",
        unit=MetricUnit.Count,
        value=1,
    ) as metric:
        metric.add_dimension(name="stage", value=classify_stage(error_code))
    with single_metric(
        namespace=METRIC_NAMESPACE,
        name="ImagesFailed",
        unit=MetricUnit.Count,
        value=1,
    ) as metric:
        metric.add_dimension(name="source", value=source)


@logger.inject_lambda_context(clear_state=True)
@metrics.log_metrics
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:  # noqa: ARG001
    """SQS event source mapping handler with partial-batch failure support."""
    auth.setup()
    ensure_policy_json()

    failures: list[dict[str, str]] = []

    for record in event.get("Records", []):
        message_id = record["messageId"]
        attempt = int(record.get("attributes", {}).get("ApproximateReceiveCount", "1"))
        scan_start = time.perf_counter()

        try:
            body = json.loads(record["body"])
            image = body["image"]
            ref = body["ref"]
            source = body.get("source") or body.get("mode") or "unknown"
            logger.append_keys(image=image, ref=ref, source=source, attempt=attempt)
            logger.info("Scan starting")

            scan_image(
                ScanRequest(
                    image=image,
                    ref=ref,
                    registry=REGISTRY,
                    auth_args=auth.get_skopeo_args(),
                    bucket=FINDINGS_BUCKET,
                    source=source,
                )
            )

        except ScanError as e:
            logger.exception(
                "Scan failed",
                extra={
                    "messageId": message_id,
                    "errorCode": e.error_code,
                    "traceUrl": _trace_url(),
                },
            )
            span = trace.get_current_span()
            span.set_status(StatusCode.ERROR, e.error_code)
            span.record_exception(e)
            span.set_attribute("http.status_code", 500)
            _record_failure(e.error_code, source)
            failures.append({"itemIdentifier": message_id})
        except Exception as e:
            logger.exception(
                "Scan failed",
                extra={
                    "messageId": message_id,
                    "errorCode": "UNKNOWN",
                    "traceUrl": _trace_url(),
                },
            )
            span = trace.get_current_span()
            span.set_status(StatusCode.ERROR, "UNKNOWN")
            span.record_exception(e)
            span.set_attribute("http.status_code", 500)
            _record_failure("UNKNOWN", source)
            failures.append({"itemIdentifier": message_id})
        finally:
            metrics.add_metric(
                name="ScanDuration",
                unit=MetricUnit.Milliseconds,
                value=(time.perf_counter() - scan_start) * 1000,
            )
            logger.remove_keys(["image", "ref", "source", "attempt"])

    return {"batchItemFailures": failures}
