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
    ENV_FINDINGS_BUCKET,
    METRIC_NAMESPACE,
    SERVICE_SCANNER,
)
from byor_scanner.errors import UNKNOWN_REGISTRY, ScanError, classify_stage
from byor_scanner.plugin_loader import load_plugin_from_path
from byor_scanner.protocols import AuthProvider
from byor_scanner.scan import ScanRequest, ensure_policy_json, scan_image

# Tracing is handled by the AWS Distro for OpenTelemetry (ADOT) Lambda layer
# attached by the CDK stack. The layer's exec wrapper auto-creates a root
# span around this handler and auto-instruments boto3 / requests / urllib3.
# Per-stage spans are created with @tracer.start_as_current_span in scan.py
# and friends.

logger = Logger(service=SERVICE_SCANNER)
metrics = Metrics(namespace=METRIC_NAMESPACE, service=SERVICE_SCANNER)

FINDINGS_BUCKET = os.environ.get(ENV_FINDINGS_BUCKET, "")

# Load one AuthProvider per configured registry once per cold start, keyed by
# registry id. Each registry's provider is resolved from its own dotted
# `auth_provider` path (BYOR_REGISTRIES), so different registries can use
# different auth mechanisms. setup() is deferred to invocation time and run
# lazily per referenced registry (see handler).
auth_by_registry: dict[str, AuthProvider] = {
    registry_id: load_plugin_from_path(entry.auth_provider, AuthProvider)
    for registry_id, entry in config.registries.items()
}


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


def _setup_registry(registry_id: str, done: set[str]) -> None:
    """Run a registry's ``auth.setup()`` once per invocation (lazy).

    Providers read their own env (e.g. MtlsAuth reads ``BYOR_MTLS_SECRET_NAME``),
    so we apply this registry's ``auth_env`` around ``setup()`` and restore it
    afterward ─ one registry's env can't leak into another's provider.
    """
    if registry_id in done:
        return
    entry = config.registries[registry_id]
    # Snapshot prior values so we can restore them after setup().
    saved: dict[str, str | None] = {
        key: os.environ.get(key) for key in entry.auth_env
    }
    try:
        for key, value in entry.auth_env.items():
            os.environ[key] = value
        auth_by_registry[registry_id].setup()
    finally:
        for key, prior in saved.items():
            if prior is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = prior
    done.add(registry_id)


def _apply_tls_policy(auth_args: list[str], insecure: bool) -> list[str]:
    """Force ``--tls-verify=false`` when a registry opts into insecure TLS.

    Only ever disables verification (never re-enables it); returns a new list.
    """
    if not insecure:
        return auth_args
    out = [a for a in auth_args if not a.startswith("--tls-verify=")]
    out.append("--tls-verify=false")
    return out


def _resolve_registry_id(requested: str | None) -> str:
    """Resolve a message's registry id, honoring the implicit default.

    A named registry is returned as-is (the caller validates it). For an
    untagged message: a registry named ``"default"`` wins; else the sole
    configured registry; else ``UNKNOWN_REGISTRY`` (ambiguous).
    """
    if requested:
        return requested
    if "default" in config.registries:
        return "default"
    if len(config.registries) == 1:
        return next(iter(config.registries))
    raise ScanError(
        UNKNOWN_REGISTRY,
        "Message did not specify a registry and no 'default' registry is "
        f"configured among {sorted(config.registries)}. Either tag the "
        "message with a registry id, name a registry 'default', or configure "
        "exactly one registry.",
    )


@logger.inject_lambda_context(clear_state=True)
@metrics.log_metrics
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:  # noqa: ARG001
    """SQS event source mapping handler with partial-batch failure support."""
    ensure_policy_json()

    # Registries set up so far this invocation (lazy per-registry setup):
    # a registry's auth.setup() runs only the first time a message in this
    # batch references it.
    setup_done: set[str] = set()
    failures: list[dict[str, str]] = []

    for record in event.get("Records", []):
        message_id = record["messageId"]
        attempt = int(record.get("attributes", {}).get("ApproximateReceiveCount", "1"))
        scan_start = time.perf_counter()
        source = "unknown"
        registry_id = "unknown"

        try:
            body = json.loads(record["body"])
            image = body["image"]
            ref = body["ref"]
            source = body.get("source") or body.get("mode") or "unknown"
            registry_id = _resolve_registry_id(body.get("registry"))
            logger.append_keys(
                image=image,
                ref=ref,
                source=source,
                registry=registry_id,
                attempt=attempt,
            )
            logger.info("Scan starting")

            entry = config.registries.get(registry_id)
            if entry is None:
                raise ScanError(
                    UNKNOWN_REGISTRY,
                    f"Message references unknown registry {registry_id!r}; "
                    f"known: {sorted(config.registries)}",
                )

            _setup_registry(registry_id, setup_done)
            auth = auth_by_registry[registry_id]

            scan_image(
                ScanRequest(
                    image=image,
                    ref=ref,
                    registry=entry.url,
                    auth_args=_apply_tls_policy(
                        auth.get_skopeo_args(), entry.insecure_tls_verify
                    ),
                    bucket=FINDINGS_BUCKET,
                    source=source,
                    registry_id=registry_id,
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
            logger.remove_keys(["image", "ref", "source", "registry", "attempt"])

    return {"batchItemFailures": failures}
