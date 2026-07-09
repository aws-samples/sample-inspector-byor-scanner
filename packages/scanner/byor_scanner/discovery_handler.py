"""Discovery Lambda: find images and fan out to SQS for scanning.

Triggered by whatever trigger the deploy wired up (today: an S3 manifest
bucket, EventBridge schedules, or direct invocation). The trigger sets
``BYOR_TRIGGER_SOURCE`` on this Lambda's env so every event this handler
receives is tagged with a logical source name even when the
event itself doesn't carry one.

## Event envelope

Every plugin's :meth:`discover` is called with the same shape::

    {
      "source":  "Hourly" | "Manifest" | <whatever>,
      "payload": <opaque dict — the trigger's input, plugin owns parsing>
    }

For triggers that fire many distinct events (e.g. ``ScheduledTrigger``'s
N schedules), each event arrives with its own ``source`` and ``payload``
inside the envelope. For single-fire triggers (S3 manifest, manual), the
incoming event is wrapped here with ``source`` defaulting to
``BYOR_TRIGGER_SOURCE`` and ``payload`` being the raw event itself.

## SQS message

Every batch enqueued to SQS carries::

    {"image": "...", "ref": "...", "source": "<source>",
     "requestedAt": "<ISO>", "registry": "<id>"}

The scanner Lambda consumes these messages from the SQS event source
mapping. ``ref`` is whatever the discovery backend returned ─ a tag or a
digest; the scanner pipeline resolves either form. ``registry`` is the
configured registry id the scanner resolves the URL + auth from; it is
included ONLY when the backend supplies one. When omitted, the scanner
resolves the default registry (one named ``"default"``, or the sole
configured registry). ``source`` is forwarded for log + metric context.
"""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from typing import Any

import boto3
from aws_lambda_powertools import Logger, Metrics, single_metric
from aws_lambda_powertools.metrics import MetricUnit
from opentelemetry import trace
from opentelemetry.trace import StatusCode

from byor_scanner.config import config
from byor_scanner.constants import (
    DEFAULT_MAX_DISCOVERED,
    DEFAULT_TRIGGER_SOURCE,
    ENV_DISCOVERY_BACKEND,
    ENV_MAX_DISCOVERED,
    ENV_QUEUE_URL,
    ENV_TRIGGER_SOURCE,
    METRIC_NAMESPACE,
    SERVICE_DISCOVERY,
    SQS_BATCH_SIZE,
)
from byor_scanner.errors import (
    CONFIG_ERROR,
    DISCOVERY_FAILED,
    ENQUEUE_FAILED,
    INVALID_INPUT,
    ScanError,
)
from byor_scanner.plugin_loader import load_plugin
from byor_scanner.protocols import DiscoveryBackend
from byor_scanner.validation import validate_source_type

logger = Logger(service=SERVICE_DISCOVERY)
metrics = Metrics(namespace=METRIC_NAMESPACE, service=SERVICE_DISCOVERY)
tracer = trace.get_tracer(__name__)

# Tracing is handled by the ADOT Lambda layer attached by the CDK stack.
# The layer's exec wrapper auto-creates a root span around the handler and
# auto-instruments boto3 / requests / urllib3. Per-stage spans are created
# with @tracer.start_as_current_span below.

QUEUE_URL = os.environ.get(ENV_QUEUE_URL, "")
MAX_DISCOVERED = int(os.environ.get(ENV_MAX_DISCOVERED, DEFAULT_MAX_DISCOVERED))

sqs_client = boto3.client("sqs")

MAX_RETRIES = config.retry.max_attempts
BASE_BACKOFF = config.retry.base_backoff_seconds

# Load discovery plugin once per cold start.
discovery: DiscoveryBackend = load_plugin(
    ENV_DISCOVERY_BACKEND,
    DiscoveryBackend,
    default=config.discovery_backend,
)


@logger.inject_lambda_context(clear_state=True)
@metrics.log_metrics
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:  # noqa: ARG001
    """Trigger-agnostic entry point. See module docstring for the envelope."""
    if not QUEUE_URL:
        raise ScanError(CONFIG_ERROR, f"{ENV_QUEUE_URL} is not configured")

    envelope = _envelope_for(event)
    source = envelope["source"]
    logger.append_keys(source=source)
    logger.info("Discovery starting")

    try:
        images = _query_with_retry(envelope)
        _validate_images(images)
        enqueued = _enqueue(images, source)
    except ScanError as e:
        logger.exception("Discovery failed", extra={"errorCode": e.error_code})
        span = trace.get_current_span()
        span.set_status(StatusCode.ERROR, e.error_code)
        span.record_exception(e)
        span.set_attribute("http.status_code", 500)
        metrics.add_metric(name="DiscoveryFailed", unit=MetricUnit.Count, value=1)
        metrics.add_metadata(key="errorCode", value=e.error_code)
        raise
    except Exception as e:
        logger.exception("Discovery failed", extra={"errorCode": "UNKNOWN"})
        span = trace.get_current_span()
        span.set_status(StatusCode.ERROR, "UNKNOWN")
        span.record_exception(e)
        span.set_attribute("http.status_code", 500)
        metrics.add_metric(name="DiscoveryFailed", unit=MetricUnit.Count, value=1)
        metrics.add_metadata(key="errorCode", value="UNKNOWN")
        raise

    metrics.add_metric(name="ImagesEnqueued", unit=MetricUnit.Count, value=enqueued)
    metrics.add_dimension(name="source", value=source)
    logger.info("Discovery complete", extra={"imagesEnqueued": enqueued})
    return {"source": source, "imagesEnqueued": enqueued}


def _envelope_for(event: dict[str, Any]) -> dict[str, Any]:
    """Wrap the raw Lambda event in the ``{source, payload}`` envelope.

    An event with a ``source`` key (e.g. a scheduled trigger's input) is the
    envelope itself; otherwise the whole event is the payload and ``source``
    falls back to ``BYOR_TRIGGER_SOURCE`` then ``DEFAULT_TRIGGER_SOURCE``.
    """
    if isinstance(event, dict) and "source" in event:
        return {
            "source": event.get("source") or _default_source(),
            "payload": event.get("payload") or {},
        }
    return {"source": _default_source(), "payload": event or {}}


def _default_source() -> str:
    return os.environ.get(ENV_TRIGGER_SOURCE) or DEFAULT_TRIGGER_SOURCE


@tracer.start_as_current_span("ResolveImages")
def _query_with_retry(envelope: dict[str, Any]) -> list[dict[str, str]]:
    last_exc: Exception | None = None
    for attempt in range(MAX_RETRIES):
        try:
            return discovery.discover(envelope)
        except Exception as e:
            last_exc = e
            if attempt == MAX_RETRIES - 1:
                break
            wait = BASE_BACKOFF * (2**attempt)
            logger.warning(
                "Backend query failed, retrying",
                extra={"waitSeconds": wait, "attempt": attempt + 1},
            )
            time.sleep(wait)
    raise ScanError(
        DISCOVERY_FAILED,
        f"Discovery backend failed after {MAX_RETRIES} attempts: {last_exc}",
    )


@tracer.start_as_current_span("ValidateImages")
def _validate_images(images: list[dict[str, str]]) -> None:
    if len(images) > MAX_DISCOVERED:
        raise ScanError(
            INVALID_INPUT,
            f"Discovery returned {len(images)} images, exceeds cap "
            f"{MAX_DISCOVERED}. Configure {ENV_MAX_DISCOVERED} or narrow "
            "the backend's query scope.",
        )
    for idx, img in enumerate(images):
        if not isinstance(img, dict):
            raise ScanError(
                INVALID_INPUT,
                f"Discovery result at index {idx} is not a dict: {img!r}",
            )
        for field in ("image", "ref"):
            value = img.get(field)
            if not isinstance(value, str) or not value:
                raise ScanError(
                    INVALID_INPUT,
                    f"Discovery result at index {idx} missing or empty "
                    f"{field!r}: {img!r}",
                )
        # `registry` is optional ─ when a backend omits it the field is left
        # off the message and the scanner resolves the default registry. If a
        # backend supplies it, it must be a non-empty string.
        registry = img.get("registry")
        if registry is not None and (not isinstance(registry, str) or not registry):
            raise ScanError(
                INVALID_INPUT,
                f"Discovery result at index {idx} has invalid "
                f"'registry' (must be a non-empty string): {img!r}",
            )
        # sourceType is optional; allowlist it (findings S3 key segment).
        source_type = img.get("sourceType")
        if source_type is not None:
            if not isinstance(source_type, str):
                raise ScanError(
                    INVALID_INPUT,
                    f"Discovery result at index {idx} has non-string "
                    f"'sourceType': {img!r}",
                )
            validate_source_type(source_type)


def _message_body(
    img: dict[str, str], source: str, requested_at: str
) -> dict[str, str]:
    """Build one SQS scan message body.

    ``registry`` is included only when the backend supplied one; otherwise it is
    omitted and the scanner resolves the default ─ keeping that decision in one
    place.
    """
    body = {
        "image": img["image"],
        "ref": img["ref"],
        "source": source,
        "requestedAt": requested_at,
    }
    registry = img.get("registry")
    if registry:
        body["registry"] = registry
    source_type = img.get("sourceType")
    if source_type:
        body["sourceType"] = source_type
    return body


def _send_batch_with_retry(entries: list[dict[str, str]]) -> list[dict[str, str]]:
    """Send one SQS batch, re-sending only the entries SQS rejects.

    ``send_message_batch`` is partial-success; rejected entries are usually
    transient, so we retry just those with exponential backoff. Returns the
    entries still failing after the last attempt (empty on success).
    """
    pending = entries
    for attempt in range(MAX_RETRIES):
        response = sqs_client.send_message_batch(QueueUrl=QUEUE_URL, Entries=pending)
        failed = response.get("Failed", [])
        if not failed:
            return []
        failed_ids = {entry["Id"] for entry in failed}
        pending = [e for e in pending if e["Id"] in failed_ids]
        if attempt == MAX_RETRIES - 1:
            return pending
        wait = BASE_BACKOFF * (2**attempt)
        logger.warning(
            "Partial SQS send failure, retrying failed entries",
            extra={
                "failedCount": len(failed),
                "waitSeconds": wait,
                "attempt": attempt + 1,
                "codes": sorted({entry["Code"] for entry in failed}),
            },
        )
        time.sleep(wait)
    return pending


@tracer.start_as_current_span("EnqueueBatch")
def _enqueue(images: list[dict[str, str]], source: str) -> int:
    if not images:
        return 0

    requested_at = datetime.now(UTC).isoformat()
    enqueued = 0
    dropped = 0

    for batch_start in range(0, len(images), SQS_BATCH_SIZE):
        batch = images[batch_start : batch_start + SQS_BATCH_SIZE]
        entries = [
            {
                "Id": str(idx),
                "MessageBody": json.dumps(_message_body(img, source, requested_at)),
            }
            for idx, img in enumerate(batch)
        ]

        still_failed = _send_batch_with_retry(entries)
        enqueued += len(entries) - len(still_failed)
        dropped += len(still_failed)

    if dropped:
        # Meter the drop, then fail so the trigger re-fires the cycle ─ recovery,
        # not just visibility. Re-enqueuing is cheap (scanner is idempotent via
        # the digest-keyed SBOM cache).
        with single_metric(
            name="ImagesEnqueueFailed",
            unit=MetricUnit.Count,
            value=dropped,
            namespace=METRIC_NAMESPACE,
        ) as metric:
            metric.add_dimension(name="source", value=source)
        raise ScanError(
            ENQUEUE_FAILED,
            f"{dropped} image(s) could not be enqueued to SQS after "
            f"{MAX_RETRIES} attempts; failing the cycle for retry.",
        )

    return enqueued
