"""Discovery Lambda: find images and fan out to SQS for scanning.

Triggered three ways:

  - **EventBridge Scheduler** (e.g. hourly / 12-hourly cron) ─ event has
    ``{"mode": "hourly" | "full"}``.
  - **Direct invoke** (canary / on-demand) ─ event has
    ``{"mode": "manual", "images": [{image, ref}, ...]}``. The static
    backend returns the ``images`` list verbatim; no external query.
  - **Direct invoke with backend params** ─ event has
    ``{"mode": "<mode>", "config": {...}}``. The ``config`` payload is
    forwarded to the backend's :meth:`~DiscoveryBackend.discover` method
    for endpoint overrides or query filters without redeploying.

Every batch enqueued to SQS carries::

    {"image": "...", "ref": "...", "mode": "<mode>", "requestedAt": "<ISO>"}

The scanner Lambda consumes these messages from the SQS event source
mapping. Per-message ``ref`` is whatever the discovery backend returned
─ a tag or a digest; the scanner pipeline resolves either form.
"""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from typing import Any

import boto3
from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.metrics import MetricUnit
from opentelemetry import trace

from byor_scanner.config import config
from byor_scanner.constants import (
    DEFAULT_MAX_DISCOVERED,
    ENV_DISCOVERY_BACKEND,
    ENV_MAX_DISCOVERED,
    ENV_QUEUE_URL,
    METRIC_NAMESPACE,
    SERVICE_DISCOVERY,
    SQS_BATCH_SIZE,
    VALID_MODES,
)
from byor_scanner.errors import (
    CONFIG_ERROR,
    DISCOVERY_FAILED,
    INVALID_INPUT,
    ScanError,
)
from byor_scanner.plugin_loader import load_plugin
from byor_scanner.protocols import DiscoveryBackend

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
    """EventBridge / direct-invoke entry point."""
    if not QUEUE_URL:
        raise ScanError(CONFIG_ERROR, f"{ENV_QUEUE_URL} is not configured")

    mode = event.get("mode")
    _validate_mode(mode)
    logger.append_keys(mode=mode)
    logger.info("Discovery starting")

    try:
        images = _resolve_images(mode, event)
        _validate_images(images)
        enqueued = _enqueue(images, mode)
    except ScanError as e:
        logger.exception("Discovery failed", extra={"errorCode": e.error_code})
        metrics.add_metric(name="DiscoveryFailed", unit=MetricUnit.Count, value=1)
        metrics.add_metadata(key="errorCode", value=e.error_code)
        raise
    except Exception:
        logger.exception("Discovery failed", extra={"errorCode": "UNKNOWN"})
        metrics.add_metric(name="DiscoveryFailed", unit=MetricUnit.Count, value=1)
        metrics.add_metadata(key="errorCode", value="UNKNOWN")
        raise

    metrics.add_metric(name="ImagesEnqueued", unit=MetricUnit.Count, value=enqueued)
    metrics.add_dimension(name="mode", value=mode)
    logger.info("Discovery complete", extra={"imagesEnqueued": enqueued})
    return {"mode": mode, "imagesEnqueued": enqueued}


def _validate_mode(mode: Any) -> None:
    if not isinstance(mode, str) or not mode:
        raise ScanError(
            INVALID_INPUT,
            f"Discovery event must include 'mode' as a non-empty string. "
            f"Valid modes: {sorted(VALID_MODES)}",
        )
    if mode not in VALID_MODES:
        raise ScanError(
            INVALID_INPUT,
            f"Unknown mode {mode!r}. Valid modes: {sorted(VALID_MODES)}",
        )


@tracer.start_as_current_span("ResolveImages")
def _resolve_images(mode: str, event: dict[str, Any]) -> list[dict[str, str]]:
    """Manual mode reads ``event.images``; other modes call the backend."""
    if mode == "manual":
        return list(event.get("images", []))
    return _query_with_retry(mode, event.get("config", {}))


def _query_with_retry(mode: str, params: dict[str, Any]) -> list[dict[str, str]]:
    last_exc: Exception | None = None
    for attempt in range(MAX_RETRIES):
        try:
            return discovery.discover(mode, params)
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


@tracer.start_as_current_span("EnqueueBatch")
def _enqueue(images: list[dict[str, str]], mode: str) -> int:
    if not images:
        return 0

    requested_at = datetime.now(UTC).isoformat()
    enqueued = 0

    for batch_start in range(0, len(images), SQS_BATCH_SIZE):
        batch = images[batch_start : batch_start + SQS_BATCH_SIZE]
        entries = [
            {
                "Id": str(idx),
                "MessageBody": json.dumps(
                    {
                        "image": img["image"],
                        "ref": img["ref"],
                        "mode": mode,
                        "requestedAt": requested_at,
                    }
                ),
            }
            for idx, img in enumerate(batch)
        ]

        response = sqs_client.send_message_batch(QueueUrl=QUEUE_URL, Entries=entries)

        failed = response.get("Failed", [])
        if failed:
            logger.error(
                "Partial SQS send failure",
                extra={
                    "failedCount": len(failed),
                    "errors": [
                        {"id": entry["Id"], "code": entry["Code"]}
                        for entry in failed
                    ],
                },
            )

        enqueued += len(entries) - len(failed)

    return enqueued
