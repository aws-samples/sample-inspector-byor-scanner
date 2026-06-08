"""Pusher Lambda — fans out scan requests to SQS.

Triggered by EventBridge schedules (hourly, 12-hourly) or invoked
directly with `mode=manual` for ad-hoc / canary scans.

TODO:
- Resolve image inventory (mode=hourly: last hour's deploys; mode=full:
  all deployed images; mode=manual: payload `images` array verbatim).
- SendMessageBatch to the scanner SQS queue.
- PusherFailed metric on registry/inventory query failure.
"""

from __future__ import annotations

from typing import Any

from aws_lambda_powertools import Logger, Metrics, Tracer
from aws_lambda_powertools.metrics import MetricUnit

logger = Logger()
metrics = Metrics(namespace="BYORScan")
tracer = Tracer()


@logger.inject_lambda_context(log_event=True)
@metrics.log_metrics
@tracer.capture_lambda_handler
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:  # noqa: ARG001
    mode = event.get("mode", "hourly")
    logger.info("pusher invoked", extra={"mode": mode})

    # TODO: resolve image list
    # TODO: SendMessageBatch
    images_enqueued = 0

    metrics.add_metric(
        name="ImagesEnqueued",
        unit=MetricUnit.Count,
        value=images_enqueued,
    )
    metrics.add_dimension(name="mode", value=mode)

    return {"mode": mode, "imagesEnqueued": images_enqueued}
