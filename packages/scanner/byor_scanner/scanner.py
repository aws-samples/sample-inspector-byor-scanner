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
from typing import Any

from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.metrics import MetricUnit

from byor_scanner.config import config
from byor_scanner.constants import (
    ENV_AUTH_PROVIDER,
    ENV_FINDINGS_BUCKET,
    ENV_REGISTRY_URL,
    METRIC_NAMESPACE,
    SERVICE_SCANNER,
)
from byor_scanner.errors import ScanError
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

        try:
            body = json.loads(record["body"])
            image = body["image"]
            ref = body["ref"]
            mode = body.get("mode", "unknown")
            logger.append_keys(image=image, ref=ref, mode=mode, attempt=attempt)
            logger.info("Scan starting")

            scan_image(
                ScanRequest(
                    image=image,
                    ref=ref,
                    registry=REGISTRY,
                    auth_args=auth.get_skopeo_args(),
                    bucket=FINDINGS_BUCKET,
                )
            )

        except ScanError as e:
            logger.exception(
                "Scan failed",
                extra={"messageId": message_id, "errorCode": e.error_code},
            )
            metrics.add_metric(name="ImagesFailed", unit=MetricUnit.Count, value=1)
            metrics.add_metadata(key="errorCode", value=e.error_code)
            failures.append({"itemIdentifier": message_id})
        except Exception:
            logger.exception(
                "Scan failed",
                extra={"messageId": message_id, "errorCode": "UNKNOWN"},
            )
            metrics.add_metric(name="ImagesFailed", unit=MetricUnit.Count, value=1)
            metrics.add_metadata(key="errorCode", value="UNKNOWN")
            failures.append({"itemIdentifier": message_id})
        finally:
            logger.remove_keys(["image", "ref", "mode", "attempt"])

    return {"batchItemFailures": failures}
