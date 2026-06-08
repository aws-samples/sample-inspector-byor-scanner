"""Scanner Lambda — pulls images, generates SBOMs, calls Inspector ScanSbom.

Triggered by SQS event source mapping. Processes one image per message:
1. skopeo inspect → resolve digest, size guard
2. S3 SBOM cache check (by digest)
3. skopeo copy → /tmp
4. inspector-sbomgen → CycloneDX 1.5
5. inspector-scan:ScanSbom → vulnerabilities
6. Write findings to S3

TODO: Implement the pipeline. Returns ReportBatchItemFailures on
per-message failure so SQS only retries the failed messages.
"""

from __future__ import annotations

from typing import Any

from aws_lambda_powertools import Logger, Metrics, Tracer
from aws_lambda_powertools.utilities.batch import (
    BatchProcessor,
    EventType,
    process_partial_response,
)
from aws_lambda_powertools.utilities.data_classes.sqs_event import SQSRecord

logger = Logger()
metrics = Metrics(namespace="BYORScan")
tracer = Tracer()

processor = BatchProcessor(event_type=EventType.SQS)


@tracer.capture_method
def _process_record(record: SQSRecord) -> None:
    body = record.json_body
    image = body["image"]
    ref = body["ref"]
    logger.info("processing image", extra={"image": image, "ref": ref})

    # TODO: skopeo inspect → digest + size guard
    # TODO: SBOM cache check
    # TODO: skopeo copy → /tmp/img.tar
    # TODO: inspector-sbomgen → /tmp/sbom.json
    # TODO: ScanSbom (chunked if components > 5000)
    # TODO: write findings to s3://{bucket}/findings/{image}/{short_digest}/{timestamp}.json
    # TODO: cleanup /tmp


@logger.inject_lambda_context(log_event=True)
@metrics.log_metrics
@tracer.capture_lambda_handler
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    return process_partial_response(
        event=event,
        record_handler=_process_record,
        processor=processor,
        context=context,
    )
