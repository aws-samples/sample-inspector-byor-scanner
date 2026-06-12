"""ScanSbom API interaction.

Wraps Inspector's ``inspector-scan:ScanSbom`` API:

  - batches SBOMs whose ``components[]`` exceed the API's 5000-component
    cap, treating each batch as a standalone CycloneDX document and
    concatenating their ``vulnerabilities[]``;
  - retries with exponential backoff on ``ThrottlingException``.
"""

from __future__ import annotations

import copy
import time
from typing import Any

import boto3
from aws_lambda_powertools import Logger
from botocore.exceptions import ClientError
from opentelemetry import trace

from byor_scanner.config import config
from byor_scanner.constants import SERVICE_SCANNER
from byor_scanner.errors import SCANSBOM_FAILED, SCANSBOM_THROTTLED, ScanError

logger = Logger(service=SERVICE_SCANNER)
tracer = trace.get_tracer(__name__)

inspector_client = boto3.client("inspector-scan")

MAX_COMPONENTS_PER_BATCH = 5000
MAX_RETRIES = config.retry.max_attempts
BASE_BACKOFF = config.retry.base_backoff_seconds


@tracer.start_as_current_span("ScanVulnerabilities")
def call_scan_sbom(sbom: dict[str, Any]) -> dict[str, Any]:
    """Call ``ScanSbom``, batching when needed.

    On a single-batch scan, returns the API response directly. On a
    multi-batch scan, returns the original SBOM with all batches'
    ``vulnerabilities[]`` concatenated.
    """
    components = sbom.get("components", [])

    if len(components) <= MAX_COMPONENTS_PER_BATCH:
        return _scan_single(sbom)

    logger.info(
        "Splitting SBOM into batches",
        extra={
            "componentCount": len(components),
            "batchSize": MAX_COMPONENTS_PER_BATCH,
        },
    )
    batches = _chunk(components, MAX_COMPONENTS_PER_BATCH)
    all_vulns: list[dict[str, Any]] = []

    for batch_idx, batch_components in enumerate(batches):
        batch_sbom = _make_batch_sbom(sbom, batch_components)
        result = _scan_single(batch_sbom)
        all_vulns.extend(result.get("vulnerabilities", []))
        logger.info(
            "Batch complete",
            extra={
                "batch": batch_idx + 1,
                "totalBatches": len(batches),
                "findings": len(result.get("vulnerabilities", [])),
            },
        )

    return {**sbom, "vulnerabilities": all_vulns}


def _scan_single(sbom: dict[str, Any]) -> dict[str, Any]:
    """Single ``ScanSbom`` invocation with throttle backoff."""
    for attempt in range(MAX_RETRIES):
        try:
            response = inspector_client.scan_sbom(
                sbom=sbom,
                outputFormat="CYCLONE_DX_1_5",
            )
            return response.get("sbom", {})
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ThrottlingException" and attempt < MAX_RETRIES - 1:
                wait = BASE_BACKOFF * (2**attempt)
                logger.warning(
                    "ScanSbom throttled, retrying",
                    extra={
                        "waitSeconds": wait,
                        "attempt": attempt + 1,
                        "maxRetries": MAX_RETRIES,
                    },
                )
                time.sleep(wait)
                continue
            if error_code == "ThrottlingException":
                raise ScanError(
                    SCANSBOM_THROTTLED,
                    f"ScanSbom throttled after {MAX_RETRIES} attempts",
                ) from e
            raise ScanError(SCANSBOM_FAILED, f"ScanSbom failed: {e}") from e

    # Unreachable: the loop always either returns or raises.
    raise ScanError(SCANSBOM_FAILED, "ScanSbom retry loop exited without result")


def _make_batch_sbom(
    original: dict[str, Any], components: list[dict[str, Any]]
) -> dict[str, Any]:
    """A standalone CycloneDX doc carrying a subset of components."""
    batch = {
        key: copy.deepcopy(val)
        for key, val in original.items()
        if key not in ("components", "vulnerabilities")
    }
    batch["components"] = components
    return batch


def _chunk(items: list[Any], size: int) -> list[list[Any]]:
    return [items[start : start + size] for start in range(0, len(items), size)]
