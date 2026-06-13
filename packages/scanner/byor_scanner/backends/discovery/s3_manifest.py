"""S3-manifest discovery backend.

Reads image manifests from S3 ``OBJECT_CREATED`` events. The default
plugin paired with the ``S3ManifestTrigger`` CDK construct.

Manifest schema (the JSON file dropped into the bucket):

    [
      {"image": "library/nginx", "ref": "1.25"},
      {"image": "myorg/api",     "ref": "sha256:abc..."}
    ]

The bucket itself is owned by the trigger construct on the CDK side; this
plugin only needs ``s3:GetObject`` on the manifests it reads (granted by
the trigger).
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import unquote_plus

import boto3
from aws_lambda_powertools import Logger
from botocore.exceptions import ClientError
from opentelemetry import trace

from byor_scanner.constants import SERVICE_DISCOVERY
from byor_scanner.errors import DISCOVERY_FAILED, ScanError

logger = Logger(service=SERVICE_DISCOVERY)
tracer = trace.get_tracer(__name__)


class S3ManifestDiscovery:
    """Read image manifests from S3 OBJECT_CREATED events."""

    def __init__(self) -> None:
        self._s3 = boto3.client("s3")

    @tracer.start_as_current_span("S3ManifestDiscovery.discover")
    def discover(self, event: dict[str, Any]) -> list[dict[str, str]]:
        payload = event.get("payload") or {}
        records = payload.get("Records") or []
        images: list[dict[str, str]] = []
        for record in records:
            bucket, key = _bucket_key(record)
            manifest = self._read_manifest(bucket, key)
            logger.info(
                "Manifest read",
                extra={"bucket": bucket, "key": key, "count": len(manifest)},
            )
            images.extend(manifest)
        return images

    def _read_manifest(self, bucket: str, key: str) -> list[dict[str, str]]:
        try:
            response = self._s3.get_object(Bucket=bucket, Key=key)
            body = response["Body"].read()
        except ClientError as e:
            raise ScanError(
                DISCOVERY_FAILED,
                f"Failed to read manifest s3://{bucket}/{key}: {e}",
            ) from e
        try:
            manifest = json.loads(body)
        except json.JSONDecodeError as e:
            raise ScanError(
                DISCOVERY_FAILED,
                f"Manifest s3://{bucket}/{key} is not valid JSON: {e}",
            ) from e
        if not isinstance(manifest, list):
            raise ScanError(
                DISCOVERY_FAILED,
                f"Manifest s3://{bucket}/{key} must be a JSON array, got "
                f"{type(manifest).__name__}",
            )
        return manifest


def _bucket_key(record: dict[str, Any]) -> tuple[str, str]:
    """Pull the S3 ``bucket`` + URL-decoded ``key`` out of one event record."""
    s3 = record.get("s3") or {}
    bucket = (s3.get("bucket") or {}).get("name")
    raw_key = (s3.get("object") or {}).get("key")
    if not bucket or not raw_key:
        raise ScanError(
            DISCOVERY_FAILED,
            f"S3 event record missing bucket name or object key: {record!r}",
        )
    return bucket, unquote_plus(raw_key)
