"""Per-image scan pipeline.

For each SQS message the handler receives, ``scan_image`` runs:

  1. ``skopeo inspect``  → resolve digest, get compressed size
  2. size guard          (skip if > max_image_size_gb)
  3. SBOM cache check    (S3 GET by digest)
  4. ``skopeo copy``     → /tmp tarball     (skipped on cache hit)
  5. ``inspector-sbomgen`` → CycloneDX SBOM (skipped on cache hit)
  6. ``ScanSbom``        → vulnerabilities
  7. write findings      → S3
  8. clean /tmp

Each stage is a tracer-captured subsegment so the X-Ray service map shows
the entire pipeline. Each error path raises ``ScanError`` with a typed
``error_code`` that the handler turns into a CloudWatch metric dimension.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.metrics import MetricUnit
from botocore.exceptions import ClientError
from opentelemetry import trace

from byor_scanner.config import config
from byor_scanner.constants import (
    DEFAULT_MAX_FINDINGS_BYTES,
    GLOBAL_SKOPEO_FLAGS,
    METRIC_NAMESPACE,
    POLICY_DIR,
    SBOMGEN_DEFAULT_PATH,
    SERVICE_SCANNER,
    SKOPEO_DEFAULT_PATH,
    SRC_PREFIX_MAP,
)
from byor_scanner.errors import (
    CONFIG_ERROR,
    FINDINGS_TOO_LARGE,
    INSPECT_TIMEOUT,
    PULL_TIMEOUT,
    S3_WRITE_FAILED,
    SBOMGEN_TIMEOUT,
    ScanError,
    classify_inspect_error,
    classify_pull_error,
    classify_sbomgen_error,
)
from byor_scanner.sbom import call_scan_sbom
from byor_scanner.subprocess_helpers import run as subprocess_run
from byor_scanner.validation import validate_image_name, validate_ref

logger = Logger(service=SERVICE_SCANNER)
metrics = Metrics(namespace=METRIC_NAMESPACE, service=SERVICE_SCANNER)
tracer = trace.get_tracer(__name__)

s3_client = boto3.client("s3")

import os  # noqa: E402 ─ used only in module-level path resolution below

SKOPEO_PATH = os.environ.get("BYOR_SKOPEO_PATH", SKOPEO_DEFAULT_PATH)
SBOMGEN_PATH = os.environ.get("BYOR_SBOMGEN_PATH", SBOMGEN_DEFAULT_PATH)

MAX_IMAGE_SIZE_BYTES = config.scan.max_image_size_gb * 1024 * 1024 * 1024
MAX_FINDINGS_BYTES = config.scan.max_findings_bytes or DEFAULT_MAX_FINDINGS_BYTES


@dataclass(frozen=True)
class ScanRequest:
    image: str
    ref: str
    registry: str
    auth_args: list[str]
    bucket: str


def ensure_policy_json() -> None:
    """Write skopeo's trust policy file once per cold start.

    The policy is ``insecureAcceptAnything``: skopeo does not verify image
    signatures. This is a deliberate trade-off ─ most BYO registries don't
    sign their images, and Inspector's vulnerability scan runs on the SBOM
    not the image, so signature verification adds friction without a
    matching security gain in this pipeline.

    Customers who DO sign their images can replace this policy file via a
    Lambda Layer that drops a stricter ``policy.json`` at the same path
    before the handler runs.
    """
    POLICY_DIR.mkdir(parents=True, exist_ok=True)
    (POLICY_DIR / "policy.json").write_text(
        '{"default":[{"type":"insecureAcceptAnything"}]}'
    )


@tracer.start_as_current_span("ScanImage")
def scan_image(req: ScanRequest) -> dict[str, Any]:
    """Run the full pipeline for a single image."""
    if not req.registry:
        raise ScanError(CONFIG_ERROR, "BYOR_REGISTRY_URL is not configured")

    validate_image_name(req.image)
    validate_ref(req.ref)

    image_ref = _build_image_ref(req.registry, req.image, req.ref)

    # Stage 1: inspect
    resolved_digest, size = _inspect(image_ref, req.auth_args)
    ref = resolved_digest or req.ref

    # Size guard
    if size > MAX_IMAGE_SIZE_BYTES:
        logger.warning(
            "Image skipped: too large",
            extra={
                "outcome": "skipped",
                "errorCode": "IMAGE_TOO_LARGE",
                "sizeBytes": size,
            },
        )
        metrics.add_metric(name="ImagesSkipped", unit=MetricUnit.Count, value=1)
        return {"outcome": "skipped", "reason": "too_large"}

    # Stage 2: SBOM cache check (only meaningful when ref is a digest)
    use_cache = ref.startswith("sha256:")
    sbom_cache_key = (
        f"sboms/{ref.replace('sha256:', '')}.json" if use_cache else None
    )
    cached_sbom = (
        _get_cached_sbom(req.bucket, sbom_cache_key) if sbom_cache_key else None
    )
    cache_hit = cached_sbom is not None

    metrics.add_metric(
        name="SBOMCacheHit" if cache_hit else "SBOMCacheMiss",
        unit=MetricUnit.Count,
        value=1,
    )

    work_dir = Path(tempfile.mkdtemp(prefix="scan-"))
    try:
        if cache_hit:
            sbom = cached_sbom
            logger.info("SBOM cache hit", extra={"sbomCacheHit": True})
        else:
            # Stage 3: pull
            tarball = work_dir / "image.tar"
            pull_ref = _build_image_ref(req.registry, req.image, ref)
            _pull(pull_ref, req.auth_args, tarball)

            # Stage 4: generate SBOM
            sbom_file = work_dir / "sbom.json"
            _generate_sbom(tarball, sbom_file)
            sbom = json.loads(sbom_file.read_text())

            # Cache the SBOM (best-effort; failure is non-fatal)
            if sbom_cache_key:
                _cache_sbom(req.bucket, sbom_cache_key, sbom)

        # Stage 5: ScanSbom
        findings = call_scan_sbom(sbom)

        # Stage 6: write findings
        findings_key = _write_findings(req.bucket, req.image, ref, findings)

        # Metrics
        vulns = findings.get("vulnerabilities", [])
        severity_counts = _count_by_severity(vulns)
        metrics.add_metric(name="ImagesScanned", unit=MetricUnit.Count, value=1)
        metrics.add_metric(
            name="VulnerabilitiesFound", unit=MetricUnit.Count, value=len(vulns)
        )
        for severity, count in severity_counts.items():
            if count:
                metrics.add_metadata(
                    key=f"vulnerabilities.{severity}", value=count
                )

        logger.info(
            "Scan complete",
            extra={
                "outcome": "success",
                "sbomCacheHit": cache_hit,
                "componentCount": len(sbom.get("components", [])),
                "findingsTotal": len(vulns),
                **{f"findings{k.capitalize()}": v for k, v in severity_counts.items()},
                "findingsKey": findings_key,
            },
        )
        return {"outcome": "success", "findingsKey": findings_key}

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
        _clean_skopeo_temps()


# ─── Helpers ───────────────────────────────────────────────────────────


def _build_image_ref(registry: str, image: str, ref: str) -> str:
    """Compose ``registry/image@digest`` or ``registry/image:tag``."""
    sep = "@" if ref.startswith("sha256:") else ":"
    return f"{registry}/{image}{sep}{ref}"


def _to_src_args(auth_args: list[str]) -> list[str]:
    """Translate auth args to ``skopeo copy``'s ``--src-*`` namespace.

    Unknown flags raise ``CONFIG_ERROR`` rather than passing through ─ a
    rogue plugin could otherwise inject arbitrary skopeo flags. New flag
    types must be declared in ``SRC_PREFIX_MAP`` or ``GLOBAL_SKOPEO_FLAGS``.
    """
    src_args: list[str] = []
    for arg in auth_args:
        if any(arg.startswith(flag) for flag in GLOBAL_SKOPEO_FLAGS):
            src_args.append(arg)
            continue
        for prefix, src_prefix in SRC_PREFIX_MAP.items():
            if arg.startswith(prefix):
                src_args.append(f"{src_prefix}{arg.split('=', 1)[1]}")
                break
        else:
            raise ScanError(
                CONFIG_ERROR,
                f"AuthProvider returned unknown skopeo flag: "
                f"{arg.split('=', 1)[0]!r}. "
                "New flag types must be declared in SRC_PREFIX_MAP or "
                "GLOBAL_SKOPEO_FLAGS in byor_scanner/constants.py.",
            )
    return src_args


@tracer.start_as_current_span("InspectImage")
def _inspect(image_ref: str, auth_args: list[str]) -> tuple[str, int]:
    """Run ``skopeo inspect``; return resolved digest + compressed size."""
    result = subprocess_run(
        argv=[SKOPEO_PATH, "inspect", *auth_args, f"docker://{image_ref}"],
        timeout=config.scan.inspect_timeout,
        timeout_error_code=INSPECT_TIMEOUT,
        timeout_message=(
            f"skopeo inspect timed out after {config.scan.inspect_timeout}s"
        ),
        failure_classifier=classify_inspect_error,
        failure_message="skopeo inspect failed",
    )
    info = json.loads(result.stdout)
    resolved_digest = info.get("Digest", "")
    layers = info.get("LayersData", [])
    size = sum(layer.get("Size", 0) for layer in layers)
    return resolved_digest, size


@tracer.start_as_current_span("PullImage")
def _pull(image_ref: str, auth_args: list[str], dest: Path) -> None:
    """Run ``skopeo copy`` to pull the image to a local tarball."""
    src_args = _to_src_args(auth_args)
    subprocess_run(
        argv=[
            SKOPEO_PATH,
            "--tmpdir", "/tmp",
            "copy",
            *src_args,
            f"docker://{image_ref}",
            f"docker-archive:{dest}",
        ],
        timeout=config.scan.copy_timeout,
        timeout_error_code=PULL_TIMEOUT,
        timeout_message=f"skopeo copy timed out after {config.scan.copy_timeout}s",
        failure_classifier=classify_pull_error,
        failure_message="skopeo copy failed",
    )


@tracer.start_as_current_span("GenerateSBOM")
def _generate_sbom(tarball: Path, sbom_file: Path) -> None:
    """Run ``inspector-sbomgen`` to produce a CycloneDX SBOM."""
    subprocess_run(
        argv=[SBOMGEN_PATH, "container", "--image", str(tarball), "-o", str(sbom_file)],
        timeout=config.scan.sbomgen_timeout,
        timeout_error_code=SBOMGEN_TIMEOUT,
        timeout_message=(
            f"inspector-sbomgen timed out after {config.scan.sbomgen_timeout}s"
        ),
        failure_classifier=classify_sbomgen_error,
        failure_message="inspector-sbomgen failed",
    )


@tracer.start_as_current_span("CheckSBOMCache")
def _get_cached_sbom(bucket: str, key: str) -> dict[str, Any] | None:
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        return json.loads(response["Body"].read())
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
            return None
        raise


@tracer.start_as_current_span("CacheSBOM")
def _cache_sbom(bucket: str, key: str, sbom: dict[str, Any]) -> None:
    try:
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=json.dumps(sbom),
            ContentType="application/json",
        )
        logger.info("SBOM cached", extra={"sbomKey": key})
    except ClientError:
        # Best effort ─ caching failure must not fail the scan.
        logger.warning("Failed to cache SBOM, continuing", extra={"sbomKey": key})


@tracer.start_as_current_span("DeliverFindings")
def _write_findings(
    bucket: str, image: str, ref: str, findings: dict[str, Any]
) -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    short_ref = ref.replace("sha256:", "")[:12]
    findings_key = f"findings/{image}/{short_ref}/{timestamp}.json"
    body = json.dumps(findings, default=str)
    if len(body.encode()) > MAX_FINDINGS_BYTES:
        raise ScanError(
            FINDINGS_TOO_LARGE,
            f"Findings JSON {len(body)} bytes exceeds cap {MAX_FINDINGS_BYTES}",
        )
    try:
        s3_client.put_object(
            Bucket=bucket,
            Key=findings_key,
            Body=body,
            ContentType="application/json",
        )
    except ClientError as e:
        raise ScanError(S3_WRITE_FAILED, f"Failed to write findings: {e}") from e
    return findings_key


def _count_by_severity(vulns: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for vuln in vulns:
        for rating in vuln.get("ratings", []):
            severity = (rating.get("severity") or "").lower()
            if severity in counts:
                counts[severity] += 1
                break
    return counts


def _clean_skopeo_temps() -> None:
    """Remove skopeo's internal temp files from /tmp.

    The containers/image library uses prefix 'container_images_' for all
    temp files. Interrupted pulls (timeout, disk full) leave these behind.
    Clean after each image to prevent accumulation across a batch.
    """
    import contextlib
    import glob
    import os

    for path in glob.glob("/tmp/container_images_*"):
        with contextlib.suppress(OSError):
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                os.remove(path)
