"""Test-registry seeder Lambda.

Fired by a CDK Custom Resource on every TestingStack deploy. Pushes a
short list of public images (defaults to ``alpine:3.19``) into the
mTLS-protected test registry so the canary always has something to scan.

The registry's storage is ephemeral ─ images are lost when the ECS task
restarts. This handler re-runs on every stack update and is idempotent
(skopeo treats existing layers as no-ops).

Inputs come from the Custom Resource's ``ResourceProperties``:
  - ``RegistryEndpoint`` ─ NLB DNS name to push to.
  - ``Images``           ─ list of source image URIs
    (e.g. ``"public.ecr.aws/docker/library/alpine:3.19"``).

Reuses :class:`~byor_scanner.backends.auth.mtls.MtlsAuth` so the cert
fetch / file-write logic only lives in one place.
"""

from __future__ import annotations

import os
from typing import Any

from aws_lambda_powertools import Logger

from byor_scanner.backends.auth.mtls import MtlsAuth
from byor_scanner.constants import (
    POLICY_DIR,
    SBOMGEN_DEFAULT_PATH,  # noqa: F401  ─ kept for parity with scan.py paths
    SERVICE_SCANNER,
    SKOPEO_DEFAULT_PATH,
)
from byor_scanner.errors import ScanError
from byor_scanner.subprocess_helpers import run as subprocess_run

logger = Logger(service=SERVICE_SCANNER)

SKOPEO_PATH = os.environ.get("BYOR_SKOPEO_PATH", SKOPEO_DEFAULT_PATH)
COPY_TIMEOUT = 300


def _ensure_policy_json() -> None:
    """skopeo refuses to run without a trust policy file. Same insecure
    accept-anything policy the scanner uses ─ public images and we trust
    the source registries."""
    POLICY_DIR.mkdir(parents=True, exist_ok=True)
    (POLICY_DIR / "policy.json").write_text(
        '{"default":[{"type":"insecureAcceptAnything"}]}'
    )


def _seed_one(source: str, registry: str, auth_args: list[str]) -> None:
    """Copy a single public image into the registry."""
    short_name = source.rsplit("/", 1)[-1]
    dest = f"{registry}/{short_name}"
    logger.info("Seeding image", extra={"source": source, "dest": dest})

    # auth_args is for the *destination* (our registry). The source is
    # public ECR so no creds. We translate to --dest-* for skopeo copy.
    dest_args = []
    for arg in auth_args:
        if arg.startswith("--cert-dir="):
            dest_args.append(f"--dest-cert-dir={arg.split('=', 1)[1]}")
        elif arg.startswith("--tls-verify="):
            dest_args.append(f"--dest-tls-verify={arg.split('=', 1)[1]}")
        # Unknown flags are dropped here ─ this Lambda only ever drives
        # MtlsAuth, which emits exactly --cert-dir + --tls-verify.

    subprocess_run(
        argv=[
            SKOPEO_PATH,
            "--tmpdir", "/tmp",
            "copy",
            "--multi-arch=system",
            *dest_args,
            f"docker://{source}",
            f"docker://{dest}",
        ],
        timeout=COPY_TIMEOUT,
        timeout_error_code="SEED_TIMEOUT",
        timeout_message=f"skopeo copy of {source} timed out",
        failure_classifier=lambda _stderr: "SEED_FAILED",
        failure_message=f"skopeo copy of {source} failed",
    )
    logger.info("Seeded image", extra={"dest": dest})


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:  # noqa: ARG001
    """CloudFormation Custom Resource entry point.

    Returns ``{"PhysicalResourceId": "..."}`` on success. On Delete this
    is a no-op (CFN tears the registry down separately, so any leftover
    images go with it).
    """
    request_type = event.get("RequestType", "Create")
    physical_id = (
        event.get("PhysicalResourceId")
        or f"seeder-{event.get('RequestId', 'init')}"
    )

    if request_type == "Delete":
        return {"PhysicalResourceId": physical_id}

    props = event.get("ResourceProperties", {})
    registry = props.get("RegistryEndpoint")
    images = props.get("Images", [])

    if not registry:
        raise ScanError(
            "CONFIG_ERROR", "RegistryEndpoint missing from ResourceProperties"
        )
    if not images:
        logger.info("No images to seed; nothing to do")
        return {"PhysicalResourceId": physical_id}

    auth = MtlsAuth()
    auth.setup()
    _ensure_policy_json()
    auth_args = auth.get_skopeo_args()

    for source in images:
        _seed_one(source, registry, auth_args)

    return {
        "PhysicalResourceId": physical_id,
        "Data": {"SeededCount": str(len(images))},
    }
