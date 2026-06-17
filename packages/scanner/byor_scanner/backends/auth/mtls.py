"""mTLS auth provider.

Reads a single Secrets Manager secret with the schema
``{"ca": "<PEM>", "cert": "<PEM>", "key": "<PEM>"}`` and writes it to
``/tmp/certs/`` so skopeo can use it via ``--cert-dir``.

The secret is fetched **on every Lambda invocation** ─ never cached
across invocations ─ so rotated certificates are picked up automatically
without a redeploy.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

import boto3
from aws_lambda_powertools import Logger
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from opentelemetry import trace

from byor_scanner.constants import (
    CERT_DIR,
    ENV_MTLS_SECRET_NAME,
    SERVICE_SCANNER,
)
from byor_scanner.errors import AUTH_FAILED, CONFIG_ERROR, ScanError

logger = Logger(service=SERVICE_SCANNER)
tracer = trace.get_tracer(__name__)

CA_FILENAME = "ca.crt"
CERT_FILENAME = "client.cert"
KEY_FILENAME = "client.key"

_REQUIRED_FIELDS = ("ca", "cert", "key")
_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR  # 0o600
_DIR_MODE = stat.S_IRWXU  # 0o700


class MtlsAuth:
    """Authenticate to registries via mutual TLS client certificates.

    Required env var: ``BYOR_MTLS_SECRET_NAME``. The secret MUST be a JSON
    object with three non-empty PEM string fields: ``ca``, ``cert``,
    ``key``. Missing config or a malformed secret raises
    :class:`~byor_scanner.errors.ScanError` ─ never silently fallbacks to
    unauthenticated calls.
    """

    def __init__(self) -> None:
        # Adaptive retries so a transient Secrets Manager throttle is backed off
        # rather than turning straight into a per-message AUTH_FAILED → DLQ.
        self._sm_client = boto3.client(
            "secretsmanager",
            config=BotoConfig(retries={"mode": "adaptive", "max_attempts": 5}),
        )
        # Per-secret cert dir, set in setup() ─ so two registries scanned in one
        # batch don't clobber each other's certs under a shared path.
        self._cert_dir: Path | None = None

    @tracer.start_as_current_span("MtlsAuth.setup")
    def setup(self) -> None:
        secret_name = os.environ.get(ENV_MTLS_SECRET_NAME, "").strip()
        if not secret_name:
            raise ScanError(
                CONFIG_ERROR,
                f"{ENV_MTLS_SECRET_NAME} is not set. MtlsAuth requires a "
                "Secrets Manager secret name to fetch client certificates.",
            )

        # Hash the secret name (it may contain '/') into a per-secret subdir.
        digest = hashlib.sha256(secret_name.encode()).hexdigest()[:16]
        self._cert_dir = CERT_DIR / digest

        logger.info("mTLS setup starting", extra={"secretName": secret_name})

        secret = self._fetch(secret_name)
        self._validate(secret, secret_name)
        self._write(secret)

        logger.info(
            "mTLS setup complete",
            extra={"certDir": str(self._cert_dir), "secretName": secret_name},
        )

    def get_skopeo_args(self) -> list[str]:
        if self._cert_dir is None:
            raise ScanError(
                CONFIG_ERROR,
                "MtlsAuth.get_skopeo_args() called before setup().",
            )
        return [f"--cert-dir={self._cert_dir}", "--tls-verify=true"]

    def _fetch(self, secret_name: str) -> dict[str, Any]:
        try:
            response = self._sm_client.get_secret_value(SecretId=secret_name)
        except ClientError as e:
            raise ScanError(
                AUTH_FAILED,
                f"Failed to fetch Secrets Manager secret {secret_name!r}: {e}",
            ) from e
        try:
            return json.loads(response["SecretString"])
        except (KeyError, json.JSONDecodeError) as e:
            raise ScanError(
                AUTH_FAILED,
                f"Secret {secret_name!r} does not contain a JSON SecretString",
            ) from e

    def _validate(self, secret: dict[str, Any], secret_name: str) -> None:
        for field in _REQUIRED_FIELDS:
            value = secret.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ScanError(
                    AUTH_FAILED,
                    f"Secret {secret_name!r} is missing or empty field "
                    f"{field!r}. Expected schema: "
                    "{'ca': '<PEM>', 'cert': '<PEM>', 'key': '<PEM>'}",
                )

    def _write(self, secret: dict[str, Any]) -> None:
        # skopeo's --cert-dir needs PEM on disk (no in-memory API), so we
        # materialize into Lambda /tmp (per-env, encrypted at rest) with 0o700/
        # 0o600 modes. The CodeQL clear-text-storage suppression below is for
        # this tool-imposed constraint, not a free choice.
        assert self._cert_dir is not None  # set in setup() before _write()
        self._cert_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self._cert_dir, _DIR_MODE)
        for filename, field in (
            (CA_FILENAME, "ca"),
            (CERT_FILENAME, "cert"),
            (KEY_FILENAME, "key"),
        ):
            path = self._cert_dir / filename
            # codeql[py/clear-text-storage-sensitive-data]
            path.write_text(secret[field])
            os.chmod(path, _FILE_MODE)
