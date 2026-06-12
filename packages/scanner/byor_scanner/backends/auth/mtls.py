"""mTLS auth provider.

Reads a single Secrets Manager secret with the schema
``{"ca": "<PEM>", "cert": "<PEM>", "key": "<PEM>"}`` and writes it to
``/tmp/certs/`` so skopeo can use it via ``--cert-dir``.

The secret is fetched **on every Lambda invocation** ─ never cached
across invocations ─ so rotated certificates are picked up automatically
without a redeploy.
"""

from __future__ import annotations

import json
import os
import stat
from typing import Any

import boto3
from aws_lambda_powertools import Logger
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
        self._sm_client = boto3.client("secretsmanager")

    @tracer.start_as_current_span("MtlsAuth.setup")
    def setup(self) -> None:
        secret_name = os.environ.get(ENV_MTLS_SECRET_NAME, "").strip()
        if not secret_name:
            raise ScanError(
                CONFIG_ERROR,
                f"{ENV_MTLS_SECRET_NAME} is not set. MtlsAuth requires a "
                "Secrets Manager secret name to fetch client certificates.",
            )

        logger.info("mTLS setup starting", extra={"secretName": secret_name})

        secret = self._fetch(secret_name)
        self._validate(secret, secret_name)
        self._write(secret)

        logger.info(
            "mTLS setup complete",
            extra={"certDir": str(CERT_DIR), "secretName": secret_name},
        )

    def get_skopeo_args(self) -> list[str]:
        return [f"--cert-dir={CERT_DIR}", "--tls-verify=true"]

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
        # skopeo's --cert-dir reads PEM material from disk; there is no API
        # for passing bytes in memory. We materialize the secret into Lambda
        # /tmp which is per-execution-environment, encrypted at rest by AWS,
        # destroyed when the env is recycled, and never shared across
        # invocations. The 0o700 dir + 0o600 file modes prevent same-host
        # cross-process reads. CodeQL's clear-text-storage check fires on
        # the write_text call below; suppressed because the constraint is
        # imposed by the third-party tool, not a free design choice.
        CERT_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(CERT_DIR, _DIR_MODE)
        for filename, field in (
            (CA_FILENAME, "ca"),
            (CERT_FILENAME, "cert"),
            (KEY_FILENAME, "key"),
        ):
            path = CERT_DIR / filename
            # codeql[py/clear-text-storage-sensitive-data]
            path.write_text(secret[field])
            os.chmod(path, _FILE_MODE)
