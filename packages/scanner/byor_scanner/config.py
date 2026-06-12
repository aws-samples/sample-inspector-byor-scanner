"""Runtime configuration loader.

Inlined defaults. Each value can be overridden by the corresponding
``BYOR_*`` environment variable, which the CDK stack sets from the
deployment-time config. See ``constants.py`` for the env-var inventory.

Loaded once at cold start.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from byor_scanner.constants import (
    DEFAULT_MAX_FINDINGS_BYTES,
    ENV_AUTH_PROVIDER,
    ENV_BASE_BACKOFF,
    ENV_COPY_TIMEOUT,
    ENV_DISCOVERY_BACKEND,
    ENV_INSPECT_TIMEOUT,
    ENV_MAX_FINDINGS_BYTES,
    ENV_MAX_IMAGE_SIZE_GB,
    ENV_MAX_RETRIES,
    ENV_SBOMGEN_TIMEOUT,
    ENV_TLS_VERIFY,
)

DEFAULT_AUTH_PROVIDER = "byor_scanner.backends.auth.mtls.MtlsAuth"
DEFAULT_DISCOVERY_BACKEND = "byor_scanner.backends.discovery.static.StaticDiscovery"


@dataclass(frozen=True)
class ScanConfig:
    max_image_size_gb: int = 2
    tls_verify: bool = True
    inspect_timeout: int = 30  # seconds
    copy_timeout: int = 300  # seconds
    sbomgen_timeout: int = 120  # seconds
    max_findings_bytes: int = DEFAULT_MAX_FINDINGS_BYTES


@dataclass(frozen=True)
class RetryConfig:
    max_attempts: int = 3
    base_backoff_seconds: float = 1.0


@dataclass(frozen=True)
class Config:
    scan: ScanConfig
    retry: RetryConfig
    auth_provider: str
    discovery_backend: str


def _bool_env(name: str, default: bool) -> bool:
    """Permissive boolean env-var parsing.

    Truthy: anything that isn't ``false`` / ``0`` / ``no`` / empty.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("false", "0", "no", "")


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw is not None else default


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    return float(raw) if raw is not None else default


def _load() -> Config:
    scan_defaults = ScanConfig()
    retry_defaults = RetryConfig()
    return Config(
        scan=ScanConfig(
            max_image_size_gb=_int_env(
                ENV_MAX_IMAGE_SIZE_GB, scan_defaults.max_image_size_gb
            ),
            tls_verify=_bool_env(ENV_TLS_VERIFY, scan_defaults.tls_verify),
            inspect_timeout=_int_env(
                ENV_INSPECT_TIMEOUT, scan_defaults.inspect_timeout
            ),
            copy_timeout=_int_env(ENV_COPY_TIMEOUT, scan_defaults.copy_timeout),
            sbomgen_timeout=_int_env(
                ENV_SBOMGEN_TIMEOUT, scan_defaults.sbomgen_timeout
            ),
            max_findings_bytes=_int_env(
                ENV_MAX_FINDINGS_BYTES, scan_defaults.max_findings_bytes
            ),
        ),
        retry=RetryConfig(
            max_attempts=_int_env(ENV_MAX_RETRIES, retry_defaults.max_attempts),
            base_backoff_seconds=_float_env(
                ENV_BASE_BACKOFF, retry_defaults.base_backoff_seconds
            ),
        ),
        auth_provider=os.environ.get(ENV_AUTH_PROVIDER, DEFAULT_AUTH_PROVIDER),
        discovery_backend=os.environ.get(
            ENV_DISCOVERY_BACKEND, DEFAULT_DISCOVERY_BACKEND
        ),
    )


config: Config = _load()
