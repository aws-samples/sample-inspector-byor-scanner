"""Runtime configuration loader.

Inlined defaults. Each value can be overridden by the corresponding
``BYOR_*`` environment variable, which the CDK stack sets from the
deployment-time config. See ``constants.py`` for the env-var inventory.

Loaded once at cold start.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

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
    ENV_MTLS_SECRET_NAME,
    ENV_REGISTRIES,
    ENV_REGISTRY_URL,
    ENV_SBOMGEN_TIMEOUT,
)

DEFAULT_AUTH_PROVIDER = "byor_scanner.backends.auth.mtls.MtlsAuth"
DEFAULT_DISCOVERY_BACKEND = "byor_scanner.backends.discovery.static.StaticDiscovery"


@dataclass(frozen=True)
class ScanConfig:
    max_image_size_gb: int = 2
    inspect_timeout: int = 30  # seconds
    copy_timeout: int = 300  # seconds
    sbomgen_timeout: int = 120  # seconds
    max_findings_bytes: int = DEFAULT_MAX_FINDINGS_BYTES


@dataclass(frozen=True)
class RetryConfig:
    max_attempts: int = 3
    base_backoff_seconds: float = 1.0


@dataclass(frozen=True)
class RegistryEntry:
    """One configured registry: where images live + how to auth.

    ``url`` is the registry hostname (no scheme). ``auth_provider`` is a
    dotted path to an :class:`~byor_scanner.protocols.AuthProvider` class.
    ``auth_env`` carries the registry-specific env vars that provider reads
    (e.g. ``BYOR_MTLS_SECRET_NAME``); the scanner applies them to
    ``os.environ`` immediately before calling that registry's ``setup()`` so
    two registries using the same provider don't collide on a shared env var.
    """

    url: str
    auth_provider: str
    auth_env: dict[str, str] = field(default_factory=dict)
    insecure_tls_verify: bool = False


@dataclass(frozen=True)
class Config:
    scan: ScanConfig
    retry: RetryConfig
    auth_provider: str
    discovery_backend: str
    registries: dict[str, RegistryEntry]


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw is not None else default


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    return float(raw) if raw is not None else default


def _load_registries(auth_provider_default: str) -> dict[str, RegistryEntry]:
    """Parse the ``BYOR_REGISTRIES`` JSON map into ``RegistryEntry`` objects.

    Shape (set by the CDK construct as a Lazy token)::

        {
          "<id>": {
            "url": "registry.example.com",
            "authProvider": "byor_scanner.backends.auth.mtls.MtlsAuth",
            "authEnv": {"BYOR_MTLS_SECRET_NAME": "scanner/prod-certs"},
            "insecureTlsVerify": false
          },
          ...
        }

    When ``BYOR_REGISTRIES`` is unset, synthesize a single ``"default"`` entry
    from the individual env vars (``BYOR_REGISTRY_URL`` / ``BYOR_AUTH_PROVIDER``
    / ``BYOR_MTLS_SECRET_NAME``). An explicit empty map (``"{}"``) is honored
    as-is (zero registries).
    """
    raw = os.environ.get(ENV_REGISTRIES, "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"{ENV_REGISTRIES} is not valid JSON: {e}. Expected a map of "
                'registry id → {"url", "authProvider", "authEnv", '
                '"insecureTlsVerify"}.'
            ) from e
        if not isinstance(parsed, dict):
            raise ValueError(
                f"{ENV_REGISTRIES} must be a JSON object (map of registry id → "
                f"config), got {type(parsed).__name__}."
            )
        for registry_id, entry in parsed.items():
            if not isinstance(entry, dict):
                raise ValueError(
                    f"{ENV_REGISTRIES} entry {registry_id!r} must be a JSON "
                    f"object, got {type(entry).__name__}."
                )
        return {
            registry_id: RegistryEntry(
                url=entry.get("url", ""),
                auth_provider=entry.get("authProvider") or auth_provider_default,
                auth_env=dict(entry.get("authEnv") or {}),
                insecure_tls_verify=bool(entry.get("insecureTlsVerify", False)),
            )
            for registry_id, entry in parsed.items()
        }

    # Synthesize a single "default" registry from the individual env vars.
    default_auth_env: dict[str, str] = {}
    mtls_secret = os.environ.get(ENV_MTLS_SECRET_NAME)
    if mtls_secret:
        default_auth_env[ENV_MTLS_SECRET_NAME] = mtls_secret
    return {
        "default": RegistryEntry(
            url=os.environ.get(ENV_REGISTRY_URL, ""),
            auth_provider=auth_provider_default,
            auth_env=default_auth_env,
        )
    }


def _load() -> Config:
    scan_defaults = ScanConfig()
    retry_defaults = RetryConfig()
    auth_provider = os.environ.get(ENV_AUTH_PROVIDER, DEFAULT_AUTH_PROVIDER)
    return Config(
        scan=ScanConfig(
            max_image_size_gb=_int_env(
                ENV_MAX_IMAGE_SIZE_GB, scan_defaults.max_image_size_gb
            ),
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
        auth_provider=auth_provider,
        discovery_backend=os.environ.get(
            ENV_DISCOVERY_BACKEND, DEFAULT_DISCOVERY_BACKEND
        ),
        registries=_load_registries(auth_provider),
    )


config: Config = _load()
