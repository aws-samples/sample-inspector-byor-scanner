"""Shared constants: paths, env-var names, skopeo arg translations."""

from __future__ import annotations

from pathlib import Path

# --- Lambda filesystem layout ---
CERT_DIR = Path("/tmp/certs")
POLICY_DIR = Path("/tmp/.config/containers")
# Binaries ship in a dedicated Lambda Layer (see BinaryLayer construct).
# /opt is where Lambda mounts attached layers; /opt/bin is automatically
# added to $PATH. We pin the absolute path so a missing layer surfaces
# as an immediate FileNotFoundError instead of silently picking up a
# different `skopeo` from somewhere else on PATH.
SKOPEO_DEFAULT_PATH = "/opt/bin/skopeo"
SBOMGEN_DEFAULT_PATH = "/opt/bin/inspector-sbomgen"

# --- Environment variable names ---
# All plugin-related and runtime-tuneable env vars use the BYOR_ prefix to
# stay distinct from AWS-standard names (AWS_*) and from Lambda-platform
# names (_X_AMZN_*, AWS_LAMBDA_*).
ENV_AUTH_PROVIDER = "BYOR_AUTH_PROVIDER"
ENV_DISCOVERY_BACKEND = "BYOR_DISCOVERY_BACKEND"
ENV_MTLS_SECRET_NAME = "BYOR_MTLS_SECRET_NAME"
ENV_MAX_DISCOVERED = "BYOR_MAX_DISCOVERED"
ENV_REGISTRY_URL = "BYOR_REGISTRY_URL"
# JSON map of registry id -> {url, authProvider, authEnv, insecureTlsVerify}.
# Set by the CDK construct from accumulated addRegistry() calls (a Lazy token).
# When absent, config.py synthesizes a single "default" entry from
# ENV_REGISTRY_URL / ENV_AUTH_PROVIDER / ENV_MTLS_SECRET_NAME.
ENV_REGISTRIES = "BYOR_REGISTRIES"
ENV_FINDINGS_BUCKET = "BYOR_FINDINGS_BUCKET"
ENV_QUEUE_URL = "BYOR_QUEUE_URL"
# Trigger logical id, set by the trigger construct on the discovery Lambda.
# Used as the default `source` value when an event does not carry one.
ENV_TRIGGER_SOURCE = "BYOR_TRIGGER_SOURCE"
# Manifest bucket name, set by S3ManifestDiscoveryProvider (the provider that
# owns the bucket). The backend reads the bucket from S3 event Records, so this
# is only used for log context / direct-invoke testing.
ENV_MANIFEST_BUCKET = "BYOR_MANIFEST_BUCKET"
ENV_MAX_IMAGE_SIZE_GB = "BYOR_MAX_IMAGE_SIZE_GB"
ENV_INSPECT_TIMEOUT = "BYOR_INSPECT_TIMEOUT"
ENV_COPY_TIMEOUT = "BYOR_COPY_TIMEOUT"
ENV_SBOMGEN_TIMEOUT = "BYOR_SBOMGEN_TIMEOUT"
ENV_MAX_RETRIES = "BYOR_MAX_RETRIES"
ENV_BASE_BACKOFF = "BYOR_BASE_BACKOFF"
ENV_MAX_FINDINGS_BYTES = "BYOR_MAX_FINDINGS_BYTES"
ENV_SKOPEO_PATH = "BYOR_SKOPEO_PATH"
ENV_SBOMGEN_PATH = "BYOR_SBOMGEN_PATH"

# --- Skopeo arg translation for `skopeo copy` ---
# `skopeo inspect` uses bare flags; `skopeo copy` distinguishes source vs
# destination, so we rewrite known auth flags to their --src-* form.
SRC_PREFIX_MAP = {
    "--cert-dir=": "--src-cert-dir=",
    "--creds=": "--src-creds=",
    "--tls-verify=": "--src-tls-verify=",
    "--registry-token=": "--src-registry-token=",
}

# Skopeo flags that are global (not source/dest scoped) and pass through
# unchanged to `skopeo copy`. Add new flags here only after confirming they
# don't conflict with destination-scoped variants.
GLOBAL_SKOPEO_FLAGS = ("--authfile=",)

# --- Findings size cap ---
# Refuse to write a findings JSON larger than this. Caps an attack surface
# where a malicious or buggy ScanSbom response could produce arbitrarily
# large objects on S3.
DEFAULT_MAX_FINDINGS_BYTES = 10 * 1024 * 1024  # 10 MiB

# --- Powertools service names ---
SERVICE_SCANNER = "byor-scanner"
SERVICE_DISCOVERY = "byor-discovery"

# --- Powertools metric namespace ---
METRIC_NAMESPACE = "BYORScan"

# --- Discovery handler ---
SQS_BATCH_SIZE = 10  # SendMessageBatch hard limit
DEFAULT_MAX_DISCOVERED = 50_000  # Hard cap on discovery result size

# Default `source` when neither the event nor BYOR_TRIGGER_SOURCE supplies one.
# Should be unusual enough to spot in logs but bounded so it never explodes
# CloudWatch metric dimensionality.
DEFAULT_TRIGGER_SOURCE = "unknown"
