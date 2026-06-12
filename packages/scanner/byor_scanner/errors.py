"""Error codes and classification logic for the scan pipeline.

Every failure surfaces a typed `errorCode` that flows into:
  - structured logs (so operators can grep for it),
  - the `ImagesFailed` CloudWatch metric (as a dimension),
  - per-stage alarms,
  - the SQS-DLQ analysis path.

When a new failure mode is added, give it an explicit code here ─ never let
it land as a generic exception.
"""

from __future__ import annotations


class ScanError(Exception):
    """Scan pipeline error with a classifiable error code.

    Error codes follow the pattern ``STAGE_REASON`` (e.g. ``PULL_TIMEOUT``).
    """

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code


# --- Configuration / input errors (fail before any work starts) ---
CONFIG_ERROR = "CONFIG_ERROR"
INVALID_INPUT = "INVALID_INPUT"

# --- Discovery handler ---
DISCOVERY_FAILED = "DISCOVERY_FAILED"

# --- Inspect stage (skopeo inspect) ---
INSPECT_TIMEOUT = "INSPECT_TIMEOUT"
INSPECT_FAILED = "INSPECT_FAILED"
IMAGE_NOT_FOUND = "IMAGE_NOT_FOUND"
IMAGE_TOO_LARGE = "IMAGE_TOO_LARGE"
AUTH_FAILED = "AUTH_FAILED"

# --- Pull stage (skopeo copy) ---
PULL_TIMEOUT = "PULL_TIMEOUT"
PULL_FAILED = "PULL_FAILED"
DISK_FULL = "DISK_FULL"

# --- SBOM generation (inspector-sbomgen) ---
SBOMGEN_TIMEOUT = "SBOMGEN_TIMEOUT"
SBOMGEN_FAILED = "SBOMGEN_FAILED"
UNSUPPORTED_OS = "UNSUPPORTED_OS"
UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"

# --- ScanSbom API ---
SCANSBOM_THROTTLED = "SCANSBOM_THROTTLED"
SCANSBOM_FAILED = "SCANSBOM_FAILED"

# --- Findings delivery ---
S3_WRITE_FAILED = "S3_WRITE_FAILED"
FINDINGS_TOO_LARGE = "FINDINGS_TOO_LARGE"


# Stderr classification. Subprocess error matching is inherently brittle ─
# skopeo's error messages are not part of its public API. When this falls
# through to the generic *_FAILED code, the failure still surfaces in
# metrics and alarms; it just loses some specificity in the dashboard.
# That's acceptable: silent classification drift is preferable to silent
# scan failures.
_INSPECT_PATTERNS: list[tuple[list[str], str]] = [
    # skopeo formats vary across versions: "manifest unknown" (1.23+) and
    # "manifest_unknown" (older). Accept both. Same for name_unknown.
    (
        [
            "manifest unknown",
            "manifest_unknown",
            "name unknown",
            "name_unknown",
            "not found",
        ],
        IMAGE_NOT_FOUND,
    ),
    (["denied", "unauthorized"], AUTH_FAILED),
]

_PULL_PATTERNS: list[tuple[list[str], str]] = [
    (["denied", "unauthorized"], AUTH_FAILED),
    (["no space left"], DISK_FULL),
]

_SBOMGEN_PATTERNS: list[tuple[list[str], str]] = [
    (["unsupportedos", "unsupported operating system"], UNSUPPORTED_OS),
    (["unsupportedmediatype", "unsupported image format"], UNSUPPORTED_FORMAT),
]


def _classify(stderr: str, patterns: list[tuple[list[str], str]], fallback: str) -> str:
    stderr_lower = stderr.lower()
    for keywords, error_code in patterns:
        if any(keyword in stderr_lower for keyword in keywords):
            return error_code
    return fallback


def classify_inspect_error(stderr: str) -> str:
    """Classify a ``skopeo inspect`` failure from its stderr output."""
    return _classify(stderr, _INSPECT_PATTERNS, INSPECT_FAILED)


def classify_pull_error(stderr: str) -> str:
    """Classify a ``skopeo copy`` failure from its stderr output."""
    return _classify(stderr, _PULL_PATTERNS, PULL_FAILED)


def classify_sbomgen_error(stderr: str) -> str:
    """Classify an ``inspector-sbomgen`` failure from its stderr output."""
    return _classify(stderr, _SBOMGEN_PATTERNS, SBOMGEN_FAILED)
