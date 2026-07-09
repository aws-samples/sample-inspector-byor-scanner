"""Image / ref validation against the OCI distribution spec.

We validate inputs strictly because both halves end up on a subprocess
command line as part of an interpolated URL. A sloppy regex would accept
``../../etc`` as a "ref" and let it leak into the skopeo invocation.

References:
  - https://github.com/distribution/reference (Go reference grammar; we
    mirror the structure but skip the registry-host parsing because the
    scanner gets the registry from config, not user input).
"""

from __future__ import annotations

import os
import re

from byor_scanner.constants import (
    DEFAULT_ALLOWED_SOURCE_TYPES,
    ENV_ALLOWED_SOURCE_TYPES,
)
from byor_scanner.errors import INVALID_INPUT, ScanError

# Repository name component grammar from the Distribution reference grammar.
# A component is a lowercase alphanumeric run with optional separators.
# Components are joined by '/'.
_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*"
_REPOSITORY_RE = re.compile(rf"^{_COMPONENT}(?:/{_COMPONENT})*$")

# Tag grammar: 1-128 chars, must start with alnum, then alnum/_/./-.
_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")

# Digest grammar: algo ":" hex; we accept sha256/sha512 with their
# canonical hex lengths.
_DIGEST_RE = re.compile(r"^sha(?:256:[A-Fa-f0-9]{64}|512:[A-Fa-f0-9]{128})$")

# Hard length cap. The Distribution spec doesn't pin one but real
# registries tend to choke past a few hundred chars; this is also a
# defense-in-depth limit on the subprocess command-line size.
_MAX_REPOSITORY_LEN = 255
_MAX_REF_LEN = 255

# sourceType is a manifest field that becomes a findings S3 key segment; keep
# it a flat token so it can't reshape the key path.
_SOURCE_TYPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def validate_image_name(image: str) -> None:
    """Raise ``ScanError(INVALID_INPUT)`` if ``image`` is not a valid
    OCI repository path.

    Accepts forms like ``library/nginx``, ``myorg/team/service``.
    Rejects empty strings, paths with ``..``, uppercase letters, or
    other characters that would alter the meaning of the ``docker://``
    URL the scanner builds from this value.
    """
    if not image:
        raise ScanError(INVALID_INPUT, "Image name is empty")
    if len(image) > _MAX_REPOSITORY_LEN:
        raise ScanError(
            INVALID_INPUT, f"Image name exceeds {_MAX_REPOSITORY_LEN} characters"
        )
    if ".." in image:
        raise ScanError(INVALID_INPUT, f"Image name contains '..': {image!r}")
    if not _REPOSITORY_RE.match(image):
        raise ScanError(
            INVALID_INPUT,
            f"Image name {image!r} does not match the OCI repository grammar",
        )


def validate_ref(ref: str) -> None:
    """Raise ``ScanError(INVALID_INPUT)`` if ``ref`` is neither a valid
    OCI tag nor a valid digest.
    """
    if not ref:
        raise ScanError(INVALID_INPUT, "Ref is empty")
    if len(ref) > _MAX_REF_LEN:
        raise ScanError(INVALID_INPUT, f"Ref exceeds {_MAX_REF_LEN} characters")
    if ref.startswith("sha"):
        if not _DIGEST_RE.match(ref):
            raise ScanError(
                INVALID_INPUT,
                f"Ref {ref!r} starts with 'sha' but is not a valid digest",
            )
        return
    if not _TAG_RE.match(ref):
        raise ScanError(
            INVALID_INPUT, f"Ref {ref!r} does not match the OCI tag grammar"
        )


def _allowed_source_types() -> frozenset[str]:
    """Allowlist from ``BYOR_ALLOWED_SOURCE_TYPES``, else the default."""
    raw = os.environ.get(ENV_ALLOWED_SOURCE_TYPES, "")
    values = [v.strip() for v in raw.split(",") if v.strip()] or list(
        DEFAULT_ALLOWED_SOURCE_TYPES
    )
    return frozenset(values)


def validate_source_type(source_type: str) -> None:
    """Raise ``ScanError(INVALID_INPUT)`` unless ``source_type`` is on the
    allowlist and a flat token (it becomes a findings S3 key segment)."""
    allowed = _allowed_source_types()
    if source_type not in allowed:
        raise ScanError(
            INVALID_INPUT,
            f"sourceType {source_type!r} is not allowed; "
            f"permitted values: {sorted(allowed)}",
        )
    if not _SOURCE_TYPE_RE.match(source_type):
        raise ScanError(
            INVALID_INPUT,
            f"sourceType {source_type!r} must be a flat token "
            "([A-Za-z0-9][A-Za-z0-9._-]{0,63}); no '/' or '..'",
        )
