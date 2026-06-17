"""Tests for the NoAuth provider (public registries)."""

from __future__ import annotations

from byor_scanner.backends.auth.none import NoAuth


def test_setup_is_noop() -> None:
    # setup() must not raise and needs no env / secret.
    NoAuth().setup()


def test_get_skopeo_args_tls_only() -> None:
    args = NoAuth().get_skopeo_args()
    assert args == ["--tls-verify=true"]
    # No credentials are emitted for a public registry.
    assert not any(
        a.startswith("--creds=") or a.startswith("--cert-dir=") for a in args
    )
