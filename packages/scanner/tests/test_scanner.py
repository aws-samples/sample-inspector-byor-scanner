"""Tests for the scanner handler's per-registry resolution.

Covers:
  - a message's ``registry`` id selects that registry's URL + auth,
  - a message with no ``registry`` falls back to ``"default"``,
  - ``auth.setup()`` runs lazily ─ once per *referenced* registry per
    invocation, never for registries the batch doesn't touch,
  - an unknown registry id surfaces ``UNKNOWN_REGISTRY`` and the message is
    reported as a batch-item failure (not a hard handler crash).

The auth providers are tiny in-test fakes selected via ``BYOR_REGISTRIES``;
``scan_image`` is patched so no skopeo/sbomgen/AWS calls happen.
"""

from __future__ import annotations

import importlib
import json
from typing import Any
from unittest.mock import MagicMock

import pytest

# Per-registry setup() call counts, keyed by the env-var marker each fake
# AuthProvider carries. Reset by the `scanner` fixture before each test.
SETUP_CALLS: dict[str, int] = {}


class _RecordingAuth:
    """Base fake AuthProvider. Subclasses set a distinct ``MARKER``."""

    MARKER = "base"

    def setup(self) -> None:
        SETUP_CALLS[self.MARKER] = SETUP_CALLS.get(self.MARKER, 0) + 1

    def get_skopeo_args(self) -> list[str]:
        return [f"--creds=user:{self.MARKER}", "--tls-verify=true"]


class ProdAuth(_RecordingAuth):
    MARKER = "prod"


class StagingAuth(_RecordingAuth):
    MARKER = "staging"


_REGISTRIES = {
    "prod": {
        "url": "prod.example.com",
        "authProvider": f"{__name__}.ProdAuth",
        "authEnv": {"BYOR_MTLS_SECRET_NAME": "scanner/prod"},
    },
    "staging": {
        "url": "staging.example.com",
        "authProvider": f"{__name__}.StagingAuth",
        "authEnv": {"BYOR_MTLS_SECRET_NAME": "scanner/stg"},
    },
}


def _reload_scanner(monkeypatch: pytest.MonkeyPatch, registries: Any) -> Any:
    """Reload config + scanner with the given BYOR_REGISTRIES, patch scan_image."""
    SETUP_CALLS.clear()
    if registries is None:
        monkeypatch.delenv("BYOR_REGISTRIES", raising=False)
    else:
        monkeypatch.setenv("BYOR_REGISTRIES", json.dumps(registries))

    import byor_scanner.config as cfg

    importlib.reload(cfg)

    import byor_scanner.scanner as scanner

    importlib.reload(scanner)
    monkeypatch.setattr(scanner, "scan_image", MagicMock())
    return scanner


def _sqs_event(*bodies: dict[str, Any]) -> dict[str, Any]:
    return {
        "Records": [
            {"messageId": str(i), "body": json.dumps(b), "attributes": {}}
            for i, b in enumerate(bodies)
        ]
    }


def _ctx() -> Any:
    return MagicMock(aws_request_id="rid", function_name="fn")


def _scan_one(scanner: Any, **body: Any) -> dict[str, Any]:
    """Drive the handler with a single-message SQS batch."""
    return scanner.handler(_sqs_event(body), _ctx())


@pytest.fixture
def scanner(monkeypatch: pytest.MonkeyPatch) -> Any:
    return _reload_scanner(monkeypatch, _REGISTRIES)


def test_message_registry_selects_url_and_auth(scanner: Any) -> None:
    _scan_one(scanner, image="a/b", ref="v1", registry="prod")
    req = scanner.scan_image.call_args.args[0]
    assert req.registry == "prod.example.com"
    assert req.registry_id == "prod"
    assert "--creds=user:prod" in req.auth_args


def test_missing_registry_falls_back_to_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No BYOR_REGISTRIES + legacy env → synthesized "default" registry.
    monkeypatch.setenv("BYOR_REGISTRY_URL", "legacy.example.com")
    monkeypatch.setenv("BYOR_MTLS_SECRET_NAME", "scanner/legacy")
    monkeypatch.setenv("BYOR_AUTH_PROVIDER", f"{__name__}.ProdAuth")
    s = _reload_scanner(monkeypatch, None)
    _scan_one(s, image="a/b", ref="v1")
    req = s.scan_image.call_args.args[0]
    assert req.registry == "legacy.example.com"
    assert req.registry_id == "default"


def test_untagged_message_uses_sole_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    # One registry, NOT named "default": an untagged message should use it
    # (the sole registry is the implicit default).
    registries = {
        "prod": {
            "url": "prod.example.com",
            "authProvider": f"{__name__}.ProdAuth",
            "authEnv": {"BYOR_MTLS_SECRET_NAME": "scanner/prod"},
        },
    }
    s = _reload_scanner(monkeypatch, registries)
    _scan_one(s, image="a/b", ref="v1")  # no registry field
    req = s.scan_image.call_args.args[0]
    assert req.registry_id == "prod"
    assert req.registry == "prod.example.com"


def test_untagged_message_ambiguous_with_multiple_registries(scanner: Any) -> None:
    # Two registries (prod + staging), neither named "default": an untagged
    # message is ambiguous → UNKNOWN_REGISTRY → batch-item failure, not a guess.
    result = _scan_one(scanner, image="a/b", ref="v1")  # no registry field
    assert result == {"batchItemFailures": [{"itemIdentifier": "0"}]}
    scanner.scan_image.assert_not_called()


def test_named_default_wins_over_sole_heuristic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # When a "default" registry exists alongside others, untagged → "default".
    registries = {
        "default": {
            "url": "default.example.com",
            "authProvider": f"{__name__}.ProdAuth",
            "authEnv": {"BYOR_MTLS_SECRET_NAME": "scanner/def"},
        },
        "staging": {
            "url": "staging.example.com",
            "authProvider": f"{__name__}.StagingAuth",
            "authEnv": {"BYOR_MTLS_SECRET_NAME": "scanner/stg"},
        },
    }
    s = _reload_scanner(monkeypatch, registries)
    _scan_one(s, image="a/b", ref="v1")
    req = s.scan_image.call_args.args[0]
    assert req.registry_id == "default"


def test_setup_is_lazy_once_per_referenced_registry(scanner: Any) -> None:
    # Batch: two prod messages + one staging message; staging referenced once.
    scanner.handler(
        _sqs_event(
            {"image": "a/b", "ref": "v1", "registry": "prod"},
            {"image": "c/d", "ref": "v2", "registry": "prod"},
            {"image": "e/f", "ref": "v3", "registry": "staging"},
        ),
        _ctx(),
    )
    # setup() runs once per *distinct* referenced registry, not per message.
    assert SETUP_CALLS == {"prod": 1, "staging": 1}
    assert scanner.scan_image.call_count == 3

    # Each message must route to its OWN registry's url + auth (not all to one).
    reqs = [c.args[0] for c in scanner.scan_image.call_args_list]
    assert [r.registry_id for r in reqs] == ["prod", "prod", "staging"]
    assert reqs[0].registry == "prod.example.com"
    assert reqs[2].registry == "staging.example.com"
    assert "--creds=user:prod" in reqs[1].auth_args
    assert "--creds=user:staging" in reqs[2].auth_args


def test_unreferenced_registry_is_not_setup(scanner: Any) -> None:
    _scan_one(scanner, image="a/b", ref="v1", registry="prod")
    assert SETUP_CALLS == {"prod": 1}
    assert "staging" not in SETUP_CALLS


def test_unknown_registry_reports_failure(scanner: Any) -> None:
    result = _scan_one(scanner, image="a/b", ref="v1", registry="nope")
    assert result == {"batchItemFailures": [{"itemIdentifier": "0"}]}
    # The unknown registry is never scanned and no setup runs.
    scanner.scan_image.assert_not_called()
    assert SETUP_CALLS == {}


# cert dir a fake auth points skopeo at; the handler must shred it end of batch.
_CERT_DIR: dict[str, str] = {}


class CertDirAuth(_RecordingAuth):
    MARKER = "certdir"

    def get_skopeo_args(self) -> list[str]:
        return [f"--cert-dir={_CERT_DIR['path']}", "--tls-verify=true"]


def test_handler_shreds_declared_cert_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    (cert_dir / "client.key").write_text("secret")
    _CERT_DIR["path"] = str(cert_dir)

    scanner = _reload_scanner(
        monkeypatch,
        {
            "default": {
                "url": "r.example.com",
                "authProvider": f"{__name__}.CertDirAuth",
                "authEnv": {},
            }
        },
    )
    scanner.handler(_sqs_event({"image": "a/b", "ref": "v1"}), _ctx())

    assert not cert_dir.exists()  # shredded after the batch


def test_auth_env_applied_before_setup(scanner: Any) -> None:
    import os

    captured: dict[str, str] = {}

    def _capture(self: Any) -> None:  # noqa: ANN401
        captured[self.MARKER] = os.environ.get("BYOR_MTLS_SECRET_NAME", "")
        _RecordingAuth.setup(self)

    # Patch the prod provider's setup to record the env it sees.
    scanner.auth_by_registry["prod"].setup = _capture.__get__(
        scanner.auth_by_registry["prod"]
    )
    _scan_one(scanner, image="a/b", ref="v1", registry="prod")
    assert captured["prod"] == "scanner/prod"


def test_apply_tls_policy_forces_insecure(scanner: Any) -> None:
    # insecure=True replaces the provider's --tls-verify=true with =false.
    args = scanner._apply_tls_policy(
        ["--creds=user:prod", "--tls-verify=true"], True
    )
    assert "--tls-verify=false" in args
    assert "--tls-verify=true" not in args
    assert "--creds=user:prod" in args


def test_apply_tls_policy_secure_is_noop(scanner: Any) -> None:
    original = ["--creds=user:prod", "--tls-verify=true"]
    assert scanner._apply_tls_policy(original, False) == original


def test_insecure_registry_flips_tls_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    registries = {
        "selfsigned": {
            "url": "selfsigned.example.com",
            "authProvider": f"{__name__}.ProdAuth",
            "authEnv": {"BYOR_MTLS_SECRET_NAME": "scanner/ss"},
            "insecureTlsVerify": True,
        },
    }
    s = _reload_scanner(monkeypatch, registries)
    _scan_one(s, image="a/b", ref="v1", registry="selfsigned")
    req = s.scan_image.call_args.args[0]
    assert "--tls-verify=false" in req.auth_args
    assert "--tls-verify=true" not in req.auth_args


def test_insecure_tls_survives_src_arg_translation(scanner: Any) -> None:
    # The insecure --tls-verify=false must translate to --src-tls-verify=false
    # for `skopeo copy` (scan.py:_to_src_args), not be rejected as an unknown
    # flag. Proves the scanner→scan composition end-to-end.
    from byor_scanner import scan

    insecure_args = scanner._apply_tls_policy(
        ["--cert-dir=/tmp/certs/x", "--tls-verify=true"], True
    )
    src_args = scan._to_src_args(insecure_args)
    assert "--src-tls-verify=false" in src_args
    assert "--src-tls-verify=true" not in src_args


def test_unknown_auth_flag_rejected_on_both_paths() -> None:
    # A rogue auth provider flag must be rejected for `inspect` (raw args) as
    # well as `copy` (--src-* translation), so the allowlist is symmetric.
    from byor_scanner import scan
    from byor_scanner.errors import CONFIG_ERROR, ScanError

    with pytest.raises(ScanError) as copy_err:
        scan._to_src_args(["--dest-creds=evil"])
    assert copy_err.value.error_code == CONFIG_ERROR

    with pytest.raises(ScanError) as inspect_err:
        scan._reject_unknown_flag("--dest-creds=evil")
    assert inspect_err.value.error_code == CONFIG_ERROR

    # Known auth flags pass the gate unharmed.
    scan._reject_unknown_flag("--creds=user:pass")
    scan._reject_unknown_flag("--tls-verify=true")
    scan._reject_unknown_flag("--authfile=/tmp/auth.json")
