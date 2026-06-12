"""Tests for the built-in MtlsAuth backend.

Uses ``unittest.mock`` to fake the boto3 Secrets Manager client ─ no
network or AWS account needed.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from byor_scanner.constants import ENV_MTLS_SECRET_NAME
from byor_scanner.errors import AUTH_FAILED, CONFIG_ERROR, ScanError


@pytest.fixture
def cert_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect CERT_DIR to a tmp path for the duration of the test."""
    target = tmp_path / "certs"
    # Patch on the module so the constant captured at import is overridden.
    import byor_scanner.backends.auth.mtls as mtls_mod

    monkeypatch.setattr(mtls_mod, "CERT_DIR", target)
    return target


@pytest.fixture
def fake_secret() -> dict[str, str]:
    # Plain placeholder strings ─ NOT real PEM. The setup() under test only
    # passes secret bytes through to disk, so the PEM envelope is irrelevant
    # for these tests AND saves us from secret-scanner false positives in
    # the public repo.
    return {
        "ca": "fake-ca-content",
        "cert": "fake-cert-content",
        "key": "fake-key-content",
    }


def _build_auth(monkeypatch: pytest.MonkeyPatch, secret_value: str | None) -> object:
    """Construct an MtlsAuth with a mocked Secrets Manager client."""
    from byor_scanner.backends.auth.mtls import MtlsAuth

    auth = MtlsAuth()
    mock_client = MagicMock()
    if secret_value is None:
        mock_client.get_secret_value.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "no"}},
            "GetSecretValue",
        )
    else:
        mock_client.get_secret_value.return_value = {"SecretString": secret_value}
    monkeypatch.setattr(auth, "_sm_client", mock_client)
    return auth


def test_setup_requires_secret_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_MTLS_SECRET_NAME, raising=False)
    auth = _build_auth(monkeypatch, secret_value=None)
    with pytest.raises(ScanError) as exc:
        auth.setup()
    assert exc.value.error_code == CONFIG_ERROR


def test_setup_writes_files_with_strict_perms(
    monkeypatch: pytest.MonkeyPatch,
    cert_dir: Path,
    fake_secret: dict[str, str],
) -> None:
    monkeypatch.setenv(ENV_MTLS_SECRET_NAME, "scanner/mtls")
    auth = _build_auth(monkeypatch, secret_value=json.dumps(fake_secret))
    auth.setup()

    for filename, expected_content_marker in (
        ("ca.crt", "fake-ca-content"),
        ("client.cert", "fake-cert-content"),
        ("client.key", "fake-key-content"),
    ):
        path = cert_dir / filename
        assert path.exists(), f"{filename} not written"
        assert expected_content_marker in path.read_text()
        # 0o600 on every file (not just the key)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600, f"{filename} mode is 0o{mode:o}, expected 0o600"


def test_setup_rejects_missing_field(
    monkeypatch: pytest.MonkeyPatch,
    cert_dir: Path,
    fake_secret: dict[str, str],
) -> None:
    monkeypatch.setenv(ENV_MTLS_SECRET_NAME, "scanner/mtls")
    bad = {**fake_secret, "key": ""}  # empty key field
    auth = _build_auth(monkeypatch, secret_value=json.dumps(bad))
    with pytest.raises(ScanError) as exc:
        auth.setup()
    assert exc.value.error_code == AUTH_FAILED


def test_setup_rejects_secrets_manager_error(
    monkeypatch: pytest.MonkeyPatch,
    cert_dir: Path,
) -> None:
    monkeypatch.setenv(ENV_MTLS_SECRET_NAME, "scanner/mtls")
    auth = _build_auth(monkeypatch, secret_value=None)  # raises ClientError
    with pytest.raises(ScanError) as exc:
        auth.setup()
    assert exc.value.error_code == AUTH_FAILED


def test_setup_rejects_non_json_secret(
    monkeypatch: pytest.MonkeyPatch, cert_dir: Path
) -> None:
    monkeypatch.setenv(ENV_MTLS_SECRET_NAME, "scanner/mtls")
    auth = _build_auth(monkeypatch, secret_value="not-json")
    with pytest.raises(ScanError) as exc:
        auth.setup()
    assert exc.value.error_code == AUTH_FAILED


def test_get_skopeo_args_shape() -> None:
    from byor_scanner.backends.auth.mtls import MtlsAuth

    auth = MtlsAuth()
    args = auth.get_skopeo_args()
    assert any(a.startswith("--cert-dir=") for a in args)
    assert "--tls-verify=true" in args
