"""Tests for the subprocess env allowlist.

The external binaries (skopeo, inspector-sbomgen) process untrusted registry
content and never call AWS APIs, so the Lambda execution role's credentials
must NOT be passed into their environment.
"""

from __future__ import annotations

import os

import pytest

from byor_scanner.subprocess_helpers import _inherited_env


def test_inherited_env_excludes_aws_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # conftest seeds dummy AWS creds; set explicitly here to be self-contained.
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "token")
    monkeypatch.setenv("BYOR_MTLS_SECRET_NAME", "scanner/certs")

    env = _inherited_env()

    assert "AWS_ACCESS_KEY_ID" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "AWS_SESSION_TOKEN" not in env
    # BYOR_* config is read in-process, not by the binaries ─ not passed through.
    assert "BYOR_MTLS_SECRET_NAME" not in env


def test_inherited_env_keeps_path_and_region(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    env = _inherited_env()

    assert env.get("PATH") == os.environ["PATH"]
    assert env.get("AWS_REGION") == "us-west-2"
