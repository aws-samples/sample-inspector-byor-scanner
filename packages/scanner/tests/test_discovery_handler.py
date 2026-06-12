"""Tests for the discovery handler.

Covers:
  - manual mode reads images directly from the event payload,
  - mode validation (empty / unknown rejected),
  - image-list validation (cap, missing fields),
  - retry-then-fail when the backend keeps raising,
  - SQS partial-batch failure logging.

The boto3 SQS client is patched on the module after import so we never
hit the network.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def mod(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("BYOR_QUEUE_URL", "https://sqs.example/q")
    monkeypatch.setenv("BYOR_MTLS_SECRET_NAME", "ignored")
    # Re-import a fresh module so the env-var driven module-level state
    # (QUEUE_URL, MAX_DISCOVERED) reflects the test setup.
    import importlib

    import byor_scanner.discovery_handler as m

    importlib.reload(m)
    fake_sqs = MagicMock()
    fake_sqs.send_message_batch.return_value = {"Failed": []}
    monkeypatch.setattr(m, "sqs_client", fake_sqs)
    return m


def _ctx() -> Any:
    return MagicMock(aws_request_id="rid", function_name="fn")


def test_handler_rejects_missing_mode(mod: Any) -> None:
    with pytest.raises(Exception) as exc:
        mod.handler({}, _ctx())
    assert "mode" in str(exc.value)


def test_handler_rejects_unknown_mode(mod: Any) -> None:
    with pytest.raises(Exception) as exc:
        mod.handler({"mode": "manaul"}, _ctx())
    assert "Unknown mode" in str(exc.value)


def test_manual_mode_enqueues_images(mod: Any) -> None:
    event = {
        "mode": "manual",
        "images": [
            {"image": "library/nginx", "ref": "1.25"},
            {"image": "myorg/app", "ref": "sha256:" + "a" * 64},
        ],
    }
    result = mod.handler(event, _ctx())
    assert result == {"mode": "manual", "imagesEnqueued": 2}
    mod.sqs_client.send_message_batch.assert_called_once()
    sent_entries = mod.sqs_client.send_message_batch.call_args.kwargs["Entries"]
    assert len(sent_entries) == 2


def test_manual_mode_with_zero_images_returns_zero(mod: Any) -> None:
    result = mod.handler({"mode": "manual", "images": []}, _ctx())
    assert result == {"mode": "manual", "imagesEnqueued": 0}
    mod.sqs_client.send_message_batch.assert_not_called()


def test_validation_rejects_missing_ref(mod: Any) -> None:
    event = {
        "mode": "manual",
        "images": [{"image": "library/nginx"}],  # ref missing
    }
    with pytest.raises(Exception) as exc:
        mod.handler(event, _ctx())
    assert "ref" in str(exc.value)


def test_validation_caps_oversized_lists(
    mod: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mod, "MAX_DISCOVERED", 5)
    event = {
        "mode": "manual",
        "images": [{"image": "x/y", "ref": str(i)} for i in range(10)],
    }
    with pytest.raises(Exception) as exc:
        mod.handler(event, _ctx())
    assert "exceeds cap" in str(exc.value)


def test_backend_retries_then_fails(
    mod: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_backend = MagicMock()
    fake_backend.discover.side_effect = RuntimeError("boom")
    monkeypatch.setattr(mod, "discovery", fake_backend)
    monkeypatch.setattr(mod, "BASE_BACKOFF", 0)  # no actual sleep
    with pytest.raises(Exception) as exc:
        mod.handler({"mode": "hourly"}, _ctx())
    assert "after" in str(exc.value).lower()
    # Three attempts (default MAX_RETRIES=3)
    assert fake_backend.discover.call_count == 3


def test_hourly_mode_uses_backend_result(
    mod: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_backend = MagicMock()
    fake_backend.discover.return_value = [
        {"image": "library/nginx", "ref": "v1"},
    ]
    monkeypatch.setattr(mod, "discovery", fake_backend)
    result = mod.handler({"mode": "hourly", "config": {"window": "1h"}}, _ctx())
    assert result == {"mode": "hourly", "imagesEnqueued": 1}
    fake_backend.discover.assert_called_once_with("hourly", {"window": "1h"})


def test_partial_sqs_failure_is_logged_and_counted(
    mod: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod.sqs_client.send_message_batch.return_value = {
        "Failed": [{"Id": "0", "Code": "ServiceUnavailable", "Message": "..."}],
        "Successful": [{"Id": "1"}],
    }
    event = {
        "mode": "manual",
        "images": [
            {"image": "library/nginx", "ref": "v1"},
            {"image": "library/redis", "ref": "v2"},
        ],
    }
    result = mod.handler(event, _ctx())
    # Two attempts, one failed → one enqueued
    assert result == {"mode": "manual", "imagesEnqueued": 1}


def test_static_discovery_returns_payload_images() -> None:
    from byor_scanner.backends.discovery.static import StaticDiscovery

    backend = StaticDiscovery()
    images = [{"image": "library/nginx", "ref": "v1"}]
    assert backend.discover("manual", {"images": images}) == images
    assert backend.discover("manual", {}) == []
