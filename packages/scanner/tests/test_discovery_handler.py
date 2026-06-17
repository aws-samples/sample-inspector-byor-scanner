"""Tests for the discovery handler.

Covers:
  - the ``{source, payload}`` envelope is built from raw events,
  - per-event ``source`` overrides the ``BYOR_TRIGGER_SOURCE`` env-var default,
  - image-list validation (cap, missing fields),
  - retry-then-fail when the backend keeps raising,
  - SQS partial-batch failure: transient is retried+recovered, persistent
    raises ENQUEUE_FAILED so the cycle re-fires,
  - SQS message body carries ``source`` (not legacy ``mode``).

The boto3 SQS client is patched on the module after import so we never
hit the network.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def mod(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("BYOR_QUEUE_URL", "https://sqs.example/q")
    monkeypatch.setenv("BYOR_MTLS_SECRET_NAME", "ignored")
    monkeypatch.setenv("BYOR_TRIGGER_SOURCE", "TestTrigger")
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


def test_raw_event_uses_env_source_and_treats_event_as_payload(
    mod: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_backend = MagicMock()
    fake_backend.discover.return_value = [
        {"image": "library/nginx", "ref": "1.25"},
    ]
    monkeypatch.setattr(mod, "discovery", fake_backend)
    raw = {"images": [{"image": "library/nginx", "ref": "1.25"}]}
    result = mod.handler(raw, _ctx())
    assert result == {"source": "TestTrigger", "imagesEnqueued": 1}
    # Plugin sees the envelope, with the raw event as payload.
    fake_backend.discover.assert_called_once_with(
        {"source": "TestTrigger", "payload": raw}
    )


def test_event_source_overrides_env_default(
    mod: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_backend = MagicMock()
    fake_backend.discover.return_value = [
        {"image": "library/nginx", "ref": "v1"},
    ]
    monkeypatch.setattr(mod, "discovery", fake_backend)
    event = {"source": "Hourly", "payload": {"window": "PT1H"}}
    result = mod.handler(event, _ctx())
    assert result == {"source": "Hourly", "imagesEnqueued": 1}
    fake_backend.discover.assert_called_once_with(event)


def test_default_source_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BYOR_QUEUE_URL", "https://sqs.example/q")
    monkeypatch.delenv("BYOR_TRIGGER_SOURCE", raising=False)
    import importlib

    import byor_scanner.discovery_handler as m

    importlib.reload(m)
    fake_sqs = MagicMock()
    fake_sqs.send_message_batch.return_value = {"Failed": []}
    monkeypatch.setattr(m, "sqs_client", fake_sqs)
    fake_backend = MagicMock()
    fake_backend.discover.return_value = [{"image": "x/y", "ref": "v1"}]
    monkeypatch.setattr(m, "discovery", fake_backend)
    result = m.handler({}, _ctx())
    assert result == {"source": "unknown", "imagesEnqueued": 1}


def test_sqs_message_carries_source_not_mode(
    mod: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_backend = MagicMock()
    fake_backend.discover.return_value = [{"image": "x/y", "ref": "v1"}]
    monkeypatch.setattr(mod, "discovery", fake_backend)
    mod.handler({"source": "Cron-12h", "payload": {}}, _ctx())
    sent_entries = mod.sqs_client.send_message_batch.call_args.kwargs["Entries"]
    body = json.loads(sent_entries[0]["MessageBody"])
    assert body["source"] == "Cron-12h"
    assert "mode" not in body
    # No backend-supplied registry → the key is omitted; the scanner resolves
    # the default (a registry named "default", or the sole configured one).
    assert "registry" not in body


def test_sqs_message_carries_backend_registry(
    mod: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_backend = MagicMock()
    fake_backend.discover.return_value = [
        {"image": "x/y", "ref": "v1", "registry": "prod"},
    ]
    monkeypatch.setattr(mod, "discovery", fake_backend)
    mod.handler({"source": "Cron-12h", "payload": {}}, _ctx())
    sent_entries = mod.sqs_client.send_message_batch.call_args.kwargs["Entries"]
    body = json.loads(sent_entries[0]["MessageBody"])
    assert body["registry"] == "prod"


def test_validation_rejects_invalid_registry(
    mod: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_backend = MagicMock()
    fake_backend.discover.return_value = [
        {"image": "x/y", "ref": "v1", "registry": ""},
    ]
    monkeypatch.setattr(mod, "discovery", fake_backend)
    with pytest.raises(Exception) as exc:
        mod.handler({"payload": {}}, _ctx())
    assert "registry" in str(exc.value)


def test_zero_images_does_not_call_sqs(
    mod: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_backend = MagicMock()
    fake_backend.discover.return_value = []
    monkeypatch.setattr(mod, "discovery", fake_backend)
    result = mod.handler({"source": "Manual", "payload": {}}, _ctx())
    assert result == {"source": "Manual", "imagesEnqueued": 0}
    mod.sqs_client.send_message_batch.assert_not_called()


def test_validation_rejects_missing_ref(
    mod: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_backend = MagicMock()
    fake_backend.discover.return_value = [{"image": "library/nginx"}]
    monkeypatch.setattr(mod, "discovery", fake_backend)
    with pytest.raises(Exception) as exc:
        mod.handler({"payload": {}}, _ctx())
    assert "ref" in str(exc.value)


def test_validation_caps_oversized_lists(
    mod: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mod, "MAX_DISCOVERED", 5)
    fake_backend = MagicMock()
    fake_backend.discover.return_value = [
        {"image": "x/y", "ref": str(i)} for i in range(10)
    ]
    monkeypatch.setattr(mod, "discovery", fake_backend)
    with pytest.raises(Exception) as exc:
        mod.handler({"payload": {}}, _ctx())
    assert "exceeds cap" in str(exc.value)


def test_backend_retries_then_fails(
    mod: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_backend = MagicMock()
    fake_backend.discover.side_effect = RuntimeError("boom")
    monkeypatch.setattr(mod, "discovery", fake_backend)
    monkeypatch.setattr(mod, "BASE_BACKOFF", 0)  # no actual sleep
    with pytest.raises(Exception) as exc:
        mod.handler({"source": "Hourly", "payload": {}}, _ctx())
    assert "after" in str(exc.value).lower()
    # Three attempts (default MAX_RETRIES=3)
    assert fake_backend.discover.call_count == 3


def test_transient_partial_sqs_failure_is_retried_and_recovered(
    mod: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)  # no real backoff
    fake_backend = MagicMock()
    fake_backend.discover.return_value = [
        {"image": "library/nginx", "ref": "v1"},
        {"image": "library/redis", "ref": "v2"},
    ]
    monkeypatch.setattr(mod, "discovery", fake_backend)
    # First send: entry "0" fails transiently; retry of just "0" succeeds.
    mod.sqs_client.send_message_batch.side_effect = [
        {"Failed": [{"Id": "0", "Code": "ServiceUnavailable", "Message": "..."}],
         "Successful": [{"Id": "1"}]},
        {"Failed": [], "Successful": [{"Id": "0"}]},
    ]
    result = mod.handler({"source": "Cron", "payload": {"images": []}}, _ctx())
    # Both images end up enqueued; the retry re-sent ONLY the failed entry.
    assert result == {"source": "Cron", "imagesEnqueued": 2}
    second_call = mod.sqs_client.send_message_batch.call_args_list[1]
    resent_ids = [e["Id"] for e in second_call.kwargs["Entries"]]
    assert resent_ids == ["0"]


def test_persistent_partial_sqs_failure_raises_enqueue_failed(
    mod: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)
    fake_backend = MagicMock()
    fake_backend.discover.return_value = [
        {"image": "library/nginx", "ref": "v1"},
        {"image": "library/redis", "ref": "v2"},
    ]
    monkeypatch.setattr(mod, "discovery", fake_backend)
    # Entry "0" fails on every attempt → dropped after retries.
    mod.sqs_client.send_message_batch.return_value = {
        "Failed": [{"Id": "0", "Code": "ServiceUnavailable", "Message": "..."}],
        "Successful": [{"Id": "1"}],
    }
    # Spy on single_metric to prove the drop surfaces as ImagesEnqueueFailed.
    metric_names: list[str] = []
    real_single_metric = mod.single_metric

    def _spy(**kwargs: Any) -> Any:
        metric_names.append(kwargs.get("name"))
        return real_single_metric(**kwargs)

    monkeypatch.setattr(mod, "single_metric", _spy)

    # The cycle fails loudly so the trigger re-fires (no silent drop).
    with pytest.raises(mod.ScanError) as exc:
        mod.handler({"source": "Cron", "payload": {"images": []}}, _ctx())
    assert exc.value.error_code == "ENQUEUE_FAILED"
    assert "ImagesEnqueueFailed" in metric_names


def test_static_discovery_returns_payload_images() -> None:
    from byor_scanner.backends.discovery.static import StaticDiscovery

    backend = StaticDiscovery()
    images = [{"image": "library/nginx", "ref": "v1"}]
    assert backend.discover({"payload": {"images": images}}) == images
    assert backend.discover({"payload": {}}) == []
    assert backend.discover({}) == []
