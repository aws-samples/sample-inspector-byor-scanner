"""Tests for the S3-manifest discovery backend."""

from __future__ import annotations

import io
import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError


def _backend(monkeypatch: pytest.MonkeyPatch, get_object: Any) -> Any:
    from byor_scanner.backends.discovery import s3_manifest

    backend = s3_manifest.S3ManifestDiscovery()
    fake_s3 = MagicMock()
    fake_s3.get_object.side_effect = get_object
    monkeypatch.setattr(backend, "_s3", fake_s3)
    return backend


def _record(bucket: str, key: str) -> dict[str, Any]:
    return {
        "s3": {"bucket": {"name": bucket}, "object": {"key": key}},
        "eventName": "ObjectCreated:Put",
    }


def _body(payload: Any) -> dict[str, Any]:
    return {"Body": io.BytesIO(json.dumps(payload).encode())}


def test_empty_records_returns_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _backend(monkeypatch, get_object=lambda **_: _body([]))
    assert backend.discover({"payload": {"Records": []}}) == []


def test_no_payload_returns_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _backend(monkeypatch, get_object=lambda **_: _body([]))
    assert backend.discover({}) == []


def test_happy_path_returns_manifest(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = [
        {"image": "library/nginx", "ref": "1.25"},
        {"image": "myorg/api", "ref": "sha256:abc"},
    ]
    backend = _backend(monkeypatch, get_object=lambda **_: _body(manifest))
    images = backend.discover(
        {"payload": {"Records": [_record("b", "manifests/x.json")]}}
    )
    assert images == manifest


def test_url_encoded_keys_are_decoded(monkeypatch: pytest.MonkeyPatch) -> None:
    seen_key: dict[str, str] = {}

    def get_object(**kwargs: Any) -> dict[str, Any]:
        seen_key["key"] = kwargs["Key"]
        return _body([])

    backend = _backend(monkeypatch, get_object=get_object)
    encoded = "manifests%2Fnested%20path%2Fdata.json"
    backend.discover({"payload": {"Records": [_record("b", encoded)]}})
    assert seen_key["key"] == "manifests/nested path/data.json"


def test_missing_bucket_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _backend(monkeypatch, get_object=lambda **_: _body([]))
    with pytest.raises(Exception) as exc:
        backend.discover(
            {
                "payload": {
                    "Records": [
                        {"s3": {"bucket": {}, "object": {"key": "k"}}},
                    ]
                }
            }
        )
    assert "bucket" in str(exc.value).lower()


def test_missing_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _backend(monkeypatch, get_object=lambda **_: _body([]))
    with pytest.raises(Exception) as exc:
        backend.discover(
            {
                "payload": {
                    "Records": [
                        {"s3": {"bucket": {"name": "b"}, "object": {}}},
                    ]
                }
            }
        )
    assert "key" in str(exc.value).lower()


def test_get_object_failure_raises_discovery_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(**_: Any) -> Any:
        raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetObject")

    backend = _backend(monkeypatch, get_object=boom)
    with pytest.raises(Exception) as exc:
        backend.discover(
            {"payload": {"Records": [_record("b", "manifests/x.json")]}}
        )
    assert "Failed to read manifest" in str(exc.value)


def test_malformed_json_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def bad_json(**_: Any) -> dict[str, Any]:
        return {"Body": io.BytesIO(b"{not json")}

    backend = _backend(monkeypatch, get_object=bad_json)
    with pytest.raises(Exception) as exc:
        backend.discover(
            {"payload": {"Records": [_record("b", "manifests/x.json")]}}
        )
    assert "valid JSON" in str(exc.value)


def test_non_array_manifest_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = _backend(
        monkeypatch, get_object=lambda **_: _body({"images": []})
    )
    with pytest.raises(Exception) as exc:
        backend.discover(
            {"payload": {"Records": [_record("b", "manifests/x.json")]}}
        )
    assert "must be a JSON array" in str(exc.value)


def test_multi_record_concatenates(monkeypatch: pytest.MonkeyPatch) -> None:
    manifests = {
        "manifests/a.json": [{"image": "a/a", "ref": "v1"}],
        "manifests/b.json": [
            {"image": "b/b", "ref": "v2"},
            {"image": "c/c", "ref": "v3"},
        ],
    }

    def get_object(**kwargs: Any) -> dict[str, Any]:
        return _body(manifests[kwargs["Key"]])

    backend = _backend(monkeypatch, get_object=get_object)
    images = backend.discover(
        {
            "payload": {
                "Records": [
                    _record("b", "manifests/a.json"),
                    _record("b", "manifests/b.json"),
                ]
            }
        }
    )
    assert images == [
        {"image": "a/a", "ref": "v1"},
        {"image": "b/b", "ref": "v2"},
        {"image": "c/c", "ref": "v3"},
    ]
