"""Smoke test: handlers import cleanly."""

from byor_scanner import pusher, scanner


def test_pusher_handler_exists() -> None:
    assert callable(pusher.handler)


def test_scanner_handler_exists() -> None:
    assert callable(scanner.handler)
