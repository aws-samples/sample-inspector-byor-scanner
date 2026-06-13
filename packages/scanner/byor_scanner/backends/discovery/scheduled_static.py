"""Scheduled-static discovery backend.

Trivial plugin paired with :class:`ScheduledTrigger`: returns
``event["payload"]["images"]`` verbatim.

Useful for canaries and simple on-cadence rescans of a fixed list. Customers
who want time-window queries (e.g. "scan everything launched in the last
hour") ship their own :class:`~byor_scanner.protocols.DiscoveryBackend` that
reads ``event["payload"]["window"]`` (or whatever shape they author into
their ``ScheduledTrigger.schedules[].payload``).
"""

from __future__ import annotations

from typing import Any

from aws_lambda_powertools import Logger
from opentelemetry import trace

from byor_scanner.constants import SERVICE_DISCOVERY

logger = Logger(service=SERVICE_DISCOVERY)
tracer = trace.get_tracer(__name__)


class ScheduledStaticDiscovery:
    """Returns the ``images`` list embedded in a schedule's payload."""

    @tracer.start_as_current_span("ScheduledStaticDiscovery.discover")
    def discover(self, event: dict[str, Any]) -> list[dict[str, str]]:
        payload = event.get("payload") or {}
        images = payload.get("images", [])
        logger.info(
            "Scheduled-static discovery returning images",
            extra={"count": len(images)},
        )
        return images
