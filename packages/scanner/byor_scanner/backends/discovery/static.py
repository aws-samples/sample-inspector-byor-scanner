"""Static discovery backend.

Returns the ``images`` list from the invocation event payload verbatim ─
no external query. Used for direct-invoke / canary / on-demand scans where
the caller supplies the image list in the event payload.

For real fleet discovery, ship a custom backend (see
:class:`~byor_scanner.protocols.DiscoveryBackend`) and select it via
``BYOR_DISCOVERY_BACKEND``.
"""

from __future__ import annotations

from typing import Any

from aws_lambda_powertools import Logger
from opentelemetry import trace

from byor_scanner.constants import SERVICE_DISCOVERY

logger = Logger(service=SERVICE_DISCOVERY)
tracer = trace.get_tracer(__name__)


class StaticDiscovery:
    """Discover images from the event envelope directly.

    Reads ``event["payload"]["images"]`` and returns it as-is. Each entry
    MUST already have ``image`` + ``ref`` keys ─ the discovery handler
    validates this after :meth:`discover` returns.
    """

    @tracer.start_as_current_span("StaticDiscovery.discover")
    def discover(self, event: dict[str, Any]) -> list[dict[str, str]]:
        payload = event.get("payload") or {}
        images = payload.get("images", [])
        logger.info(
            "Static discovery returning images",
            extra={"count": len(images)},
        )
        return images
