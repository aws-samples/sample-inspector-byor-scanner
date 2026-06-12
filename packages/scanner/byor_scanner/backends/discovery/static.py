"""Static discovery backend.

Returns the ``images`` list from the invocation event payload verbatim ─
no external query. This is the default backend and the one used for
manual / on-demand scans.

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
    """Discover images from the event payload directly.

    Reads ``config["images"]`` and returns it as-is. Each entry MUST
    already have ``image`` + ``ref`` keys ─ the discovery handler
    validates this after :meth:`discover` returns.
    """

    @tracer.start_as_current_span("StaticDiscovery.discover")
    def discover(self, mode: str, config: dict[str, Any]) -> list[dict[str, str]]:
        images = config.get("images", [])
        logger.info(
            "Static discovery returning images",
            extra={"mode": mode, "count": len(images)},
        )
        return images
