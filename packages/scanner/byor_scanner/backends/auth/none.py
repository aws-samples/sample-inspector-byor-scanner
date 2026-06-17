"""No-auth provider for public registries.

For registries that require no client authentication (e.g. public.ecr.aws,
Docker Hub public images). Fetches nothing and emits only the TLS-verify flag;
a per-registry ``insecureTlsVerify`` can still downgrade it via the scanner's
TLS policy.
"""

from __future__ import annotations

from aws_lambda_powertools import Logger
from opentelemetry import trace

from byor_scanner.constants import SERVICE_SCANNER

logger = Logger(service=SERVICE_SCANNER)
tracer = trace.get_tracer(__name__)


class NoAuth:
    """Authenticate to public registries ─ i.e. not at all."""

    @tracer.start_as_current_span("NoAuth.setup")
    def setup(self) -> None:
        # Nothing to fetch or write for a public registry.
        logger.info("NoAuth setup (public registry, no credentials)")

    def get_skopeo_args(self) -> list[str]:
        return ["--tls-verify=true"]
