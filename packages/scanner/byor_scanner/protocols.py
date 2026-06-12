"""Plugin protocols ─ the contracts that auth and discovery backends implement.

Custom plugins live in their own module (often delivered as a Lambda Layer)
and only need a class with matching method signatures. They do **not** need
to import this module ─ duck-typing via ``@runtime_checkable`` is enough.

## Logging contract

Every plugin method MUST emit structured JSON log lines on entry, exit, and
error. The recommended logger is ``aws_lambda_powertools.Logger``, which the
host Lambdas use. Each log line should include enough context that an
operator can answer "why did this method behave this way?" from CloudWatch
Logs Insights ─ at minimum the method name, the inputs that drove behavior,
and on error a typed ``errorCode`` matching the alarm dimensions defined in
the observability layer.

## Tracing contract

The host Lambdas use OpenTelemetry via the AWS Distro for OpenTelemetry
(ADOT) Lambda layer. The layer's exec wrapper auto-creates a root span
around the Lambda invocation and auto-instruments boto3 / requests /
urllib3. As a result:

  - Any boto3 / requests / urllib3 call from a plugin produces an OTel
    span under the parent invocation span automatically. **No plugin
    code needed.**
  - Plugins that want custom spans around their own logic SHOULD use the
    OpenTelemetry API directly::

        from opentelemetry import trace

        tracer = trace.get_tracer(__name__)

        class MyDiscovery:
            @tracer.start_as_current_span("MyDiscovery.discover")
            def discover(self, mode, config):
                trace.get_current_span().set_attribute("mode", mode)
                ...

  - The trace context is ambient (OTel reads it from the OTLP-aware
    Lambda exec wrapper and stores it in a context-var). Plugins do not
    receive a trace ID parameter and do not need to thread one through.
    HTTP calls to downstream services join the trace automatically once
    the relevant instrumentation library is installed.

## Backwards compatibility

Method signatures here are part of the public extension contract. Adding a
new method or renaming an argument is a breaking change for every customer
shipping their own backend.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class DiscoveryBackend(Protocol):
    """Discovers container images to scan.

    Implementations query the customer's deployment system (a container
    orchestration database, a Harbor / GitLab API, an S3 manifest, ...) and
    return a list of image references.

    ## Return value

    Each returned dict MUST contain:

      - ``image`` (str): repository path (e.g. ``"myapp/web"``,
        ``"library/nginx"``). Excludes the registry hostname.
      - ``ref`` (str): tag or digest (e.g. ``"latest"``, ``"v2.1"``,
        ``"sha256:abc..."``).

    ## Writing a custom backend

    A custom backend is a plain class with a single method::

        # my_backend.py (delivered via a Lambda Layer at /opt/python/)
        from typing import Any
        from aws_lambda_powertools import Logger
        from opentelemetry import trace

        logger = Logger()
        tracer = trace.get_tracer(__name__)

        class HarborDiscovery:
            \"\"\"Discover images by querying a Harbor instance.\"\"\"

            @tracer.start_as_current_span("HarborDiscovery.discover")
            def discover(
                self, mode: str, config: dict[str, Any]
            ) -> list[dict[str, str]]:
                logger.info("Discovery starting", extra={"mode": mode})
                images = []
                # ... call Harbor API, build the list ...
                logger.info("Discovery complete", extra={"count": len(images)})
                return images

    The Discovery Lambda loads it by setting
    ``BYOR_DISCOVERY_BACKEND=my_backend.HarborDiscovery``.
    """

    def discover(self, mode: str, config: dict[str, Any]) -> list[dict[str, str]]:
        """Return list of images to scan.

        :param mode: Trigger mode (e.g. ``"hourly"``, ``"full"``,
            ``"manual"``). Use this to scope queries ─ ``"hourly"`` typically
            returns only images deployed in the last hour, ``"full"`` returns
            everything, ``"manual"`` is for ad-hoc invocations from the
            payload.
        :param config: Runtime config passed in the EventBridge schedule input
            or the manual invocation payload. Useful for endpoint overrides
            or query filters without redeploying.
        :returns: List of dicts with ``image`` and ``ref`` keys.
        """
        ...


@runtime_checkable
class AuthProvider(Protocol):
    """Provides registry authentication credentials for skopeo.

    Implementations fetch credentials (certs, tokens, passwords) from the
    customer's secret store and return the appropriate skopeo CLI flags.

    ## Lifecycle

    The scanner Lambda calls :meth:`setup` once per invocation, then calls
    :meth:`get_skopeo_args` for each image in the SQS batch. ``setup()``
    SHOULD fetch credentials fresh on every invocation ─ never cache across
    invocations ─ so rotated certs and tokens are picked up automatically
    without redeploy. The Lambda execution environment is what gets reused
    across warm starts; do not add a second caching layer in the plugin.

    ## Built-in providers

      - :class:`byor_scanner.backends.auth.mtls.MtlsAuth`: Mutual TLS via
        client certs from Secrets Manager. Reads
        ``{"ca": "...", "cert": "...", "key": "..."}`` from the secret named
        in ``MTLS_SECRET_NAME``, writes ``ca.crt``, ``client.cert``,
        ``client.key`` to ``/tmp/certs/``, and returns
        ``["--cert-dir=/tmp/certs", "--tls-verify=true"]``.

    Other auth modes (basic, bearer, authfile) can be added by writing a
    custom AuthProvider against the protocol below.

    ## Writing a custom AuthProvider

    A custom provider is a plain class with two methods::

        # my_auth.py (delivered via a Lambda Layer at /opt/python/)
        from aws_lambda_powertools import Logger
        from opentelemetry import trace

        logger = Logger()
        tracer = trace.get_tracer(__name__)

        class MyAuth:
            @tracer.start_as_current_span("MyAuth.setup")
            def setup(self) -> None:
                logger.info("Auth setup starting")
                # ... fetch creds, write any files needed ...
                logger.info("Auth setup complete")

            def get_skopeo_args(self) -> list[str]:
                return ["--creds=user:secret", "--tls-verify=true"]

    The scanner Lambda loads it by setting ``BYOR_AUTH_PROVIDER=my_auth.MyAuth``.
    """

    def setup(self) -> None:
        """Fetch credentials and write any files skopeo will need on disk.

        Called once per Lambda invocation. Implementations SHOULD fetch
        fresh credentials every call ─ never cache across invocations ─
        so rotated secrets are picked up automatically. The Lambda warm-
        start cycle handles re-use of the execution environment; do not
        add a second caching layer in the plugin.
        """
        ...

    def get_skopeo_args(self) -> list[str]:
        """Return skopeo CLI args for authentication.

        These args are passed directly to ``skopeo inspect`` and translated
        to ``--src-`` prefixed versions for ``skopeo copy``.

        Supported arg formats::

            --cert-dir=<path>     → --src-cert-dir=<path>
            --creds=<user:pass>   → --src-creds=<user:pass>
            --tls-verify=<bool>   → --src-tls-verify=<bool>
            --authfile=<path>     → passed through unchanged (global flag)
        """
        ...
