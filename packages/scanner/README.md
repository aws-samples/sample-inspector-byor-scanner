# scanner

Python AWS Lambda package — handlers for the discovery + scan pipeline plus the registry seeder.

Runtime: **Python 3.11**.

## Layout

```
byor_scanner/
├── scanner.py             SQS handler. Per-image: skopeo inspect → cache check → pull → sbomgen → ScanSbom → S3.
├── discovery_handler.py   EventBridge / direct-invoke handler. Calls DiscoveryBackend, fan-outs to SQS.
├── seeder.py              Test-only Custom Resource handler. Pushes public images into the test registry on deploy.
├── scan.py                Per-image pipeline; one tracer span per stage.
├── sbom.py                ScanSbom API client + 5000-component batching.
├── subprocess_helpers.py  Shared timeout/classify wrapper around skopeo / sbomgen calls.
├── validation.py          Strict OCI image / ref grammar.
├── plugin_loader.py       importlib + Protocol check for backends.
├── protocols.py           AuthProvider + DiscoveryBackend contracts (see file for plugin-authoring docs).
├── config.py              Inlined defaults + BYOR_* env-var overrides.
├── constants.py           Paths, env-var names, skopeo arg translations.
├── errors.py              Typed error codes + stderr → errorCode classifiers.
└── backends/
    ├── auth/mtls.py       Built-in mTLS provider (Secrets Manager → /tmp/certs).
    └── discovery/static.py  Built-in StaticDiscovery (returns event['images'] verbatim).
```

## Targets

```sh
nx run scanner:test       # pytest
nx run scanner:lint       # ruff check
nx run scanner:format     # ruff format

nx run scanner:add --name <pkg>          # add a runtime dependency (uv-backed)
nx run scanner:add --name <pkg> --dev    # add a dev dependency
```

The CDK side bundles this package into the Lambda zip at `cdk synth` time via `aws-lambda-python-alpha`'s `PythonFunction` (uv-driven, hash-keyed off `pyproject.toml` + `uv.lock` + the source tree). There is no separate `package` step. `skopeo` and `inspector-sbomgen` ship in the shared `BinaryStack` Lambda Layer (see `packages/infra/`).

## Plugin model

Both `AuthProvider` and `DiscoveryBackend` are duck-typed Python `Protocol`s. A custom backend lives in its own module (typically delivered via a Lambda Layer at `/opt/python/`) and is selected at runtime via `BYOR_AUTH_PROVIDER` / `BYOR_DISCOVERY_BACKEND` env vars. See `byor_scanner/protocols.py` for the full contract and worked examples (Harbor discovery, custom auth).

## Conventions

- **Logging** — `aws_lambda_powertools.Logger` with structured JSON; key `errorCode` dimensions match the alarms in `ScannerStack`.
- **Tracing** — OpenTelemetry. The host Lambda is auto-wrapped by the ADOT layer; per-stage spans are created with `@tracer.start_as_current_span` from `from opentelemetry import trace`. **Do not** import `aws_lambda_powertools.Tracer` — Powertools Tracer + ADOT collide and produce double traces.
- **Metrics** — `aws_lambda_powertools.Metrics` to namespace `BYORScan`, EMF-encoded.
- **Errors** — every failure path raises `ScanError(<code>, <msg>)`. Codes are listed in `errors.py`.
- **Subprocesses** — go through `subprocess_helpers.run` for consistent timeout / env / classify behavior. Don't `subprocess.run(...)` directly.
