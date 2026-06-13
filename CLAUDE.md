# CLAUDE.md

Guidance for AI agents working in this repo. Optimized for picking up cold without re-reading every file.

## Project shape

Open-source AWS sample. Serverless container vulnerability scanner for non-ECR registries. The customer brings a registry; the scanner pulls images via `skopeo`, generates SBOMs via `inspector-sbomgen`, and submits them to Amazon Inspector's `ScanSbom` API.

NX monorepo, three packages:

- `packages/infra/` — CDK (TypeScript). Three stacks: `BinaryStack` (shared Lambda Layer), `TestingStack` (test registry + seeder, sample-only), `ScannerStack` (scanner + discovery Lambdas).
- `packages/scanner/` — Lambda code (Python). Discovery + Scanner + Seeder handlers, plugin protocols, mTLS auth backend, static discovery backend.
- `packages/canary/` — CloudWatch Synthetics canary scaffolding. Not yet wired into TestingStack.

Plugin model is the project's differentiator: customers ship custom auth + discovery backends as Lambda Layers; no rebuild needed.

## Working pattern

For substantive changes, follow this ritual:

1. **Read existing code carefully** before reaching for a new file. Many things already exist as helpers (`subprocess_helpers.run`, `validation.validate_image_name`, `BinaryLayer`).
2. **Run the four lenses** before writing code:
   - **DX** — customer can deploy in <15 min with one command. Inline docs over external ones.
   - **Security** — every IAM grant least-priv with inline rationale. No `--tls-verify=false` defaults. Schema-validate every secret.
   - **Observability** — silent failure is a bug. Every error path emits a metric with `errorCode` dimension.
   - **Maintainability** — readable cold by a stranger in 6 months. Naming reflects role not implementation.
3. **Security wins ties.** Customers can opt into weaker security with explicit props (e.g. `insecureTlsVerify: true`) — never as a default.
4. **Surface decisions to the user before writing code.** Concrete options, not "what do you think?"

## Architecture key facts

### Three-stack deploy order

`BinaryStack` → `TestingStack` → `ScannerStack`. The latter two consume the binary layer ARN from `BinaryStack` as a prop. `bin/app.ts` wires this up; `cdk deploy --all` follows the implicit cross-stack edges.

### Lambda binaries live in a shared Layer, NOT in the function zip

- Source of truth: `packages/infra/lib/binary-stack.ts` + `packages/infra/lib/constructs/binary-layer/`.
- skopeo is **built from source** at `cdk synth` time inside a digest-pinned `golang:1.25-alpine` container.
- inspector-sbomgen is **downloaded** from the official AWS S3 URL with SHA256 verification.
- Both end up at `/opt/bin/<name>` after Lambda mounts the layer.
- The `BinaryLayer` construct is a generic builder: `addBinaryFromSource` + `addBinaryFromArchive`. Adding new binaries (trivy, syft, …) is one line.
- Asset hash is `AssetHashType.CUSTOM` keyed on (image pin, build command, URL, SHA256). The default `SOURCE` mode would NOT invalidate when the build command changes — known CDK pitfall.

### Tracing is OTel, NOT Powertools Tracer

The Lambdas use `aws_lambda_powertools.Logger` and `aws_lambda_powertools.Metrics` — but **NOT** `aws_lambda_powertools.Tracer`. Tracing is OTel via the ADOT Python Lambda Layer:

```python
from opentelemetry import trace
tracer = trace.get_tracer(__name__)

@tracer.start_as_current_span("MyStep")
def my_step(...): ...
```

The ADOT layer auto-wraps the handler; do **not** decorate the handler. `tracer.patch_all()` is also handled by the layer; do not call it. Powertools Tracer + ADOT collide and produce two parallel trace pipelines.

### Env-var convention: `BYOR_*` prefix

All plugin selection + runtime tunables. `constants.py` is the single source of truth. AWS-standard names (`AWS_*`) and Lambda-platform names (`AWS_LAMBDA_*`, `_X_AMZN_*`) stay as-is.

### mTLS cert generation

`packages/infra/lib/constructs/docker-registry/auth/mtls/generate-certs/` runs a Custom Resource Lambda using `@peculiar/x509`. **`reflect-metadata` import is required** as the FIRST import (tsyringe transitive dep). WebCrypto types come from Node's `webcrypto` namespace — do NOT add `"DOM"` to `tsconfig.lib`, it pollutes Lambda code with `window`/`document`.

PEM marker template strings (`-----BEGIN PRIVATE KEY-----` etc.) are constructed from concatenated halves to sidestep secret-scanner false positives. Don't "simplify" back to a single literal.

### Powertools `Logger` reserves the field name `module`

Use `moduleName` instead in `extra={...}` payloads. `module` collides with a built-in `LogRecord` attribute and raises `KeyError`.

### Cleanup of /tmp in scanner Lambda

Per-image: `scan.py` creates `/tmp/scan-XXX/`, `finally:` does `shutil.rmtree(work_dir, ignore_errors=True)`. Skopeo's `--tmpdir /tmp` and inspector-sbomgen's own scratch space self-clean on subprocess exit.

## Common commands

```sh
# Tests (21 currently passing)
npx nx run scanner:test
cd packages/scanner && uv run pytest tests/                 # bypass nx cache

# Lint
npx nx run scanner:lint                                     # ruff
cd packages/infra && npx tsc --noEmit                       # TS typecheck (no nx target yet)

# Build the Lambda zip
npx nx run scanner:package                                  # ~16 MB; binaries NOT included

# Synth all three stacks
cd packages/infra && CDK_DEFAULT_ACCOUNT=<account> \
  CDK_DEFAULT_REGION=<region> npx cdk synth --quiet

# Deploy all three (sample flavor)
cd packages/infra && CDK_DEFAULT_ACCOUNT=<account> \
  CDK_DEFAULT_REGION=<region> npx cdk deploy --all --require-approval never

# Trigger an end-to-end scan against the deployed test registry by dropping
# a manifest into the S3ManifestTrigger bucket (the default v1 trigger).
BUCKET=$(aws cloudformation describe-stacks --stack-name ScannerStack \
  --query 'Stacks[0].Outputs[?OutputKey==`ManifestBucketName`].OutputValue' --output text)
echo '[{"image":"alpine","ref":"3.19"}]' > /tmp/m.json
aws s3 cp /tmp/m.json "s3://$BUCKET/manifests/smoke.json"
```

Set `AWS_PROFILE` (or `AWS_ACCESS_KEY_ID` etc.) to whatever credential mechanism your account uses, and substitute `<account>` / `<region>` for the target deployment.

## Open punch list (as of last work session)

Priority order:

1. **Production-deploy docs** — README has a section; a fuller doc would help.
2. **Plugin-authoring docs** — `protocols.py` docstrings cover it but a top-level guide is missing.
3. **Canary wiring** — Playwright code exists but TestingStack doesn't deploy a Synthetics canary.
4. **`cdk-nag` re-enable** — currently off in `bin/app.ts` (TODO note). Public repo with cdk-nag off is a bad signal.
5. **CDK assertion tests** — `packages/infra` has zero jest tests.
6. **SNS topic on alarms** — three CloudWatch alarms exist; no targets.
7. **At least one non-trivial DiscoveryBackend** — `StaticDiscovery` works but doesn't prove the model. Consider an `S3ManifestDiscovery` example.
8. **ADOT layer ARNs only cover `us-east-1`/`us-west-2`** — `scanner-stack.ts` throws for other regions.
9. **Slim seeder zip** — currently ships the full scanner Python package.
10. **OSS hygiene files** — `SECURITY.md`, refreshed `CONTRIBUTING.md`, PR template.
11. **CI integration-tests gate is `if: false`** in `.github/workflows/pr.yml`.
12. **Seeder runs before ECS task restart** — race condition: cert regen forces ECS rollover and wipes ephemeral storage, but seeder pushed alpine BEFORE the rollover. Fix: seeder Custom Resource should depend on a "ECS service is healthy after cert change" signal.
