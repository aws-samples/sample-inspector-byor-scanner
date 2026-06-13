# Inspector BYOR Scanner

A serverless AWS-hosted vulnerability scanner for **non-ECR container registries**. Bring your own registry (Docker Distribution, Harbor, JFrog, etc.) — the scanner pulls images, generates SBOMs with [`inspector-sbomgen`](https://docs.aws.amazon.com/inspector/latest/user/sbom-generator.html), and runs them through Amazon Inspector's vulnerability database.

Built for customers whose registries Inspector's native scanning does not reach.

## Architecture

```
                                                              ┌────────────────┐
EventBridge Scheduler ──┐                                     │ BinaryStack    │
(hourly + 12-hourly)    │                                     │  - skopeo      │
                        ▼                                     │  - sbomgen     │
                  Discovery Lambda ─── DiscoveryBackend       │ Lambda Layer   │
                        │                                     │ /opt/bin/      │
                        ▼                                     └───┬────────────┘
                       SQS ─────── DLQ + alarms                   │ attached to
                        │                                         ▼
                        ▼                              ┌──────────────────────┐
                 Scanner Lambda  ── AuthProvider plugin│  Scanner Lambda      │
                        │         (mTLS by default)    │  Discovery Lambda    │
                        ▼                              │  Seeder Lambda (test)│
                      S3 bucket                        └──────────────────────┘
                  ├ sboms/<digest>.json   (cache, 30d)
                  └ findings/<image>/<digest>/<ts>.json
```

Three CFN stacks deploy in order:

1. **`BinaryStack`** — owns the shared Lambda Layer holding `skopeo` + `inspector-sbomgen`.
2. **`TestingStack`** *(sample only)* — VPC, mTLS-protected Distribution registry on ECS Fargate, self-signed certs generated at deploy time, one-shot Lambda seeder that pushes `alpine:3.19` into the registry.
3. **`ScannerStack`** — S3 bucket, SQS queue + DLQ, Discovery Lambda, Scanner Lambda, optional EventBridge schedules, three CloudWatch alarms.

## Repo layout

NX monorepo, three packages:

```
packages/
├── infra/      CDK (TypeScript). All stacks, constructs, and the BinaryLayer.
├── scanner/    Lambda code (Python). Discovery + Scanner + Seeder handlers, plugin protocols, mTLS auth backend, static discovery backend.
└── canary/     CloudWatch Synthetics canary scaffolding (Playwright). Not yet wired into TestingStack.
```

## Plugin model

Auth and discovery are pluggable via Python `Protocol` classes loaded by dotted path from environment variables:

| Env var | Default | Purpose |
|---|---|---|
| `BYOR_AUTH_PROVIDER` | `byor_scanner.backends.auth.mtls.MtlsAuth` | How the scanner authenticates to your registry. |
| `BYOR_DISCOVERY_BACKEND` | `byor_scanner.backends.discovery.static.StaticDiscovery` | How images are discovered for scanning. |

Customers ship custom plugins as **Lambda Layers** at `/opt/python/` and select via env var; no rebuild needed. The protocol contracts and worked examples are in [`packages/scanner/byor_scanner/protocols.py`](packages/scanner/byor_scanner/protocols.py).

## Prerequisites

- Node.js ≥ 22, npm
- Python ≥ 3.11, [`uv`](https://docs.astral.sh/uv/)
- AWS CDK CLI (`npm i -g aws-cdk`) and AWS credentials
- Docker (or Podman) — used at `cdk synth` to build `skopeo` from source in a pinned Alpine image
- `curl` + `unzip` — used at `cdk synth` to fetch `inspector-sbomgen`

The build host platform doesn't matter; binaries are always compiled for `linux/amd64` (Lambda's runtime architecture).

## Getting started

```bash
npm install                          # JS workspaces + auto-runs uv sync for Python pkgs
npx nx run-many -t test,lint         # tests + lint across all packages
npx nx run infra:synth               # synth all three stacks (PythonFunction bundles
                                     #   the Lambda zip via uv during synth)
```

First deploy (uses default sample stacks: BinaryStack + TestingStack + ScannerStack):

```bash
# bootstrap CDK once per account+region
npx cdk bootstrap aws://<account>/<region>

# deploy all three stacks
cd packages/infra
npx cdk deploy --all --require-approval never
```

The first deploy takes ~6-8 min: CDK runs the Docker-based `skopeo` build inside a pinned `golang:1.25-alpine` container, downloads `inspector-sbomgen` with SHA256 verification, and provisions the three stacks. Subsequent deploys skip the binary build (asset hash unchanged).

### Running an end-to-end scan

```bash
DISC=$(aws cloudformation describe-stacks --stack-name ScannerStack \
  --query 'Stacks[0].Outputs[?OutputKey==`DiscoveryFunctionName`].OutputValue' --output text)
FINDINGS=$(aws cloudformation describe-stacks --stack-name ScannerStack \
  --query 'Stacks[0].Outputs[?OutputKey==`FindingsBucketName`].OutputValue' --output text)

echo '{"mode":"manual","images":[{"image":"alpine","ref":"3.19"}]}' > /tmp/disc.json
aws lambda invoke --function-name "$DISC" --payload fileb:///tmp/disc.json /tmp/out.json

# Wait ~30 seconds, then look at S3:
aws s3 ls "s3://$FINDINGS/findings/" --recursive
```

You should see `findings/alpine/<short-digest>/<timestamp>.json` — that's CycloneDX 1.5 with a populated `vulnerabilities[]`.

### Cleanup

```bash
cd packages/infra
npx cdk destroy --all --force
```

The test registry's NAT gateway is the only ongoing cost (~$33/mo). Don't leave it deployed.

## Production deploy

The default `bin/app.ts` wires up the **sample** stacks (TestingStack + ScannerStack). For a production deploy you typically:

1. Skip `TestingStack` entirely — bring your own VPC, your own registry, your own pre-existing Secrets Manager secret containing `{ca, cert, key}`.
2. Pass those resources to `ScannerStack` directly:
   ```ts
   new ScannerStack(app, 'ScannerStack', {
     vpc: ec2.Vpc.fromLookup(scope, 'Vpc', { vpcId: 'vpc-...' }),
     registryUrl: 'registry.internal.example.com',
     mtlsSecret: secretsmanager.Secret.fromSecretNameV2(scope, 'MtlsCerts', 'scanner/mtls'),
     binaryLayer: binaries.binaryLayer,
     enableSchedules: true,            // production wants the cron
     authProvider: 'my_custom_pkg.MyAuth',          // optional: custom plugin
     pluginLayerArn: 'arn:aws:lambda:...:layer:...', // your plugin layer
   });
   ```
3. The same `BinaryStack` is reused; you do not need a separate testing flavor.

## Observability

Both Lambdas are instrumented with [AWS Distro for OpenTelemetry](https://aws-otel.github.io/) via the ADOT Lambda layer — `tracing: lambda.Tracing.ACTIVE` plus the layer's auto-instrumentation produces full Application Signals + service map output. EMF metrics under namespace `BYORScan` cover `ImagesEnqueued`, `ImagesScanned`, `ImagesFailed` (with `errorCode` dimension), `SBOMCacheHit`/`Miss`, `VulnerabilitiesFound`, `DiscoveryFailed`. Three alarms ship out of the box:

- DLQ depth > 0
- SQS oldest message age > 14h
- Discovery Lambda errors > 0

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for the responsible-disclosure process.

## License

MIT-0. See [LICENSE](LICENSE).
