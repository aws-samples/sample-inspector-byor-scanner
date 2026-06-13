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
3. **`ScannerStack`** — S3 bucket, SQS queue + DLQ, Discovery Lambda, Scanner Lambda, optional EventBridge schedules, CloudWatch alarms, Application Signals SLOs, and a dashboard.

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

The default `bin/app.ts` wires up the **sample** stacks (`BinaryStack` + `TestingStack` + `ScannerStack`). `TestingStack` is what provisions the throwaway VPC, self-signed certs, and test registry — for production you skip it and bring your own three resources:

1. **Skip `TestingStack`** — bring your own VPC, your own registry hostname, and your own pre-existing Secrets Manager secret containing `{ca, cert, key}` (the shape [`MtlsRepositoryAuth`](packages/infra/lib/constructs/inspector-scanner/auth/) reads).
2. **Pass those resources to `ScannerStack` directly.** Replace the `TestingStack` block in `bin/app.ts` with lookups for your own resources:
   ```ts
   import * as ec2 from 'aws-cdk-lib/aws-ec2';
   import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';

   const binaries = new BinaryStack(app, 'BinaryStack', { env });

   new ScannerStack(app, 'ScannerStack', {
     env,
     // Your VPC — needs private subnets + egress to your registry and AWS APIs.
     vpc: ec2.Vpc.fromLookup(app, 'Vpc', { vpcId: 'vpc-...' }),
     // Your registry hostname — host only, no scheme, no path.
     registryUrl: 'registry.internal.example.com',
     // Your pre-existing secret holding the mTLS material ({ca, cert, key} PEMs).
     mtlsSecret: secretsmanager.Secret.fromSecretNameV2(app, 'MtlsCerts', 'scanner/mtls'),
     binaryLayer: binaries.binaryLayer,
   });
   ```
   `vpc`, `registryUrl`, `mtlsSecret`, and `binaryLayer` are the required props. To target a non-mTLS registry, pass a custom `repositoryAuth`; to change how scans fire (scheduled vs. the default S3 manifest), pass a `trigger`. See [`ScannerStackProps`](packages/infra/lib/scanner-stack.ts) for all options.
3. The same `BinaryStack` is reused; you do not need a separate testing flavor.

For a full step-by-step runbook — staging the mTLS secret, a dedicated `bin/prod.ts` entry point, triggering the first scan, and common failure modes — see [`docs/PRODUCTION_DEPLOY.md`](docs/PRODUCTION_DEPLOY.md).

## Observability

Both Lambdas are instrumented with [AWS Distro for OpenTelemetry](https://aws-otel.github.io/) via the ADOT Lambda layer — `tracing: lambda.Tracing.ACTIVE` plus the layer's auto-instrumentation produces full Application Signals + service map output, and the scan pipeline adds manual spans per stage (`ScanImage` → `InspectImage`, `PullImage`, `GenerateSBOM`, `ScanVulnerabilities`, `DeliverFindings`, …).

### Metrics

EMF metrics (Powertools) under namespace `BYORScan`, carrying a `service` dimension (`byor-scanner` / `byor-discovery`):

| Metric | Notes |
|--------|-------|
| `ImagesScanned` / `ImagesFailed` / `ImagesSkipped` | scan outcomes; `ImagesFailed` is also emitted with an `errorCode` dimension for the per-operation alarms |
| `ScanDuration` | per-image wall-clock in ms (p50/p99) |
| `SBOMCacheHit` / `SBOMCacheMiss` | SBOM cache effectiveness |
| `VulnerabilitiesFound` | findings per scan |
| `ImagesEnqueued` | discovery fan-out (also dimensioned by `mode`) |
| `DiscoveryFailed` | discovery-stage failures |

### Alarms

**Operational** (always on, the primary paging signals):

- DLQ depth > 0
- SQS oldest message age > 14h
- Discovery Lambda errors > 0

**Per-operation** — fire when an `errorCode` appears on `ImagesFailed` at least twice in 3 of 5 five-minute periods: `AUTH_FAILED`, `INSPECT_FAILED`, `PULL_FAILED`, `PULL_TIMEOUT`, `SBOMGEN_FAILED`, `SCANSBOM_FAILED`, `SCANSBOM_THROTTLED`, `SCANSBOM_VALIDATION`, `S3_WRITE_FAILED`.

**Burn-rate** — one per SLO that isn't already covered by an operational alarm (scanner availability + latency, discovery latency, new-image-coverage, image-compatibility).

### Service Level Objectives

Seven [Application Signals](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Application-Signals.html) SLOs. Availability and latency use **metric-based SLIs** over the `ApplicationSignals` `Latency`/`Fault` metrics (read as plain CloudWatch metrics, not service-bound `keyAttributes` SLIs), so every SLO **creates on the first deploy** — before the service has been discovered. Availability is the non-fault request ratio `(Latency SampleCount − Fault) / Latency SampleCount`; scan/discovery failures are marked as server faults (`http.status_code=500`) so they count against it.

| SLO | SLI | Attainment goal |
|-----|-----|-----------------|
| `byor-scanner-availability` | non-fault request ratio | 99.9% |
| `byor-scanner-latency` | p99 < 80% of scanner timeout | 99.9% |
| `byor-discovery-availability` | non-fault request ratio | 99.9% |
| `byor-discovery-latency` | p99 < 80% of discovery timeout | 99.9% |
| `byor-scan-freshness` | queue drains within 14h | 99% |
| `byor-new-image-coverage` | p99 scan duration < 60 min | 99% |
| `byor-image-compatibility` | scannable (not skipped) ≥ 95% | 95% |

`byor-scan-freshness` and `byor-discovery-availability` are attainment-only (no burn-rate alarm), since the operational alarms above already page on those signals.

### Dashboard

A `BYORScan` CloudWatch dashboard:

- **Logs Insights:** top 10 images by critical findings; all images with latest findings; repeatedly-failed images. Findings rows expose a clickable `FindingsURL` (S3 console) link, and the repeatedly-failed table includes a clickable `Trace` column that deep-links to the failure's X-Ray trace.
- **Metrics:** scan volume, scan success rate, discovery volume, and scan duration (p50/p99).

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for the responsible-disclosure process.

## License

MIT-0. See [LICENSE](LICENSE).

This project bundles or downloads third-party software (skopeo, inspector-sbomgen)
into a shared Lambda Layer at synth time. See
[THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES.md) for their versions, sources, and
license texts.
