# CloudWatch Synthetics Canary

## Overview

The canary validates the end-to-end scan pipeline by writing a manifest to S3 (triggering discovery) and polling for findings. It runs as a CloudWatch Synthetics canary on `syn-nodejs-puppeteer-16.0`.

The manifest includes `sourceType: "canary"` which causes the scanner to write findings under `findings/canary/` instead of `findings/`, keeping test output separate from production findings.

### Flow

```
Canary → PutObject (manifest to S3) → S3 event → Discovery Lambda → SQS → Scanner → Findings in S3
                                                                                           ↑
Canary → ListObjectsV2 (poll for findings) ────────────────────────────────────────────────┘
```

## Architecture

| Component | Purpose |
|-----------|---------|
| `packages/canary/src/scanner-canary.ts` | Canary handler (triggerScan + waitForFindings) |
| `packages/canary/esbuild.config.mjs` | Builds canary bundle |
| `packages/canary/sam/` | Local testing harness |
| `packages/infra/lib/constructs/canary/` | CDK construct (`ScannerCanary`) |

### Environment Variables

| Var | Description |
|-----|-------------|
| `MANIFEST_BUCKET` | S3 bucket where the canary writes manifests to trigger scans |
| `FINDINGS_BUCKET` | S3 bucket where the scanner writes findings |
| `TEST_IMAGE` | Image name to scan (default: `alpine`) |
| `TEST_IMAGE_TAG` | Image tag/ref (default: `3.19`) |

## Deploying

The `ScannerCanary` construct is available via the `InspectorScanner` methodful API. Call `addCanary()` in your stack to deploy the canary:

```typescript
inspector.addCanary('scannerCanary', {
  manifestBucket: manifestDiscovery.bucket,
  // Optional:
  // testImage: 'alpine',
  // testImageTag: '3.19',
  // schedule: synthetics.Schedule.rate(Duration.minutes(15)),
  // timeout: Duration.minutes(5),
  // enableAlarm: true,
});
```

The canary starts running on its schedule after deployment. It does not auto-run on creation to avoid race conditions with VPC-attached Lambdas.

## Local Testing with SAM

### Prerequisites

- Docker running
- AWS SAM CLI installed
- A deployed `ScannerStack` (canary calls real AWS resources)
- Valid AWS credentials

### Build with local shims

The Synthetics layer can't be downloaded locally (cross-account restriction). The `build:local` script copies shim files that replace the layer:

```sh
cd packages/canary
npm run build:local
```

This runs esbuild + copies `sam/local-shims/` into `dist/nodejs/node_modules/`:
- `cw-synthetics.js` — SAM entrypoint that routes to `index.handler`
- `@aws/synthetics-puppeteer/index.js` — provides `executeStep()` with logging

### Invoke

```sh
cd packages/canary/sam
sam build
sam local invoke -e event.json \
  --parameter-overrides \
    ManifestBucket=$(aws cloudformation describe-stacks \
      --stack-name ScannerStack \
      --query 'Stacks[0].Outputs[?OutputKey==`ManifestBucketName`].OutputValue' \
      --output text) \
    FindingsBucket=$(aws s3api list-buckets \
      --query 'Buckets[?contains(Name,`findingsbucket`)].Name | [0]' \
      --output text) \
    AwsRegion=us-west-2
```

Or with explicit values:

```sh
sam local invoke -e event.json \
  --parameter-overrides \
    ManifestBucket=scannerstack-manifestbucket-xxx \
    FindingsBucket=scannerstack-findingsbucket-xxx \
    AwsRegion=us-west-2
```

### Expected Output

```
[Synthetics] Step started: triggerScan
[Synthetics] Step passed: triggerScan
[Synthetics] Step started: waitForFindings
[Synthetics] Step passed: waitForFindings
```

If findings aren't found within 5 minutes, the step fails with a timeout error.

## Seeding the Registry

The canary scans `alpine:3.19` by default. The `TestingStack` Seeder Lambda pushes this image into the test registry automatically at deploy time. If you changed `TEST_IMAGE`/`TEST_IMAGE_TAG`, ensure that image exists in the registry.

## Troubleshooting

> **Note:** The canary does not appear under Application Signals → Service → Synthetics Canaries tab because S3 event notifications don't propagate X-Ray trace headers. The canary triggers the pipeline asynchronously (S3 PutObject → S3 notification → Discovery Lambda), so Application Signals can't link the traces.

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Cannot find module '@aws/synthetics-puppeteer'` | Built with `npm run build` instead of `build:local` | Use `npm run build:local` |
| `Cannot find module 'cw-synthetics'` | Same as above | Use `npm run build:local` |
| `Timed out waiting for findings` | Scanner didn't complete in 5min | Check scanner Lambda logs, verify image exists in registry |
| SAM can't start container | Docker not running or path not shared | Start Docker, add `/Volumes/workplace` to file sharing |

