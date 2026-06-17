# Production deploy runbook

How to deploy the Inspector BYOR scanner against a real container registry
(e.g. Titus). Skips the sample's `TestingStack` (test ECS Fargate registry,
seeded `alpine:3.19`) and wires the L3 directly into your VPC + Secrets
Manager + registry hostname.

## What this gives you

A serverless container vulnerability scanner that:

- Pulls images from your registry over mTLS
- Generates a CycloneDX SBOM with `inspector-sbomgen`
- Scans it via Amazon Inspector's `ScanSbom` API
- Writes findings JSON to S3
- Fires automatically when you drop a manifest into a designated S3 bucket

## Prerequisites

- AWS account with Inspector enabled in your target region (`us-west-2`
  or `us-east-1` — the only regions with the ADOT layer pinned today)
- A VPC the Lambdas can attach to with private subnets and egress to:
  - Your registry hostname
  - AWS service endpoints (S3, SQS, Secrets Manager, Inspector, CloudWatch)
- An mTLS client cert + key + CA bundle that your registry accepts
- CDK CLI v2.1126+, Node 22+, Docker (for `cdk synth` to bundle the Python
  Lambdas via `aws-lambda-python-alpha`)

## Step 1 — Stage the mTLS material in Secrets Manager

`MtlsRepositoryAuth` reads a single Secrets Manager secret with this exact
JSON shape:

```jsonc
{
  "ca":   "<CA chain PEM, e.g. -----BEGIN CERTIFI…E-----…>",
  "cert": "<client cert PEM, e.g. -----BEGIN CERTIFI…E-----…>",
  "key":  "<client key PEM, e.g. -----BEGIN PRIVATE KE…Y-----…>"
}
```

All three fields are required, all three are PEM strings (literal `\n`
in the JSON, real newlines inside the PEM). The plugin fetches this
secret on **every** Lambda invocation — rotate certs by updating the
secret, no redeploy needed.

```sh
# Stage from local PEM files
jq -n \
  --arg ca   "$(cat ca.pem)" \
  --arg cert "$(cat client.pem)" \
  --arg key  "$(cat client.key)" \
  '{ca:$ca, cert:$cert, key:$key}' \
  > /tmp/mtls.json

aws secretsmanager create-secret \
  --name byor-scanner/registry-mtls \
  --secret-string file:///tmp/mtls.json
```

The Lambda role gets `secretsmanager:GetSecretValue` on this exact secret
ARN — nothing else.

## Step 2 — Compose the stack

You don't want `TestingStack` (it provisions a test ECS Fargate registry
and seeds `alpine:3.19`). Write your own entry point at
`packages/infra/bin/prod.ts`:

```ts
#!/usr/bin/env node
import { App, Stack } from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import {
  InspectorScanner,
  MtlsRepositoryAuth,
  S3ManifestDiscoveryProvider,
  S3ManifestTrigger,
} from '@constructs/inspector-scanner';

const app = new App();
const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

class ProdScannerStack extends Stack {
  constructor(scope: App, id: string) {
    super(scope, id, { env });

    // Drop these lookups in via CFN params, SSM, or hard-code per environment.
    const vpc = ec2.Vpc.fromLookup(this, 'Vpc', { vpcId: 'vpc-xxxxxxxx' });
    const mtlsSecret = secretsmanager.Secret.fromSecretNameV2(
      this, 'MtlsSecret', 'byor-scanner/registry-mtls',
    );

    // The scanner owns its binary layer (skopeo + sbomgen) — no BinaryStack.
    const scanner = new InspectorScanner(this, 'Inspector', { vpc });

    // Attach the registry (host only, no scheme, no path) + its auth.
    scanner.addRegistry('default', {
      url: 'registry.example.internal',
      auth: new MtlsRepositoryAuth(this, 'Auth', { secret: mtlsSecret }),
    });

    // Fire scans by dropping a JSON manifest (array of {image, ref}) into a
    // bucket. The provider owns its manifest bucket (created here); the trigger
    // attaches an object-created notification to that same bucket. Swap in a
    // ScheduledTrigger, or omit triggers for manual invoke.
    const manifest = new S3ManifestDiscoveryProvider(this, 'Manifest');
    const provider = scanner.addDiscoveryProvider('manifest', manifest);
    scanner.addTrigger(
      'manifest',
      new S3ManifestTrigger(this, 'ManifestTrigger', {
        discovery: provider,
        bucket: manifest.bucket,
      }),
    );
  }
}

new ProdScannerStack(app, 'ProdScannerStack');
```

Then run:

```sh
npx cdk --app 'npx ts-node bin/prod.ts' deploy --all
```

## Step 3 — Deploy

```sh
git clone <repo>
cd <repo> && npm install
cd packages/infra
CDK_DEFAULT_ACCOUNT=<account> CDK_DEFAULT_REGION=us-west-2 \
  npx cdk --app 'npx ts-node bin/prod.ts' deploy --all --require-approval never
```

Synth time on first run is ~3 minutes (Docker bundles `skopeo` from source
for the BinaryLayer, then bundles the Python Lambda zip via `uv`).
Subsequent synths are near-instant — both layers are content-hashed.

## Step 4 — Trigger your first scan

Get the manifest bucket from the stack output, drop a JSON in:

```sh
BUCKET=$(aws cloudformation describe-stacks --stack-name ProdScannerStack \
  --query 'Stacks[0].Outputs[?contains(OutputKey, `ManifestBucket`)].OutputValue' \
  --output text)

cat > /tmp/manifest.json <<'EOF'
[
  { "image": "your-team/your-service", "ref": "v2024.06.13" },
  { "image": "your-team/your-service", "ref": "sha256:abc123..." }
]
EOF

aws s3 cp /tmp/manifest.json "s3://$BUCKET/scans/$(date +%Y%m%d)/manual.json"
```

The `image` value is the **repo path on your registry, without the
hostname** — the registry hostname is configured once at deploy time.
`ref` is a tag or a `sha256:` digest; both work.

### Manual / on-demand scan (no trigger needed)

A trigger (S3 manifest, EventBridge schedule) is just an automatic event
source. There is no separate "manual trigger" — manual invocation is simply
calling a provider's discovery Lambda directly, which you can always do
whether or not the provider also has a trigger. (A provider added with
`addDiscoveryProvider` but no `addTrigger` is manual-invoke only.)

The discovery handler is trigger-agnostic: it wraps whatever event it
receives in a `{source, payload}` envelope. Invoke it with an explicit image
list (handled by the `StaticDiscovery` / `ScheduledStaticDiscovery` backend,
which reads `payload.images`):

```sh
DISCOVERY_FN=$(aws cloudformation describe-stacks --stack-name ProdScannerStack \
  --query 'Stacks[0].Outputs[?contains(OutputKey, `DiscoveryFunctionName`)].OutputValue' \
  --output text)

aws lambda invoke \
  --function-name "$DISCOVERY_FN" \
  --cli-binary-format raw-in-base64-out \
  --payload '{
    "source": "Manual",
    "payload": { "images": [
      { "image": "your-team/your-service", "ref": "v2024.06.13" }
    ] }
  }' \
  /tmp/out.json && cat /tmp/out.json
```

The optional top-level `source` (here `"Manual"`) tags the run for metrics; if
omitted it falls back to the provider's id. The discovery Lambda enqueues the
images to SQS and the scanner picks them up exactly as it would for a manifest
drop or a scheduled run — same `image`/`ref` semantics as above. Each image
may also carry a `registry` id; omit it to use the `default` registry (or the
sole configured registry).

## Step 5 — Find findings

```sh
FINDINGS_BUCKET=$(aws cloudformation describe-stacks --stack-name ProdScannerStack \
  --query 'Stacks[0].Outputs[?contains(OutputKey, `FindingsBucket`)].OutputValue' \
  --output text)

aws s3 ls "s3://$FINDINGS_BUCKET/findings/your-team/your-service/"
```

Each scan writes one JSON at
`findings/<image>/<digest-prefix>/<timestamp>.json` containing the full
ScanSbom response (CycloneDX SBOM with `vulnerabilities[]` populated).

## Step 6 — Wire it into your existing flow

Three integration patterns:

1. **CI/CD post-deploy hook** — after a deploy, drop a manifest covering
   the just-deployed image refs into the bucket. Findings will be in S3
   within ~2 min for small images.
2. **Periodic re-scan** — replace `S3ManifestTrigger` with
   `ScheduledTrigger` (one or more cron entries). Each entry carries an
   opaque `payload`; pair with a custom discovery plugin that reads e.g.
   `payload.window = 'PT1H'` and queries your fleet for images deployed in
   the last hour. See `byor_scanner/protocols.py` for the plugin contract.
3. **Custom discovery backend** — write
   `class MyDiscovery: def discover(self, event): …` that hits your
   internal API directly, package it as a Lambda Layer, and set
   `BYOR_DISCOVERY_BACKEND=mypkg.MyDiscovery`. Plugin support is the
   project's differentiator.

## Common issues

- **`AUTH_FAILED` on first scan** — usually a secret-schema mismatch.
  Pull `aws logs tail /aws/lambda/<discovery-fn>` and grep `errorCode`.
- **`SCANSBOM_THROTTLED`** — Inspector ScanSbom has account-level rate
  limits; for large fleets the retry-with-backoff in `sbom.py` may not be
  enough.
- **Region not in `ADOT_LAYER_ARNS`** — the construct throws at synth.
  Add the region's ADOT layer ARN to `inspector-scanner.ts`. Documented
  as a known gap in the README's punch-list.
- **Non-standard image path scheme** — the scanner builds
  `${registryUrl}/${image}:${ref}` (or `@${digest}`). If your registry
  needs a `v2/` prefix or anything else, the discovery plugin has to
  format the `image` field accordingly.

## What's not covered

- **Distroless / scratch images** — `inspector-sbomgen` may return
  `UNSUPPORTED_OS`. Ship a no-op SBOM fallback in your discovery plugin
  if you need to count those as "scanned anyway".
- **Multi-arch** — the scanner pulls whatever digest the manifest list
  resolves to in Lambda's `linux/amd64` runtime. If you need arm64-
  specific scans, the manifest entry must carry a per-arch digest or
  registry-side selection has to be configured.
- **>5000 components per image** — handled by `sbom.py`'s batching, but
  worth knowing about for the largest base images.

## Customer checklist (fill in before deploy)

| Field                  | Value                                    |
|------------------------|------------------------------------------|
| AWS account            | `<account-id>`                           |
| Region                 | `us-west-2` or `us-east-1`               |
| VPC ID                 | `vpc-xxxxxxxx`                           |
| Registry hostname      | `registry.example.internal`              |
| mTLS secret name       | `byor-scanner/registry-mtls`             |
| Stack name             | `ProdScannerStack` (or your own)         |
