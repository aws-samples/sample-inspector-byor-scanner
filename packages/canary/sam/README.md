# Canary local-debug harness

Per [AWS docs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Debug_Locally.html), Synthetics canaries can be run locally with AWS SAM CLI against a Lambda-emulating container.

## Prerequisites

- Docker (or Rancher Desktop with Docker runtime)
- [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html)
- A deployed `ScannerStack`/`TestingStack` (the canary invokes real AWS resources)
- AWS credentials in your environment (`aws configure` or `AWS_PROFILE=...`)

## Run

From the repo root:

```bash
npx nx run @inspector-byor-scanner/canary:sam:invoke
```

This builds the canary bundle and runs `sam local invoke` with `event.json`.

## Configure

Before running, edit `event.json`:

- `artifactS3Location.s3Bucket` — set to a bucket you can write to (canary HARs / screenshots)
- `canaryRunId` — generate a fresh UUID per run if you want X-Ray traces to be distinct

Override Pusher / findings-bucket targets via the SAM CLI:

```bash
sam local invoke \
  --parameter-overrides \
    PusherFunctionName=ScannerStack-PusherFunction-XXX \
    FindingsBucket=scannerstack-findingsbucket-xxx \
  -e event.json
```
