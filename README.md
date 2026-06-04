# Inspector BYOR Scanner

A serverless, AWS-hosted container image vulnerability scanner for **non-ECR registries**. Bring your own registry (Docker Distribution, Harbor, JFrog, etc.) — pulls images on a schedule, generates SBOMs with [`inspector-sbomgen`](https://docs.aws.amazon.com/inspector/latest/user/sbom-generator.html), and scans them against AWS Inspector's vulnerability database.

Built for customers whose registries Inspector's native scanning does not reach.

## Architecture

```
EventBridge (hourly + 12-hourly cron)
        │
        ▼
  Pusher Lambda  ──── queries deployed-image inventory
        │
        ▼
     SQS  ──── DLQ (alarms on depth > 0)
        │
        ▼
 Scanner Lambda  ──── skopeo inspect → S3 SBOM cache check
                 ──── skopeo copy → inspector-sbomgen → Inspector ScanSbom
                 ──── findings → S3
```

## Repo Layout

NX monorepo with three packages:

```
packages/
├── cdk/        # CDK infrastructure (TypeScript) — ScannerStack + TestingStack
├── canary/     # CloudWatch Synthetics canary (TypeScript / Playwright)
└── scanner/    # Lambda handlers (Python) — pusher + scanner
```

## Prerequisites

- Node.js ≥ 22
- npm
- [`uv`](https://docs.astral.sh/uv/) (Python package manager)
- AWS CDK CLI (`npm i -g aws-cdk`) and AWS credentials
- [`skopeo`](https://github.com/containers/skopeo) — pulls images from the registry without a Docker daemon (`brew install skopeo` on macOS)
- [`inspector-sbomgen`](https://docs.aws.amazon.com/inspector/latest/user/sbom-generator.html) — generates CycloneDX SBOMs from a container image

Both `skopeo` and `inspector-sbomgen` are bundled as static x86_64 binaries into the Scanner Lambda zip at build time.

## Getting Started

```bash
npm install                 # installs JS deps and triggers uv sync for Python packages
npx nx run-many -t build    # build everything
npx nx run-many -t test     # test everything
npx nx graph                # visualize the dependency graph
```

Per-project commands:

```bash
npx nx <target> <project>           # e.g. npx nx build cdk
npx nx affected -t build            # only build what changed since main
```

## Deployment

```bash
npx nx deploy cdk                   # deploys ScannerStack + TestingStack
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
