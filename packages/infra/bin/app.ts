#!/usr/bin/env node
import { App } from 'aws-cdk-lib';
import * as path from 'path';
import { BinaryStack } from '../lib/binary-stack';
import { ScannerStack } from '../lib/scanner-stack';
import { TestingStack } from '../lib/testing-stack';

const app = new App();

const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

// The scanner Lambda zip directory ─ produced by `nx run scanner:package`.
// Both Scanner + Testing stacks consume it (testing reuses the zip for the
// registry seeder handler).
const scannerLambdaCodePath = path.join(
  __dirname, '..', '..', 'scanner', 'dist', 'lambda',
);

// Deploy order:
//   1. BinaryStack ─ owns the skopeo + sbomgen layer.
//   2. TestingStack ─ provisions VPC + test registry + mTLS secret + seeder.
//   3. ScannerStack ─ consumes VPC / secret from TestingStack and the layer
//      from BinaryStack.
// `cdk deploy --all` follows the implicit dependency edges automatically.
const binaries = new BinaryStack(app, 'BinaryStack', {
  env,
  description: 'Inspector BYOR Scanner — shared binary layer (skopeo, inspector-sbomgen)',
});

const testing = new TestingStack(app, 'TestingStack', {
  env,
  description: 'Inspector BYOR Scanner — test registry and Synthetics canary',
  scannerLambdaCodePath,
  binaryLayer: binaries.binaryLayer,
});

new ScannerStack(app, 'ScannerStack', {
  env,
  description: 'Inspector BYOR Scanner — core scanning infrastructure',
  vpc: testing.vpc,
  registryUrl: testing.registryEndpoint,
  mtlsSecret: testing.clientSecret,
  binaryLayer: binaries.binaryLayer,
  // Schedules off in the sample so the canary's manual invokes are the
  // only traffic. Production deploys override to true.
  enableSchedules: false,
});

// TODO: re-enable cdk-nag (AwsSolutionsChecks) once both stacks have the
// expected suppressions. See docs/cdk-nag.md.
