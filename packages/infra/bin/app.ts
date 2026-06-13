#!/usr/bin/env node
import { App } from 'aws-cdk-lib';
import { BinaryStack } from '../lib/binary-stack';
import { ScannerStack } from '../lib/scanner-stack';
import { TestingStack } from '../lib/testing-stack';

const app = new App();

const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

// Deploy order:
//   1. BinaryStack ─ owns the skopeo + sbomgen layer.
//   2. TestingStack ─ provisions VPC + test registry + mTLS secret + seeder.
//   3. ScannerStack ─ consumes VPC / secret from TestingStack and the layer
//      from BinaryStack.
// `cdk deploy --all` follows the implicit dependency edges automatically.
//
// Python Lambda code is bundled at synth time via PythonFunction (uv-based);
// no separate `nx run scanner:package` step is required before deploying.
const binaries = new BinaryStack(app, 'BinaryStack', {
  env,
  description: 'Inspector BYOR Scanner — shared binary layer (skopeo, inspector-sbomgen)',
});

const testing = new TestingStack(app, 'TestingStack', {
  env,
  description: 'Inspector BYOR Scanner — test registry and Synthetics canary',
  binaryLayer: binaries.binaryLayer,
});

new ScannerStack(app, 'ScannerStack', {
  env,
  description: 'Inspector BYOR Scanner — core scanning infrastructure',
  vpc: testing.vpc,
  registryUrl: testing.registryEndpoint,
  mtlsSecret: testing.clientSecret,
  binaryLayer: binaries.binaryLayer,
});

// TODO: re-enable cdk-nag (AwsSolutionsChecks) once both stacks have the
// expected suppressions. See docs/cdk-nag.md.
