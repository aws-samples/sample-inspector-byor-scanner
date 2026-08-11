#!/usr/bin/env node
import { App, Validations } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { BinaryStack } from '../lib/binary-stack';
import { ScannerStack } from '../lib/scanner-stack';
import { TestingStack } from '../lib/testing-stack';

const app = new App();

const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

// Deploy order:
//   1. BinaryStack ─ owns the skopeo + sbomgen layer for the test registry seeder.
//   2. TestingStack ─ provisions VPC + test registry + mTLS secret + seeder.
//   3. ScannerStack ─ consumes VPC / secret from TestingStack. It owns its own
//      binary layer, so it does not depend on BinaryStack.
// `cdk deploy --all` follows the implicit dependency edges automatically.
//
// Python Lambda code is bundled at synth time via PythonFunction (uv-based);
// no separate `nx run scanner:package` step is required before deploying.
const binaries = new BinaryStack(app, 'BinaryStack', {
  env,
  description: 'Inspector BYOR Scanner — binary layer for the test registry seeder',
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
});

// AWS Solutions checks run at synth; accepted findings are acknowledged per-stack.
Validations.of(app).addPlugins(new AwsSolutionsChecks(app, { verbose: true }));
