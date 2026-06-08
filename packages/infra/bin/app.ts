#!/usr/bin/env node
import { App, Aspects } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { ScannerStack } from '../lib/scanner-stack';
import { TestingStack } from '../lib/testing-stack';

const app = new App();

const scanner = new ScannerStack(app, 'ScannerStack', {
  description: 'Inspector BYOR Scanner — core scanning infrastructure',
});

new TestingStack(app, 'TestingStack', {
  description: 'Inspector BYOR Scanner — test registry and Synthetics canary',
  vpc: scanner.vpc,
  pusherFunction: scanner.pusherFunction,
  findingsBucket: scanner.findingsBucket,
});

Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
