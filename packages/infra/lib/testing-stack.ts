import { Stack, StackProps } from 'aws-cdk-lib';
import { IVpc } from 'aws-cdk-lib/aws-ec2';
import { IFunction } from 'aws-cdk-lib/aws-lambda';
import { IBucket } from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';

export interface TestingStackProps extends StackProps {
  readonly vpc: IVpc;
  readonly pusherFunction: IFunction;
  readonly findingsBucket: IBucket;
}

/**
 * Testing infrastructure: mTLS-protected Docker registry on ECS Fargate
 * (pre-loaded with alpine:3.19), self-signed cert generator, and a
 * CloudWatch Synthetics canary that exercises the full scanner pipeline.
 *
 * TODO: Resources are not yet defined. Imports the scanner's VPC,
 * Pusher Lambda ARN, and findings bucket from ScannerStack.
 */
export class TestingStack extends Stack {
  constructor(scope: Construct, id: string, props: TestingStackProps) {
    super(scope, id, props);

    // TODO: Custom Resource — generate self-signed CA + server + client certs
    // TODO: Secrets Manager — store {ca, cert, key}
    // TODO: ECS Fargate Docker registry (mTLS), Cloud Map service discovery
    // TODO: Synthetics canary (syn-nodejs-playwright-2.0, activeTracing)
    // TODO: Canary alarm on SuccessPercent
  }
}
