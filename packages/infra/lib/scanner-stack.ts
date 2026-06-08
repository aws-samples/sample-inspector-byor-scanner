import { Stack, StackProps } from 'aws-cdk-lib';
import { IVpc } from 'aws-cdk-lib/aws-ec2';
import { IFunction } from 'aws-cdk-lib/aws-lambda';
import { IBucket } from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';

/**
 * Core scanning infrastructure: VPC, Pusher + Scanner Lambdas, SQS queue +
 * DLQ, S3 findings bucket, EventBridge schedules, alarms.
 *
 * TODO: Resources are not yet defined. The exposed properties below are
 * placeholders for cross-stack wiring with TestingStack.
 */
export class ScannerStack extends Stack {
  public readonly vpc!: IVpc;
  public readonly pusherFunction!: IFunction;
  public readonly findingsBucket!: IBucket;

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // TODO: VPC
    // TODO: S3 findings bucket (SSE-KMS, lifecycle on sboms/ prefix)
    // TODO: SQS queue + DLQ
    // TODO: Scanner Lambda (Python, zip-packaged, VPC-attached)
    // TODO: Pusher Lambda (Python, VPC-attached)
    // TODO: EventBridge schedules (hourly, 12-hourly)
    // TODO: CloudWatch alarms (DLQ depth, ImagesFailed, queue age)
  }
}
