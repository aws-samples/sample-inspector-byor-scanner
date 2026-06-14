import { Duration } from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as synthetics from 'aws-cdk-lib/aws-synthetics';
import { Construct } from 'constructs';
import * as fs from 'fs';
import * as path from 'path';

export interface ScannerCanaryProps {
  readonly manifestBucket: s3.IBucket;
  readonly findingsBucket: s3.IBucket;
  readonly testImage?: string;
  readonly testImageTag?: string;
  readonly schedule?: synthetics.Schedule;
  readonly timeout?: Duration;
  readonly enableAlarm?: boolean;
}

export class ScannerCanary extends Construct {
  public readonly canary: synthetics.Canary;

  constructor(scope: Construct, id: string, props: ScannerCanaryProps) {
    super(scope, id);

    const canaryDistPath = path.join(__dirname, '..', '..', '..', '..', 'canary', 'dist');
    if (!fs.existsSync(canaryDistPath)) {
      throw new Error(`Canary dist not found at ${canaryDistPath}. Run "npm run build" in packages/canary first.`);
    }

    this.canary = new synthetics.Canary(this, 'Canary', {
      runtime: new synthetics.Runtime('syn-nodejs-puppeteer-16.0', synthetics.RuntimeFamily.NODEJS),
      test: synthetics.Test.custom({
        code: synthetics.Code.fromAsset(canaryDistPath),
        handler: 'nodejs/node_modules/index.handler',
      }),
      schedule: props.schedule ?? synthetics.Schedule.rate(Duration.minutes(15)),
      activeTracing: true,
      environmentVariables: {
        MANIFEST_BUCKET: props.manifestBucket.bucketName,
        FINDINGS_BUCKET: props.findingsBucket.bucketName,
        TEST_IMAGE: props.testImage ?? 'alpine',
        TEST_IMAGE_TAG: props.testImageTag ?? '3.19',
      },
      timeout: props.timeout ?? Duration.minutes(5),
    });

    props.manifestBucket.grantWrite(this.canary.role);
    props.findingsBucket.grantRead(this.canary.role);

    this.canary.role.addToPrincipalPolicy(new iam.PolicyStatement({
      actions: ['xray:PutTraceSegments', 'xray:PutTelemetryRecords'],
      resources: ['*'],
    }));

    if (props.enableAlarm !== false) {
      new cloudwatch.Alarm(this, 'Alarm', {
        metric: this.canary.metricSuccessPercent(),
        threshold: 100,
        comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
        evaluationPeriods: 2,
        datapointsToAlarm: 2,
        treatMissingData: cloudwatch.TreatMissingData.BREACHING,
        alarmDescription: 'Inspector BYOR E2E canary failed',
      });
    }
  }
}
