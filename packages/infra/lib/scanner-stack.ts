import { CfnOutput, Duration, Stack, StackProps } from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';
import * as path from 'path';
import {
  IDiscoveryTrigger,
  InspectorScanner,
  IRepositoryAuth,
  MtlsRepositoryAuth,
  S3ManifestTrigger,
} from '@constructs/inspector-scanner';

export interface ScannerStackProps extends StackProps {
  /** VPC the Lambdas attach to. Must have private subnets and egress for AWS APIs. */
  readonly vpc: ec2.IVpc;

  /**
   * Hostname of the BYO container registry (e.g. ``registry.example.com``).
   * The scanner pulls images from ``${registryUrl}/<image>:<tag>``.
   */
  readonly registryUrl: string;

  /**
   * Layer holding ``skopeo`` and ``inspector-sbomgen`` at ``/opt/bin/``.
   * Provided by ``BinaryStack``; reused by the registry seeder so all
   * three Lambdas (scanner, discovery, seeder) run identical binaries.
   */
  readonly binaryLayer: lambda.ILayerVersion;

  /**
   * Secret holding the mTLS client material the scanner Lambda uses to
   * authenticate to the registry. Used as the default
   * {@link MtlsRepositoryAuth} when `repositoryAuth` is not supplied.
   */
  readonly mtlsSecret: secretsmanager.ISecret;

  /**
   * Repository auth seam. Defaults to {@link MtlsRepositoryAuth} bound to
   * `mtlsSecret`. Override for non-mTLS registries.
   */
  readonly repositoryAuth?: IRepositoryAuth;

  /**
   * Optional trigger override. Leave unset for the sample's default
   * (`S3ManifestTrigger` named `'Manifest'`); override to wire a
   * `ScheduledTrigger`, `ManualTrigger`, or a custom one.
   */
  readonly trigger?: IDiscoveryTrigger;

  /** Optional KMS CMK for the findings bucket. Defaults to S3-managed (SSE-S3). */
  readonly findingsBucketKey?: kms.IKey;

  /** Scanner Lambda timeout. Defaults to 15 min (Lambda max). */
  readonly scannerTimeout?: Duration;
  /** Scanner Lambda memory. Defaults to 6144 MiB. */
  readonly scannerMemoryMiB?: number;
  /** Scanner Lambda /tmp size. Defaults to 10 GiB (Lambda max). */
  readonly scannerEphemeralStorageGiB?: number;
  /** SQS event source mapping batch size. Defaults to 10. */
  readonly sqsBatchSize?: number;
  /** SQS event source mapping max concurrency. Defaults to 10. */
  readonly sqsMaxConcurrency?: number;
}

/**
 * Sample-stack wrapper around {@link InspectorScanner}.
 *
 * Picks defaults appropriate for the sample (mTLS auth from the test
 * registry's secret; S3-manifest trigger so a customer can drop a JSON and
 * watch the scanner fire). Production deploys can either:
 *  - reuse this stack and pass `trigger` / `repositoryAuth` explicitly, or
 *  - bypass it and instantiate `InspectorScanner` directly inside their own
 *    stack/app.
 */
export class ScannerStack extends Stack {
  public readonly findingsBucket: s3.IBucket;
  public readonly scanQueue: sqs.IQueue;
  public readonly scanDeadLetterQueue: sqs.IQueue;
  public readonly scannerFunction: lambda.IFunction;
  public readonly discoveryFunction: lambda.IFunction;

  constructor(scope: Construct, id: string, props: ScannerStackProps) {
    super(scope, id, props);

    const repositoryAuth =
      props.repositoryAuth ??
      new MtlsRepositoryAuth(this, 'RepositoryAuth', { secret: props.mtlsSecret });

    // Sample default: an S3 manifest bucket. Drop a JSON array of
    // {image, ref} into the bucket and the scan fires. Override via
    // `props.trigger` for scheduled or manual deploys.
    const trigger =
      props.trigger ??
      new S3ManifestTrigger(this, 'Trigger', { source: 'Manifest' });

    const lambdaCodePath = path.join(
      __dirname, '..', '..', 'scanner', 'dist', 'lambda',
    );

    const inspector = new InspectorScanner(this, 'Inspector', {
      vpc: props.vpc,
      registryUrl: props.registryUrl,
      binaryLayer: props.binaryLayer,
      lambdaCodePath,
      repositoryAuth,
      trigger,
      findingsBucketKey: props.findingsBucketKey,
      scannerTimeout: props.scannerTimeout,
      scannerMemoryMiB: props.scannerMemoryMiB,
      scannerEphemeralStorageGiB: props.scannerEphemeralStorageGiB,
      sqsBatchSize: props.sqsBatchSize,
      sqsMaxConcurrency: props.sqsMaxConcurrency,
    });

    this.findingsBucket = inspector.findingsBucket;
    this.scanQueue = inspector.scanQueue;
    this.scanDeadLetterQueue = inspector.scanDeadLetterQueue;
    this.scannerFunction = inspector.scannerFunction;
    this.discoveryFunction = inspector.discoveryFunction;

    // Re-export the manifest bucket name so canaries / docs can drop into it.
    if (trigger instanceof S3ManifestTrigger) {
      new CfnOutput(this, 'ManifestBucketName', {
        value: trigger.bucket.bucketName,
        description:
          'Drop a JSON manifest (array of {image, ref}) here to fire a scan.',
      });
    }
  }
}
