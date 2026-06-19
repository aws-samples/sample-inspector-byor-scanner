import { CfnOutput, Duration, Stack, StackProps } from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as cr from 'aws-cdk-lib/custom-resources';
import { Construct } from 'constructs';
import {
  InspectorScanner,
  IRepositoryAuth,
  MtlsRepositoryAuth,
  NoAuth,
  S3ManifestDiscoveryProvider,
  S3ManifestTrigger,
  ScheduledStaticDiscoveryProvider,
  ScheduledTrigger,
} from '@constructs/inspector-scanner';
import { Observability } from './constructs/inspector-scanner/observability';

export interface ScannerStackProps extends StackProps {
  /** VPC the Lambdas attach to. Must have private subnets and egress for AWS APIs. */
  readonly vpc: ec2.IVpc;

  /**
   * Hostname of the BYO container registry (e.g. ``registry.example.com``).
   * Attached to the scanner as the ``default`` registry.
   */
  readonly registryUrl: string;

  /**
   * Secret holding the mTLS client material the scanner Lambda uses to
   * authenticate to the registry. Used to build the default
   * {@link MtlsRepositoryAuth} when `repositoryAuth` is not supplied.
   */
  readonly mtlsSecret: secretsmanager.ISecret;

  /**
   * Repository auth for the ``default`` registry. Defaults to
   * {@link MtlsRepositoryAuth} bound to `mtlsSecret`. Override for non-mTLS
   * registries.
   */
  readonly repositoryAuth?: IRepositoryAuth;

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
 * Wires the methodful L3 to a single-registry, S3-manifest-driven sample
 * deployment: one mTLS registry (``default``) from the test secret, an
 * {@link S3ManifestDiscoveryProvider} discovery provider, and an
 * {@link S3ManifestTrigger} so dropping a JSON manifest into the bucket fires a
 * scan. Production deploys can either reuse this stack with `registryUrl` /
 * `repositoryAuth`, or bypass it and drive {@link InspectorScanner} directly
 * with their own `addRegistry` / `addDiscoveryProvider` / `addTrigger` calls.
 */
export class ScannerStack extends Stack {
  public readonly findingsBucket: s3.IBucket;
  public readonly scanQueue: sqs.IQueue;
  public readonly scanDeadLetterQueue: sqs.IQueue;
  public readonly scannerFunction: lambda.IFunction;
  public readonly discoveryFunction: lambda.IFunction;

  constructor(scope: Construct, id: string, props: ScannerStackProps) {
    super(scope, id, props);

    const scannerTimeout = props.scannerTimeout ?? Duration.minutes(15);
    const discoveryTimeout = Duration.minutes(5);

    const repositoryAuth =
      props.repositoryAuth ??
      new MtlsRepositoryAuth(this, 'RepositoryAuth', { secret: props.mtlsSecret });

    // Foundational resources only ─ registries / discovery / triggers are
    // attached below via the methodful surface.
    const inspector = new InspectorScanner(this, 'Inspector', {
      vpc: props.vpc,
      findingsBucketKey: props.findingsBucketKey,
      scannerTimeout,
      scannerMemoryMiB: props.scannerMemoryMiB,
      scannerEphemeralStorageGiB: props.scannerEphemeralStorageGiB,
      sqsBatchSize: props.sqsBatchSize,
      sqsMaxConcurrency: props.sqsMaxConcurrency,
    });

    // The single sample registry, attached as ``default`` so messages without
    // an explicit registry id route to it.
    inspector.addRegistry('default', {
      url: props.registryUrl,
      auth: repositoryAuth,
    });

    // A public registry (Docker Hub) needing no auth ─ demonstrates
    // multi-registry with a second, different auth provider. Images tagged
    // `registry: "public"` pull from here (e.g. `library/alpine:3.19`).
    inspector.addRegistry('public', {
      url: 'docker.io',
      auth: new NoAuth(),
      insecureTlsVerify: false,
    });

    // S3-manifest discovery: drop a JSON array of {image, ref} into the bucket
    // to fire a scan. The provider owns the bucket and the trigger attaches its
    // notification to that same bucket, so they can't diverge.
    const manifestDiscovery = new S3ManifestDiscoveryProvider(this, 'Manifest', {});
    const provider = inspector.addDiscoveryProvider('manifest', manifestDiscovery);

    inspector.addTrigger(
      'manifest',
      new S3ManifestTrigger(this, 'Trigger', {
        discovery: provider,
        bucket: manifestDiscovery.bucket,
      }),
    );

    // A second discovery provider + trigger: an EventBridge schedule that fires
    // a static backend with a fixed image list baked into the schedule payload.
    // Demonstrates a second trigger type sharing the same scanner/queue.
    const scheduledProvider = inspector.addDiscoveryProvider(
      'scheduled',
      new ScheduledStaticDiscoveryProvider(),
    );
    inspector.addTrigger(
      'nightly',
      new ScheduledTrigger(this, 'Nightly', {
        discovery: scheduledProvider,
        schedules: [
          {
            id: 'Hourly',
            schedule: 'rate(1 hour)',
            payload: {
              images: [
                { image: 'library/alpine', ref: '3.19', registry: 'public' },
              ],
            },
          },
        ],
      }),
    );

    this.findingsBucket = inspector.findingsBucket;
    this.scanQueue = inspector.scanQueue;
    this.scanDeadLetterQueue = inspector.scanDeadLetterQueue;
    this.scannerFunction = inspector.scannerFunction;
    this.discoveryFunction = provider.discoveryFunction;

    new CfnOutput(this, 'ManifestBucketName', {
      value: manifestDiscovery.bucket.bucketName,
      description:
        'Drop a JSON manifest (array of {image, ref}) here to fire a scan.',
    });

    // ─── Application Signals discovery + observability ─────────────────
    // Application Signals must be enabled at the account level before it
    // surfaces the instrumented Lambdas as services for the SLOs to bind
    // to. StartDiscovery is idempotent and account-wide.
    new cr.AwsCustomResource(this, 'AppSignalsDiscovery', {
      onUpdate: {
        service: 'application-signals',
        action: 'StartDiscovery',
        physicalResourceId: cr.PhysicalResourceId.of('app-signals-discovery'),
      },
      installLatestAwsSdk: true,
      policy: cr.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          actions: [
            'application-signals:StartDiscovery',
            'iam:CreateServiceLinkedRole',
          ],
          resources: ['*'],
        }),
      ]),
    });

    // SLOs (+ per-operation alarms) and the CloudWatch dashboard.
    new Observability(this, 'Observability', {
      scannerFunction: this.scannerFunction,
      queue: this.scanQueue,
      scannerTimeout,
      discoveryTimeout,
    });

    // ─── Outputs ───────────────────────────────────────────────────────
    // FindingsBucketName / ScanQueueUrl / ScanDLQUrl / ScannerFunctionName are
    // emitted by the InspectorScanner construct itself. Only the sample-stack-
    // specific outputs are declared here.
    new CfnOutput(this, 'DiscoveryFunctionName', {
      value: this.discoveryFunction.functionName,
    });
  }
}
