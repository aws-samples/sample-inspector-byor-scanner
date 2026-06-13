import { CfnOutput, Duration, RemovalPolicy, Size, Stack } from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { SqsEventSource } from 'aws-cdk-lib/aws-lambda-event-sources';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';
import { IRepositoryAuth } from './auth';
import { IDiscoveryTrigger } from './triggers';

const ENV_REGISTRY_URL = 'BYOR_REGISTRY_URL';
const ENV_FINDINGS_BUCKET = 'BYOR_FINDINGS_BUCKET';
const ENV_QUEUE_URL = 'BYOR_QUEUE_URL';
const ENV_AUTH_PROVIDER = 'BYOR_AUTH_PROVIDER';
const ENV_DISCOVERY_BACKEND = 'BYOR_DISCOVERY_BACKEND';
const ENV_TRIGGER_SOURCE = 'BYOR_TRIGGER_SOURCE';

/**
 * ADOT (AWS Distro for OpenTelemetry) Python layer. Provides Application
 * Signals + auto-instrumentation. Account 615299751070 is AWS-owned.
 *
 * NOTE: ARNs are region-specific. Layer revisions advance independently per
 * region; refresh quarterly.
 */
const ADOT_LAYER_ARNS: Record<string, string> = {
  'us-west-2':
    'arn:aws:lambda:us-west-2:615299751070:layer:AWSOpenTelemetryDistroPython:32',
  'us-east-1':
    'arn:aws:lambda:us-east-1:615299751070:layer:AWSOpenTelemetryDistroPython:32',
};

export interface InspectorScannerProps {
  /** VPC the Lambdas attach to. Must have private subnets and egress for AWS APIs. */
  readonly vpc: ec2.IVpc;

  /**
   * Hostname of the BYO container registry (e.g. ``registry.example.com``).
   * The scanner pulls images from ``${registryUrl}/<image>:<tag>``.
   */
  readonly registryUrl: string;

  /**
   * Layer holding ``skopeo`` and ``inspector-sbomgen`` at ``/opt/bin/``.
   * Provided by ``BinaryStack``.
   */
  readonly binaryLayer: lambda.ILayerVersion;

  /**
   * Path to the scanner Lambda's deployment directory (the
   * ``packages/scanner/dist/lambda`` output of ``nx run scanner:package``).
   */
  readonly lambdaCodePath: string;

  /**
   * Repository auth ─ how the scanner Lambda authenticates to the
   * customer's container registry. Built-ins:
   * {@link MtlsRepositoryAuth}.
   */
  readonly repositoryAuth: IRepositoryAuth;

  /**
   * Trigger ─ how the discovery Lambda is invoked. Built-ins:
   * {@link S3ManifestTrigger} (default), {@link ScheduledTrigger},
   * {@link ManualTrigger}.
   */
  readonly trigger: IDiscoveryTrigger;

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
 * Reusable L3 for the Inspector BYOR scanner.
 *
 * Owns:
 *  - findings bucket (encrypted, lifecycle-managed)
 *  - SQS scan queue + DLQ
 *  - scanner Lambda (Python, x86_64, ADOT-instrumented)
 *  - discovery Lambda (Python, x86_64, ADOT-instrumented)
 *  - operational alarms (DLQ depth, queue age, discovery failures)
 *  - ADOT layer wiring
 *
 * Pluggable seams:
 *  - {@link IRepositoryAuth} ─ how the scanner authenticates to the registry
 *  - {@link IDiscoveryTrigger} ─ how the discovery Lambda gets invoked
 *    (paired 1:1 with an {@link IDiscoveryPlugin})
 *
 * Adding a new auth mode or trigger = one new file pair (TS construct
 * implementing the interface, Python plugin implementing the matching
 * `byor_scanner.protocols` protocol). The L3 doesn't change.
 */
export class InspectorScanner extends Construct {
  public readonly findingsBucket: s3.IBucket;
  public readonly scanQueue: sqs.IQueue;
  public readonly scanDeadLetterQueue: sqs.IQueue;
  public readonly scannerFunction: lambda.IFunction;
  public readonly discoveryFunction: lambda.IFunction;

  constructor(scope: Construct, id: string, props: InspectorScannerProps) {
    super(scope, id);

    const scannerTimeout = props.scannerTimeout ?? Duration.minutes(15);
    const scannerMemoryMiB = props.scannerMemoryMiB ?? 6144;
    const scannerEphemeralStorageGiB = props.scannerEphemeralStorageGiB ?? 10;
    const sqsBatchSize = props.sqsBatchSize ?? 10;
    const sqsMaxConcurrency = props.sqsMaxConcurrency ?? 10;

    // ─── Findings bucket ─────────────────────────────────────────────────
    this.findingsBucket = new s3.Bucket(this, 'FindingsBucket', {
      // Findings are valuable audit data ─ never auto-delete on stack destroy.
      removalPolicy: RemovalPolicy.RETAIN,
      enforceSSL: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: props.findingsBucketKey
        ? s3.BucketEncryption.KMS
        : s3.BucketEncryption.S3_MANAGED,
      encryptionKey: props.findingsBucketKey,
      lifecycleRules: [
        // SBOM cache: regenerable in days; keep 30d to absorb scan-cycle skew.
        { prefix: 'sboms/', expiration: Duration.days(30) },
        // Findings: keep 1 year for audit / trend analysis.
        { prefix: 'findings/', expiration: Duration.days(365) },
      ],
    });

    // ─── SQS queue + DLQ ─────────────────────────────────────────────────
    this.scanDeadLetterQueue = new sqs.Queue(this, 'ScanDLQ', {
      retentionPeriod: Duration.days(14),
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
    });

    this.scanQueue = new sqs.Queue(this, 'ScanQueue', {
      // Visibility timeout MUST exceed the scanner's max execution time so
      // the same message isn't redelivered while still being processed.
      visibilityTimeout: Duration.seconds(scannerTimeout.toSeconds() + 30),
      retentionPeriod: Duration.days(4),
      deadLetterQueue: { queue: this.scanDeadLetterQueue, maxReceiveCount: 3 },
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
    });

    // ─── ADOT layer ──────────────────────────────────────────────────────
    const region = Stack.of(this).region;
    const adotLayerArn = ADOT_LAYER_ARNS[region];
    if (!adotLayerArn) {
      throw new Error(
        `ADOT layer ARN unknown for region ${region}. Add it to ` +
          `ADOT_LAYER_ARNS in inspector-scanner.ts. See ` +
          `docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Application-Signals-Lambda.html`,
      );
    }
    const adotLayer = lambda.LayerVersion.fromLayerVersionArn(
      this,
      'AdotLayer',
      adotLayerArn,
    );

    const baseLayers: lambda.ILayerVersion[] = [adotLayer, props.binaryLayer];
    const scannerLayers = [...baseLayers];
    if (props.repositoryAuth.layer) scannerLayers.push(props.repositoryAuth.layer);
    const discoveryLayers = [...baseLayers];
    if (props.trigger.plugin.layer) discoveryLayers.push(props.trigger.plugin.layer);

    // ─── Common Lambda env (shared between scanner + discovery) ──────────
    const commonEnv = {
      // ADOT ─ Application Signals
      AWS_LAMBDA_EXEC_WRAPPER: '/opt/otel-instrument',
      OTEL_AWS_APPLICATION_SIGNALS_ENABLED: 'true',
      // Powertools is used for Logger + Metrics; tracing is OTel-only.
      POWERTOOLS_TRACE_DISABLED: 'true',
    };

    // ─── Scanner Lambda ──────────────────────────────────────────────────
    this.scannerFunction = new lambda.Function(this, 'ScannerLambda', {
      runtime: lambda.Runtime.PYTHON_3_11,
      // x86_64 is mandatory: skopeo + sbomgen are linux/amd64 binaries.
      architecture: lambda.Architecture.X86_64,
      handler: 'byor_scanner.scanner.handler',
      code: lambda.Code.fromAsset(props.lambdaCodePath),
      timeout: scannerTimeout,
      memorySize: scannerMemoryMiB,
      ephemeralStorageSize: Size.gibibytes(scannerEphemeralStorageGiB),
      tracing: lambda.Tracing.ACTIVE,
      vpc: props.vpc,
      layers: scannerLayers,
      logRetention: logs.RetentionDays.ONE_MONTH,
      environment: {
        ...commonEnv,
        [ENV_REGISTRY_URL]: props.registryUrl,
        [ENV_FINDINGS_BUCKET]: this.findingsBucket.bucketName,
        [ENV_AUTH_PROVIDER]: props.repositoryAuth.dottedPath,
        ...props.repositoryAuth.environment,
        // Binary paths default to /opt/bin/<name> in constants.py ─ matches
        // where the BinaryLayer mounts at runtime, so we don't need
        // explicit BYOR_SKOPEO_PATH / BYOR_SBOMGEN_PATH overrides.
      },
    });

    this.scannerFunction.addEventSource(
      new SqsEventSource(this.scanQueue, {
        batchSize: sqsBatchSize,
        maxConcurrency: sqsMaxConcurrency,
        reportBatchItemFailures: true,
      }),
    );

    this.findingsBucket.grantReadWrite(this.scannerFunction);
    props.repositoryAuth.grantRead(this.scannerFunction.role!);
    if (props.findingsBucketKey) {
      props.findingsBucketKey.grantEncryptDecrypt(this.scannerFunction);
    }

    // Inspector ScanSbom does not support resource-level permissions.
    // See https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazoninspector2.html
    this.scannerFunction.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['inspector-scan:ScanSbom'],
        resources: ['*'],
      }),
    );

    // Application Signals managed policy ─ required for the ADOT layer to
    // publish Application Signals metrics.
    this.scannerFunction.role!.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName(
        'CloudWatchLambdaApplicationSignalsExecutionRolePolicy',
      ),
    );

    // ─── Discovery Lambda ────────────────────────────────────────────────
    this.discoveryFunction = new lambda.Function(this, 'DiscoveryLambda', {
      runtime: lambda.Runtime.PYTHON_3_11,
      architecture: lambda.Architecture.X86_64,
      handler: 'byor_scanner.discovery_handler.handler',
      code: lambda.Code.fromAsset(props.lambdaCodePath),
      timeout: Duration.minutes(5),
      memorySize: 512,
      tracing: lambda.Tracing.ACTIVE,
      vpc: props.vpc,
      layers: discoveryLayers,
      logRetention: logs.RetentionDays.ONE_MONTH,
      environment: {
        ...commonEnv,
        [ENV_QUEUE_URL]: this.scanQueue.queueUrl,
        [ENV_DISCOVERY_BACKEND]: props.trigger.plugin.dottedPath,
        [ENV_TRIGGER_SOURCE]: props.trigger.source,
        ...props.trigger.plugin.environment,
      },
    });

    this.scanQueue.grantSendMessages(this.discoveryFunction);
    props.trigger.plugin.grantRead(this.discoveryFunction.role!);
    props.trigger.grantRead(this.discoveryFunction.role!);
    this.discoveryFunction.role!.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName(
        'CloudWatchLambdaApplicationSignalsExecutionRolePolicy',
      ),
    );

    // ─── Trigger event source binding ────────────────────────────────────
    props.trigger.bind(this, this.discoveryFunction);

    // ─── Operational alarms ──────────────────────────────────────────────
    new cloudwatch.Alarm(this, 'DlqDepthAlarm', {
      alarmDescription:
        'DLQ has at least one message - a scan was permanently abandoned. ' +
        'Investigate via CloudWatch Logs Insights filtered by the message body.',
      metric: this.scanDeadLetterQueue.metricApproximateNumberOfMessagesVisible({
        period: Duration.minutes(5),
        statistic: cloudwatch.Stats.MAXIMUM,
      }),
      threshold: 0,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    new cloudwatch.Alarm(this, 'QueueAgeAlarm', {
      alarmDescription:
        'SQS oldest message age > 14h. The scanner Lambda is not keeping ' +
        'up with the discovery rate. Check scanner errors and concurrency.',
      metric: this.scanQueue.metricApproximateAgeOfOldestMessage({
        period: Duration.minutes(5),
        statistic: cloudwatch.Stats.MAXIMUM,
      }),
      threshold: 14 * 60 * 60,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 3,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    new cloudwatch.Alarm(this, 'DiscoveryFailureAlarm', {
      alarmDescription:
        'Discovery Lambda failed - no images were enqueued for at least one ' +
        'scheduled cycle. The scanner is silently not running.',
      metric: this.discoveryFunction.metricErrors({
        period: Duration.minutes(5),
        statistic: cloudwatch.Stats.SUM,
      }),
      threshold: 0,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    // ─── Outputs ─────────────────────────────────────────────────────────
    new CfnOutput(this, 'FindingsBucketName', {
      value: this.findingsBucket.bucketName,
    });
    new CfnOutput(this, 'ScanQueueUrl', { value: this.scanQueue.queueUrl });
    new CfnOutput(this, 'ScanDLQUrl', {
      value: this.scanDeadLetterQueue.queueUrl,
    });
    new CfnOutput(this, 'ScannerFunctionName', {
      value: this.scannerFunction.functionName,
    });
    new CfnOutput(this, 'DiscoveryFunctionName', {
      value: this.discoveryFunction.functionName,
    });
  }
}
