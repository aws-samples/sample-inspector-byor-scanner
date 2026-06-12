import {
  CfnOutput,
  Duration,
  RemovalPolicy,
  Size,
  Stack,
  StackProps,
} from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { SqsEventSource } from 'aws-cdk-lib/aws-lambda-event-sources';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as scheduler from 'aws-cdk-lib/aws-scheduler';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';
import * as path from 'path';

export interface ScannerScheduleConfig {
  /** Cron expression in EventBridge Scheduler syntax. */
  readonly expression: string;
  /** Mode passed to the Discovery Lambda (`hourly`, `full`). */
  readonly mode: 'hourly' | 'full';
  /** Optional config block forwarded to the discovery backend. */
  readonly backendConfig?: Record<string, unknown>;
  /** Schedule retry attempts on Lambda failure. Defaults to 2. */
  readonly retryAttempts?: number;
}

export interface ScannerStackProps extends StackProps {
  /** VPC the Lambdas attach to. Must have private subnets and egress for AWS APIs. */
  readonly vpc: ec2.IVpc;

  /**
   * Hostname of the BYO container registry (e.g. ``registry.example.com``).
   * The scanner pulls images from ``${registryUrl}/<image>:<tag>`` over mTLS.
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
   * authenticate to the registry. Schema: ``{ca, cert, key}``.
   *
   * Two consumption modes:
   *  - **Test path**: pass ``MtlsRegistryAuth.clientSecret`` from the
   *    test stack (auto-generated CA + leaf certs).
   *  - **Production path**: pass an existing ``ISecret`` reference,
   *    e.g. ``secretsmanager.Secret.fromSecretNameV2(...)``.
   */
  readonly mtlsSecret: secretsmanager.ISecret;

  /** Optional KMS CMK for the findings bucket. Defaults to S3-managed (SSE-S3). */
  readonly findingsBucketKey?: kms.IKey;

  /** Optional Lambda Layer ARN with custom plugins (auth or discovery backends). */
  readonly pluginLayerArn?: string;

  /** Auth provider plugin path. Defaults to the built-in mTLS provider. */
  readonly authProvider?: string;

  /** Discovery backend plugin path. Defaults to the built-in static provider. */
  readonly discoveryBackend?: string;

  /**
   * Enable EventBridge schedules. Default true ─ first deploy starts
   * scanning automatically. Set false for sandboxes that only run
   * manual / canary scans.
   */
  readonly enableSchedules?: boolean;

  /** Schedules wired in when ``enableSchedules`` is true. Defaults to hourly + 12-hour. */
  readonly schedules?: Record<string, ScannerScheduleConfig>;

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

const DEFAULT_AUTH_PROVIDER = 'byor_scanner.backends.auth.mtls.MtlsAuth';
const DEFAULT_DISCOVERY_BACKEND =
  'byor_scanner.backends.discovery.static.StaticDiscovery';

/**
 * ADOT (AWS Distro for OpenTelemetry) Python layer. Provides Application
 * Signals + auto-instrumentation. Account 615299751070 is AWS-owned.
 *
 * Update: refresh the layer revision quarterly. ARNs are region-specific.
 */
const ADOT_LAYER_ARNS: Record<string, string> = {
  'us-west-2':
    'arn:aws:lambda:us-west-2:615299751070:layer:AWSOpenTelemetryDistroPython:32',
  'us-east-1':
    'arn:aws:lambda:us-east-1:615299751070:layer:AWSOpenTelemetryDistroPython:32',
};

const DEFAULT_SCHEDULES: Record<string, ScannerScheduleConfig> = {
  // The hourly cron skips the hours where the full cycle fires.
  hourly: {
    expression: 'cron(0 1-11,13-23 * * ? *)',
    mode: 'hourly',
    retryAttempts: 2,
  },
  full: {
    expression: 'cron(0 0,12 * * ? *)',
    mode: 'full',
    retryAttempts: 2,
  },
};

/**
 * Core scanner infrastructure.
 *
 * Deploys:
 *  - S3 bucket for findings + SBOM cache (encrypted, lifecycle-managed)
 *  - SQS queue + DLQ
 *  - Scanner Lambda (Python, x86_64, ADOT-instrumented)
 *  - Discovery Lambda (Python, x86_64, ADOT-instrumented)
 *  - Optional EventBridge schedules (hourly + 12-hourly by default)
 *  - CloudWatch alarms (DLQ depth, queue age, discovery failure)
 *
 * The Lambda zip is built by ``nx run scanner:package``. CDK consumes
 * ``packages/scanner/dist/lambda`` directly (a directory, not the zip ─
 * CDK zips it itself when uploading to S3 staging).
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
    const scannerMemoryMiB = props.scannerMemoryMiB ?? 6144;
    const scannerEphemeralStorageGiB = props.scannerEphemeralStorageGiB ?? 10;
    const sqsBatchSize = props.sqsBatchSize ?? 10;
    const sqsMaxConcurrency = props.sqsMaxConcurrency ?? 10;
    const enableSchedules = props.enableSchedules ?? true;
    const schedules = props.schedules ?? DEFAULT_SCHEDULES;
    const authProvider = props.authProvider ?? DEFAULT_AUTH_PROVIDER;
    const discoveryBackend = props.discoveryBackend ?? DEFAULT_DISCOVERY_BACKEND;

    // ─── Findings bucket ───────────────────────────────────────────────
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

    // ─── SQS queue + DLQ ───────────────────────────────────────────────
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

    // ─── Lambda layers ─────────────────────────────────────────────────
    const adotLayerArn = ADOT_LAYER_ARNS[this.region];
    if (!adotLayerArn) {
      throw new Error(
        `ADOT layer ARN unknown for region ${this.region}. Add it to ` +
          `ADOT_LAYER_ARNS in scanner-stack.ts. See ` +
          `docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Application-Signals-Lambda.html`,
      );
    }
    const adotLayer = lambda.LayerVersion.fromLayerVersionArn(
      this,
      'AdotLayer',
      adotLayerArn,
    );

    const layers: lambda.ILayerVersion[] = [adotLayer, props.binaryLayer];
    if (props.pluginLayerArn) {
      layers.push(
        lambda.LayerVersion.fromLayerVersionArn(
          this,
          'PluginLayer',
          props.pluginLayerArn,
        ),
      );
    }

    const lambdaCodePath = path.join(
      __dirname,
      '..',
      '..',
      'scanner',
      'dist',
      'lambda',
    );

    // ─── Common Lambda env (shared between scanner + discovery) ────────
    const commonEnv = {
      // ADOT ─ Application Signals
      AWS_LAMBDA_EXEC_WRAPPER: '/opt/otel-instrument',
      OTEL_AWS_APPLICATION_SIGNALS_ENABLED: 'true',
      // Powertools is used for Logger + Metrics; tracing is OTel-only.
      POWERTOOLS_TRACE_DISABLED: 'true',
    };

    // ─── Scanner Lambda ────────────────────────────────────────────────
    this.scannerFunction = new lambda.Function(this, 'ScannerLambda', {
      runtime: lambda.Runtime.PYTHON_3_11,
      // x86_64 is mandatory: skopeo + sbomgen are linux/amd64 binaries.
      // See packages/scanner/scripts/build-binaries.sh.
      architecture: lambda.Architecture.X86_64,
      handler: 'byor_scanner.scanner.handler',
      code: lambda.Code.fromAsset(lambdaCodePath),
      timeout: scannerTimeout,
      memorySize: scannerMemoryMiB,
      ephemeralStorageSize: Size.gibibytes(scannerEphemeralStorageGiB),
      tracing: lambda.Tracing.ACTIVE,
      vpc: props.vpc,
      layers,
      logRetention: logs.RetentionDays.ONE_MONTH,
      environment: {
        ...commonEnv,
        BYOR_REGISTRY_URL: props.registryUrl,
        BYOR_FINDINGS_BUCKET: this.findingsBucket.bucketName,
        BYOR_MTLS_SECRET_NAME: props.mtlsSecret.secretName,
        BYOR_AUTH_PROVIDER: authProvider,
        // Binary paths default to /opt/bin/<name> in constants.py ─ that
        // matches where the BinaryLayer mounts at runtime, so we don't
        // need explicit BYOR_SKOPEO_PATH / BYOR_SBOMGEN_PATH overrides.
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
    props.mtlsSecret.grantRead(this.scannerFunction);
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

    // Application Signals managed policy ─ required for the ADOT layer
    // to publish Application Signals metrics.
    this.scannerFunction.role!.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName(
        'CloudWatchLambdaApplicationSignalsExecutionRolePolicy',
      ),
    );

    // ─── Discovery Lambda ──────────────────────────────────────────────
    this.discoveryFunction = new lambda.Function(this, 'DiscoveryLambda', {
      runtime: lambda.Runtime.PYTHON_3_11,
      architecture: lambda.Architecture.X86_64,
      handler: 'byor_scanner.discovery_handler.handler',
      code: lambda.Code.fromAsset(lambdaCodePath),
      timeout: Duration.minutes(5),
      memorySize: 512,
      tracing: lambda.Tracing.ACTIVE,
      vpc: props.vpc,
      layers,
      logRetention: logs.RetentionDays.ONE_MONTH,
      environment: {
        ...commonEnv,
        BYOR_QUEUE_URL: this.scanQueue.queueUrl,
        BYOR_DISCOVERY_BACKEND: discoveryBackend,
      },
    });

    this.scanQueue.grantSendMessages(this.discoveryFunction);
    this.discoveryFunction.role!.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName(
        'CloudWatchLambdaApplicationSignalsExecutionRolePolicy',
      ),
    );

    // ─── EventBridge schedules (opt-in via enableSchedules) ────────────
    if (enableSchedules) {
      const schedulerRole = new iam.Role(this, 'SchedulerRole', {
        assumedBy: new iam.ServicePrincipal('scheduler.amazonaws.com'),
      });
      this.discoveryFunction.grantInvoke(schedulerRole);

      for (const [name, sched] of Object.entries(schedules)) {
        const capitalized = name.charAt(0).toUpperCase() + name.slice(1);
        new scheduler.CfnSchedule(this, `${capitalized}Schedule`, {
          scheduleExpression: sched.expression,
          flexibleTimeWindow: { mode: 'OFF' },
          target: {
            arn: this.discoveryFunction.functionArn,
            roleArn: schedulerRole.roleArn,
            input: JSON.stringify({
              mode: sched.mode,
              ...(sched.backendConfig ? { config: sched.backendConfig } : {}),
            }),
            retryPolicy: { maximumRetryAttempts: sched.retryAttempts ?? 2 },
          },
        });
      }
    }

    // ─── Alarms (the three from the design doc) ────────────────────────
    new cloudwatch.Alarm(this, 'DlqDepthAlarm', {
      alarmDescription:
        'DLQ has at least one message - a scan was permanently abandoned. ' +
        'Investigate via CloudWatch Logs Insights filtered by the message body.',
      metric: this.scanDeadLetterQueue.metricApproximateNumberOfMessagesVisible({
        period: Duration.minutes(5),
        statistic: cloudwatch.Stats.MAXIMUM,
      }),
      threshold: 0,
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
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
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
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
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    // ─── Outputs ───────────────────────────────────────────────────────
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
