import { CfnOutput, Duration, Stack, StackProps, Validations } from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Construct, IConstruct } from 'constructs';
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

    // Observability — SLOs, dashboard, alarms, and Application Signals
    // discovery enablement — is owned by the InspectorScanner construct
    // (scanner.observability).

    // ─── Outputs ───────────────────────────────────────────────────────
    // FindingsBucketName / ScanQueueUrl / ScanDLQUrl / ScannerFunctionName are
    // emitted by the InspectorScanner construct itself. Only the sample-stack-
    // specific outputs are declared here.
    new CfnOutput(this, 'DiscoveryFunctionName', {
      value: this.discoveryFunction.functionName,
    });

    acknowledgeNagFindings(this);
  }
}

/**
 * Granular cdk-nag finding ids. Rules that report per-finding (IAM4/IAM5) are
 * matched by the exact `RuleId[Finding]` string, so they must be acknowledged
 * finding-by-finding — acknowledging `AwsSolutions-IAM5` alone has no effect.
 */
const IAM4_BASIC =
  'AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole]';
const IAM4_VPC =
  'AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole]';
const IAM4_SIGNALS =
  'AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/CloudWatchLambdaApplicationSignalsExecutionRolePolicy]';
const IAM5_ANY_RESOURCE = 'AwsSolutions-IAM5[Resource::*]';
const IAM5_S3_READ = [
  'AwsSolutions-IAM5[Action::s3:GetBucket*]',
  'AwsSolutions-IAM5[Action::s3:GetObject*]',
  'AwsSolutions-IAM5[Action::s3:List*]',
];
const IAM5_S3_WRITE = [
  'AwsSolutions-IAM5[Action::s3:Abort*]',
  'AwsSolutions-IAM5[Action::s3:DeleteObject*]',
];

function acknowledgeNagFindings(stack: Stack): void {
  const REASON = {
    execRole:
      'CDK-default Lambda execution role. AWSLambda{Basic,VPCAccess}ExecutionRole and the Application Signals policy grant only CloudWatch Logs writes, VPC ENI management, and telemetry publication, all scoped by AWS. Least-privilege is applied to the function-specific inline policy.',
    grantWildcards:
      'Least-privilege grants use CDK-generated wildcards for object-level S3 (arn:.../<bucket>/*) and CloudWatch log streams (log-group:...:*). Amazon Inspector ScanSbom has no resource-level scoping and requires resource "*" per the API. Actions and resources are otherwise scoped to this stack.',
    cdkManaged:
      'CDK-framework-managed resource (custom-resource provider / log-retention / bucket-notifications handler). Its role and policy are generated and maintained by aws-cdk-lib, not by application code.',
  };
  const A = (path: string, ids: string[], reason: string) => {
    const target = constructAt(stack, path);
    for (const id of ids) acknowledgeFinding(target, id, reason);
  };
  const P = 'ScannerStack/Inspector';

  for (const fn of ['ScannerLambda', 'DiscoverymanifestLambda', 'DiscoveryscheduledLambda']) {
    A(`${P}/${fn}/ServiceRole/Resource`, [IAM4_BASIC, IAM4_VPC, IAM4_SIGNALS], REASON.execRole);
    A(`${P}/${fn}/Resource`, ['AwsSolutions-L1'], REASON.execRole);
  }

  A(
    `${P}/ScannerLambda/ServiceRole/DefaultPolicy/Resource`,
    [IAM5_ANY_RESOURCE, ...IAM5_S3_READ, ...IAM5_S3_WRITE,
     // Object-level grant on the findings bucket; embeds its generated logical id.
     'AwsSolutions-IAM5[Resource::<InspectorFindingsBucket1AF26623.Arn>/*]'],
    REASON.grantWildcards,
  );
  A(
    `${P}/DiscoverymanifestLambda/ServiceRole/DefaultPolicy/Resource`,
    [IAM5_ANY_RESOURCE, ...IAM5_S3_READ,
     'AwsSolutions-IAM5[Resource::<ManifestBucket41E8D4D7.Arn>/*]'],
    REASON.grantWildcards,
  );
  A(`${P}/DiscoveryscheduledLambda/ServiceRole/DefaultPolicy/Resource`, [IAM5_ANY_RESOURCE], REASON.grantWildcards);
  A(
    `${P}/NightlySchedulerRole/DefaultPolicy/Resource`,
    ['AwsSolutions-IAM5[Resource::<InspectorDiscoveryscheduledLambdaA44F2FAE.Arn>:*]'],
    REASON.grantWildcards,
  );
  A(`${P}/Observability/AppSignalsDiscovery/CustomResourcePolicy/Resource`, [IAM5_ANY_RESOURCE], REASON.cdkManaged);

  A('ScannerStack/AWS679f53fac002430cb0da5b7982bd2287/ServiceRole/Resource', [IAM4_BASIC], REASON.cdkManaged);
  A('ScannerStack/BucketNotificationsHandler050a0587b7544547bf325f094a3db834/Role/Resource', [IAM4_BASIC], REASON.cdkManaged);
  A('ScannerStack/LogRetentionaae0aa3c5b4d4f87b02d85b201efdd8a/ServiceRole/Resource', [IAM4_BASIC], REASON.cdkManaged);
  A('ScannerStack/LogRetentionaae0aa3c5b4d4f87b02d85b201efdd8a/ServiceRole/DefaultPolicy/Resource', [IAM5_ANY_RESOURCE], REASON.cdkManaged);
}

/**
 * Record a cdk-nag acknowledgement on `target`.
 *
 * Writes the acknowledgement metadata directly instead of calling
 * `Validations.acknowledge()`, because that method rejects any id containing
 * more than one `::` — which every granular IAM4/IAM5 finding id does, since
 * they embed ARNs (`Policy::arn:<AWS::Partition>:iam::aws:policy/...`). See
 * cdklabs/cdk-nag#2351 and #2359. cdk-nag reads this same metadata key when
 * deciding whether a finding is acknowledged, so the effect is identical for
 * the ids `acknowledge()` does accept.
 */
function acknowledgeFinding(target: IConstruct, id: string, reason: string): void {
  target.node.addMetadata(Validations.ACKNOWLEDGED_RULES_METADATA_KEY, {
    [id]: reason,
  });
}

/**
 * Resolve a construct from its stack-relative path (the form cdk-nag reports),
 * so acknowledgements can be attached to CDK-managed resources we hold no
 * reference to.
 */
function constructAt(stack: Stack, path: string): IConstruct {
  return path
    .split('/')
    .slice(1)
    .reduce<IConstruct>((node, id) => node.node.findChild(id), stack);
}
