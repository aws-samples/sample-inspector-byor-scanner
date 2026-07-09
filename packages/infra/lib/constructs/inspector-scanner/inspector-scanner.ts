import * as path from 'path';
import { PythonFunction } from '@aws-cdk/aws-lambda-python-alpha';
import { Aspects, CfnOutput, Duration, Lazy, RemovalPolicy, Size, Stack } from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { SqsEventSource } from 'aws-cdk-lib/aws-lambda-event-sources';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Construct, IConstruct } from 'constructs';
import {
  AddBinaryFromArchiveOptions,
  AddBinaryFromSourceOptions,
  BinaryLayer,
} from '@constructs/binary-layer';
import { IRepositoryAuth } from './auth';
import { METRIC_NAMESPACE, ObservabilityOptions, SCANNER_SERVICE, ScannerObservability, adotPythonLayer } from './observability';
import {
  DiscoveryAttachment,
  IDiscoveryProvider,
  ITrigger,
  TriggerAttachment,
} from './triggers';
import { ScannerCanary, ScannerCanaryProps } from '@constructs/canary';

/**
 * Path to the scanner Python package (`packages/scanner`). Resolved once at
 * synth time relative to this file's location: the package lives four
 * directories up at the workspace level. PythonFunction reads `pyproject.toml`
 * + `uv.lock` from this entry and bundles via `uv` inside a Lambda runtime
 * image — no external `nx run scanner:package` step required.
 */
const SCANNER_ENTRY = path.join(__dirname, '..', '..', '..', '..', 'scanner');

/**
 * Files to skip when copying the scanner package into the bundling image.
 * Excluding these keeps the Lambda zip small and prevents rsync from choking
 * on host-only artifacts (pytest cache, ruff cache, build outputs).
 */
const BUNDLE_EXCLUDES = [
  'tests',
  '.venv',
  'dist',
  '__pycache__',
  '.pytest_cache',
  '.ruff_cache',
  '.mypy_cache',
  '*.pyc',
];

/**
 * JSON map of registry id → `{ url, authProvider, authEnv, insecureTlsVerify }`
 * parsed by `config.py`. Serialized lazily at synth from `addRegistry` calls.
 * Bounded by Lambda's 4 KB env cap (~25 registries); beyond that, move the map
 * to S3/SSM.
 */
const ENV_REGISTRIES = 'BYOR_REGISTRIES';
const ENV_FINDINGS_BUCKET = 'BYOR_FINDINGS_BUCKET';
const ENV_QUEUE_URL = 'BYOR_QUEUE_URL';
const ENV_DISCOVERY_BACKEND = 'BYOR_DISCOVERY_BACKEND';
const ENV_TRIGGER_SOURCE = 'BYOR_TRIGGER_SOURCE';
const ENV_ALLOWED_SOURCE_TYPES = 'BYOR_ALLOWED_SOURCE_TYPES';

/**
 * Configuration for a single container registry attached via
 * {@link InspectorScanner.addRegistry}. A registry is *where* images live plus
 * *how* the scanner authenticates to it.
 */
export interface RegistryProps {
  /** Hostname of the registry (e.g. ``registry.example.com``). */
  readonly url: string;

  /**
   * How the scanner Lambda authenticates to this registry. The auth provider's
   * `dottedPath` + `environment` ride into the per-id entry of the
   * `BYOR_REGISTRIES` env var; its `grantRead` is wired onto the scanner role
   * eagerly when `addRegistry` is called.
   */
  readonly auth: IRepositoryAuth;

  /**
   * Skip TLS verification when pulling from this registry. Defaults to
   * ``false``. Intended only for self-signed test registries.
   */
  readonly insecureTlsVerify?: boolean;
}

/**
 * Handle returned by {@link InspectorScanner.addRegistry}. Carries the registry
 * `id` (which the discovery side stamps into scan messages) plus the resolved
 * url + auth, so callers can reach what was attached.
 */
export interface RegistryAttachment {
  /** The registry id — stamped into SQS scan messages by discovery. */
  readonly id: string;
  /** Hostname of the registry. */
  readonly url: string;
  /** The auth provider wired for this registry. */
  readonly auth: IRepositoryAuth;
  /** Whether TLS verification is skipped for this registry (test-only). */
  readonly insecureTlsVerify: boolean;
}

/**
 * Props for {@link InspectorScanner.addCanary}.
 */
export interface AddCanaryProps extends Omit<ScannerCanaryProps, 'findingsBucket'> {
  /** Bucket the canary drops its trigger manifest into. */
  readonly manifestBucket: s3.IBucket;
}

/**
 * The per-registry shape serialized into the `BYOR_REGISTRIES` env var. CamelCase
 * keys are the Python contract (parsed in `config.py`). Internal — not exported.
 */
interface RegistrySerialized {
  readonly url: string;
  readonly authProvider: string;
  readonly authEnv: Record<string, string>;
  readonly insecureTlsVerify: boolean;
}

export interface InspectorScannerProps {
  /** VPC the Lambdas attach to. Must have private subnets and egress for AWS APIs. */
  readonly vpc: ec2.IVpc;

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

  /**
   * Allowlist of accepted `sourceType` values (each becomes a findings S3 key
   * segment). Defaults to `['canary']` in the Lambda. Set to add partitions.
   */
  readonly allowedSourceTypes?: string[];

  /** Observability tuning knobs (dashboard toggle, SLO goals, etc.). */
  readonly observability?: ObservabilityOptions;
}

/**
 * Reusable L3 for the Inspector BYOR scanner.
 *
 * Owns (created at construction):
 *  - findings bucket (encrypted, lifecycle-managed)
 *  - SQS scan queue + DLQ
 *  - scanner Lambda (Python, x86_64, ADOT-instrumented)
 *  - owned binary layer (skopeo + sbomgen), attached lazily at synth
 *  - operational alarms (DLQ depth, queue age)
 *  - ADOT layer wiring
 *
 * Attached 0..N via `add*()` methods (each returns a handle), in the shape of
 * `RestApi` / `Bucket`:
 *  - {@link addRegistry} ─ a registry the scanner pulls from (url + auth + tls).
 *  - {@link addDiscoveryProvider} ─ compute that enumerates images; each gets its
 *    OWN discovery Lambda + failure alarm, fanning into the shared queue.
 *  - {@link addTrigger} ─ an event source that invokes a provider by handle.
 *    A provider with no trigger is manual-invoke only.
 *
 * Standalone: the only required input is a VPC, so a consumer can drive it
 * directly without the sample stack. New auth/discovery/trigger seams are added
 * as new {@link IRepositoryAuth} / {@link IDiscoveryProvider} / {@link ITrigger}
 * implementations without changing the L3.
 */
export class InspectorScanner extends Construct {
  public readonly findingsBucket: s3.IBucket;
  public readonly scanQueue: sqs.IQueue;
  public readonly scanDeadLetterQueue: sqs.IQueue;
  public readonly scannerFunction: lambda.IFunction;

  /**
   * The owned binary layer (skopeo + sbomgen at `/opt/bin/` on the scanner).
   * Extend it post-construction via {@link addBinaryFromSource} /
   * {@link addBinaryFromArchive} ─ it materializes lazily at synth.
   */
  public readonly binaryLayer: BinaryLayer;

  /**
   * Registries attached via {@link addRegistry}, keyed by id. Read-only view for
   * introspection + the duplicate-id guard; mutate only through `addRegistry`.
   */
  public readonly registries: ReadonlyMap<string, RegistryAttachment>;

  /** Backing store for {@link registries}; `addRegistry` is the sole writer. */
  private readonly registryMap = new Map<string, RegistryAttachment>();

  /**
   * Discovery providers attached via {@link addDiscoveryProvider}, keyed by id.
   * Read-only view; mutate only through `addDiscoveryProvider`.
   */
  public readonly discoveryProviders: ReadonlyMap<string, DiscoveryAttachment>;

  /** Backing store for {@link discoveryProviders}; `addDiscoveryProvider` is the sole writer. */
  private readonly discoveryProviderMap = new Map<string, DiscoveryAttachment>();

  /** Sources already claimed by a discovery provider, for the duplicate-source guard. */
  private readonly discoverySources = new Set<string>();

  /** Trigger ids already attached via {@link addTrigger}, for the duplicate-id guard. */
  private readonly triggerIds = new Set<string>();


  /**
   * Auth provider layers already attached to the scanner Lambda, so multiple
   * registries sharing an auth layer don't double-attach it.
   */
  private readonly attachedAuthLayers = new Set<lambda.ILayerVersion>();

  /**
   * The scanner's observability facade: SLOs, dashboard, and the alarm registry.
   * Exposed so consumers can reach `addSegment` / `monitorCustom` / `dashboard` /
   * `slos` / `createdAlarms`; InspectorScanner forwards only {@link addAlarmAction}. Owns
   * every alarm the scanner creates (DLQ depth, queue age, and each per-provider
   * discovery failure alarm) via {@link ScannerObservability.registerAlarm}, so a
   * single {@link addAlarmAction} routes them all, including providers added later.
   */
  public readonly observability: ScannerObservability;

  /**
   * Config captured at construction (VPC, ADOT layer, common env) and reused by
   * {@link addDiscoveryProvider} to build each per-provider discovery Lambda.
   */
  private readonly discoveryFactoryContext: {
    readonly vpc: ec2.IVpc;
    readonly adotLayer: lambda.ILayerVersion;
    readonly commonEnv: Record<string, string>;
  };

  constructor(scope: Construct, id: string, props: InspectorScannerProps) {
    super(scope, id);

    this.registries = this.registryMap;
    this.discoveryProviders = this.discoveryProviderMap;
    this.observability = new ScannerObservability(this, 'Observability', {
      defaults: props.observability,
    });

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
    const adotLayer = adotPythonLayer(this, 'AdotLayer', Stack.of(this).region);

    // ─── Owned binary layer (skopeo + sbomgen) ───────────────────────────
    // The construct OWNS its binary layer rather than receiving one as a prop.
    // It is pre-loaded with the exact skopeo / sbomgen specs that `BinaryStack`
    // uses, so the scanner is a standalone, reusable unit.
    this.binaryLayer = this.createBinaryLayer();

    // The eagerly-known layers. The owned BinaryLayer is intentionally NOT
    // added here ─ see the lazy-attach note below. Auth provider layers are
    // attached per-registry by `addRegistry`; discovery provider layers by
    // `addDiscoveryProvider`. So the scanner starts with just the ADOT layer.
    const baseLayers: lambda.ILayerVersion[] = [adotLayer];
    const scannerLayers = [...baseLayers];

    // ─── Common Lambda env (shared between scanner + discovery) ──────────
    const commonEnv: Record<string, string> = {
      // ADOT ─ Application Signals
      AWS_LAMBDA_EXEC_WRAPPER: '/opt/otel-instrument',
      OTEL_AWS_APPLICATION_SIGNALS_ENABLED: 'true',
      // Powertools is used for Logger + Metrics; tracing is OTel-only.
      POWERTOOLS_TRACE_DISABLED: 'true',
    };
    // Only set when overriding the Lambda default (['canary']).
    if (props.allowedSourceTypes?.length) {
      commonEnv[ENV_ALLOWED_SOURCE_TYPES] = props.allowedSourceTypes.join(',');
    }

    // Capture what `addDiscoveryProvider` needs to build per-provider discovery
    // Lambdas (VPC, ADOT layer, common env).
    this.discoveryFactoryContext = { vpc: props.vpc, adotLayer, commonEnv };

    // ─── Scanner Lambda ──────────────────────────────────────────────────
    // PythonFunction bundles `packages/scanner` at synth time inside the
    // SAM Python build image, using `uv` (auto-detected from uv.lock) to
    // resolve dependencies. No external `nx run scanner:package` step.
    this.scannerFunction = new PythonFunction(this, 'ScannerLambda', {
      runtime: lambda.Runtime.PYTHON_3_11,
      // x86_64 is mandatory: skopeo + sbomgen are linux/amd64 binaries.
      architecture: lambda.Architecture.X86_64,
      entry: SCANNER_ENTRY,
      index: 'byor_scanner/scanner.py',
      handler: 'handler',
      bundling: { assetExcludes: BUNDLE_EXCLUDES },
      timeout: scannerTimeout,
      memorySize: scannerMemoryMiB,
      ephemeralStorageSize: Size.gibibytes(scannerEphemeralStorageGiB),
      tracing: lambda.Tracing.ACTIVE,
      vpc: props.vpc,
      layers: scannerLayers,
      logRetention: logs.RetentionDays.ONE_MONTH,
      environment: {
        ...commonEnv,
        OTEL_SERVICE_NAME: 'byor-scanner',
        [ENV_FINDINGS_BUCKET]: this.findingsBucket.bucketName,
        // Registry url + auth come from the per-registry BYOR_REGISTRIES map
        // (added lazily below from `addRegistry` calls), NOT a single global.
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

    // ─── Lazy BYOR_REGISTRIES env var ────────────────────────────────────
    // Registries arrive via `addRegistry` AFTER construction, so this value
    // MUST be a Lazy token: computing it eagerly here would serialize an empty
    // map. CDK resolves the produce callback at synth, after all `addRegistry`
    // calls have run. `grantRead` IAM wiring happens eagerly inside
    // `addRegistry` (grants compose additively).
    (this.scannerFunction as lambda.Function).addEnvironment(
      ENV_REGISTRIES,
      Lazy.string({ produce: () => JSON.stringify(this.serializeRegistries()) }),
    );

    this.findingsBucket.grantReadWrite(this.scannerFunction);
    // Registry auth is granted per-registry in `addRegistry` (each registry's
    // auth provider wires its own `grantRead` onto the scanner role).
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

    // ─── Discovery Lambdas ───────────────────────────────────────────────
    // Discovery is fully methodful: each provider attached via
    // `addDiscoveryProvider` gets its OWN discovery Lambda (own backend,
    // source, and failure alarm) fanning into the shared scan queue. The
    // construct builds NO discovery Lambda eagerly ─ a scanner with no
    // providers simply has nothing enqueuing scans yet.

    // ─── Lazy binary-layer attach (Aspect) ───────────────────────────────
    // Reading `binaryLayer.layer` freezes the builder, so we can't attach in
    // the constructor without breaking post-construction `addBinary*`. Defer to
    // synth via an Aspect, which runs after the consumer's `addBinary*` calls.
    // Scanner only: discovery Lambdas never exec skopeo/sbomgen. The `attached`
    // flag keeps it idempotent if Aspect stabilization re-traverses.
    const scannerFn = this.scannerFunction;
    const owner = this;
    let attached = false;
    Aspects.of(this).add({
      visit(node: IConstruct): void {
        if (attached || node !== scannerFn) return;
        (scannerFn as lambda.Function).addLayers(owner.binaryLayer.layer);
        attached = true;
      },
    });

    // ─── Observability (SLOs, dashboard, and the alarm registry) ─────────
    // The facade owns the DLQ-depth + queue-age coarse alarms, the system SLOs,
    // and the dashboard. Per-provider discovery failure alarms are registered
    // from `addDiscoveryProvider`.
    this.observability.monitorScannerCore({
      scannerFunction: this.scannerFunction,
      queue: this.scanQueue,
      dlq: this.scanDeadLetterQueue,
      scannerTimeout,
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
  }

  /**
   * Add a binary built from source (via Docker) to the owned layer, chainable.
   * Safe to call after construction (the layer materializes at synth).
   *
   * @param name  Filename under `bin/` in the layer.
   * @param opts  Build image (digest-pinned) + command.
   */
  public addBinaryFromSource(
    name: string,
    opts: AddBinaryFromSourceOptions,
  ): this {
    this.binaryLayer.addBinaryFromSource(name, opts);
    return this;
  }

  /**
   * Add a binary downloaded + extracted from a zip to the owned layer, chainable.
   * Safe to call after construction (the layer materializes at synth).
   *
   * @param name  Filename under `bin/` in the layer.
   * @param opts  URL + SHA256 + (optional) path inside the archive.
   */
  public addBinaryFromArchive(
    name: string,
    opts: AddBinaryFromArchiveOptions,
  ): this {
    this.binaryLayer.addBinaryFromArchive(name, opts);
    return this;
  }

  /**
   * Attach a registry the scanner can pull from (url + auth). Returns a handle
   * whose `id` rides into scan messages. Wires `auth.grantRead` + any auth layer
   * onto the scanner eagerly; the `BYOR_REGISTRIES` entry is serialized lazily at
   * synth, so call order doesn't matter. Throws on a duplicate `id`.
   *
   * @param id    Unique registry id, stamped into SQS scan messages by discovery.
   * @param props Registry url + auth (+ optional `insecureTlsVerify`).
   */
  public addRegistry(id: string, props: RegistryProps): RegistryAttachment {
    InspectorScanner.validateId('registry', id);
    if (this.registryMap.has(id)) {
      throw new Error(
        `InspectorScanner already has a registry with id '${id}'. ` +
          'Registry ids must be unique.',
      );
    }

    // Grants compose additively onto the scanner role, which already exists.
    props.auth.grantRead(this.scannerFunction.role!);

    // Attach the auth provider's layer (if any) to the scanner Lambda, mirroring
    // how the constructor attaches `repositoryAuth.layer`. Guard against
    // attaching the same layer twice across multiple registries.
    if (props.auth.layer) {
      const fn = this.scannerFunction as lambda.Function;
      if (!this.attachedAuthLayers.has(props.auth.layer)) {
        fn.addLayers(props.auth.layer);
        this.attachedAuthLayers.add(props.auth.layer);
      }
    }

    const attachment: RegistryAttachment = {
      id,
      url: props.url,
      auth: props.auth,
      insecureTlsVerify: props.insecureTlsVerify ?? false,
    };
    this.registryMap.set(id, attachment);
    return attachment;
  }

  /**
   * Attach a discovery provider ─ compute that enumerates images and fans them
   * into the shared scan queue. Each provider gets its OWN discovery Lambda
   * (own backend, `source`, and failure alarm) so one failing source can't hide
   * behind an aggregate alarm. Wires the queue send-grant + the provider's
   * `grantRead`/`layer` onto that Lambda. Throws on a duplicate `id`/`source`,
   * or if a `provider.registries[*]` handle wasn't added to THIS scanner.
   *
   * @param id       Unique provider id, also used as the discovery `source`.
   * @param provider The {@link IDiscoveryProvider} describing the backend.
   */
  public addDiscoveryProvider(
    id: string,
    provider: IDiscoveryProvider,
  ): DiscoveryAttachment {
    InspectorScanner.validateId('discovery provider', id);
    if (this.discoveryProviderMap.has(id)) {
      throw new Error(
        `InspectorScanner already has a discovery provider with id '${id}'. ` +
          'Provider ids must be unique.',
      );
    }

    const source = id;
    if (this.discoverySources.has(source)) {
      throw new Error(
        `InspectorScanner already has a discovery provider with source ` +
          `'${source}'. Discovery sources must be unique.`,
      );
    }

    // Reject registry handles that were not added to THIS scanner ─ a foreign
    // handle would silently bind the provider to a registry it cannot route to.
    for (const registry of provider.registries ?? []) {
      if (this.registryMap.get(registry.id) !== registry) {
        throw new Error(
          `Discovery provider '${id}' references registry '${registry.id}', ` +
            'which was not added to this InspectorScanner via addRegistry(). ' +
            'Add the registry to this scanner first, and pass the handle it ' +
            'returns.',
        );
      }
    }

    const { vpc, adotLayer, commonEnv } = this.discoveryFactoryContext;
    const discoveryLayers: lambda.ILayerVersion[] = [adotLayer];
    if (provider.layer) discoveryLayers.push(provider.layer);

    const fn = new PythonFunction(this, `Discovery${id}Lambda`, {
      runtime: lambda.Runtime.PYTHON_3_11,
      architecture: lambda.Architecture.X86_64,
      entry: SCANNER_ENTRY,
      index: 'byor_scanner/discovery_handler.py',
      handler: 'handler',
      bundling: { assetExcludes: BUNDLE_EXCLUDES },
      timeout: Duration.minutes(5),
      memorySize: 512,
      tracing: lambda.Tracing.ACTIVE,
      vpc,
      layers: discoveryLayers,
      logRetention: logs.RetentionDays.ONE_MONTH,
      environment: {
        ...commonEnv,
        OTEL_SERVICE_NAME: 'byor-discovery',
        [ENV_QUEUE_URL]: this.scanQueue.queueUrl,
        [ENV_DISCOVERY_BACKEND]: provider.dottedPath,
        [ENV_TRIGGER_SOURCE]: source,
        ...provider.environment,
      },
    });

    this.scanQueue.grantSendMessages(fn);
    provider.grantRead(fn.role!);
    fn.role!.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName(
        'CloudWatchLambdaApplicationSignalsExecutionRolePolicy',
      ),
    );

    // Per-provider observability (failure alarm + dashboard widgets), owned by
    // the facade and carried on the handle.
    const monitor = this.observability.monitorProvider({
      id,
      source,
      discoveryFunction: fn,
    });

    const attachment: DiscoveryAttachment = {
      id,
      source,
      discoveryFunction: fn,
      failureAlarm: monitor.failureAlarm,
    };
    this.discoveryProviderMap.set(id, attachment);
    this.discoverySources.add(source);
    return attachment;
  }

  /**
   * Attach a trigger ─ an event source (S3 manifest drop, EventBridge schedule)
   * that invokes a discovery provider's Lambda. The trigger references the
   * provider it fires by handle ({@link ITrigger.discovery}); a provider with no
   * trigger is manual-invoke only. Binds the event source onto the provider's
   * Lambda. Throws on a duplicate `id`, or if the discovery handle belongs to a
   * different scanner instance.
   *
   * @param id      Unique trigger id, echoed onto the returned handle.
   * @param trigger The {@link ITrigger} wiring the event source.
   */
  public addTrigger(id: string, trigger: ITrigger): TriggerAttachment {
    InspectorScanner.validateId('trigger', id);
    if (this.triggerIds.has(id)) {
      throw new Error(
        `InspectorScanner already has a trigger with id '${id}'. ` +
          'Trigger ids must be unique.',
      );
    }

    // The referenced discovery handle MUST be one this scanner produced ─
    // identity comparison against our own map rejects foreign handles.
    if (this.discoveryProviderMap.get(trigger.discovery.id) !== trigger.discovery) {
      throw new Error(
        `Trigger '${id}' references a discovery provider ` +
          `('${trigger.discovery.id}') that does not belong to this ` +
          'InspectorScanner. Pass the handle returned by this scanner\'s ' +
          'addDiscoveryProvider().',
      );
    }

    const discoveryFn = trigger.discovery.discoveryFunction;
    trigger.bind(this, discoveryFn);
    trigger.grantInvoke(discoveryFn.role!);

    // A trigger that stamps its own `source` tells the dashboard which sources
    // to graph. Without this, the widget queries the provider id, which that
    // trigger never emits, and stays empty.
    const metricSources = trigger.metricSources?.();
    if (metricSources?.length) {
      this.observability.setDiscoverySources(trigger.discovery.id, metricSources);
    }

    this.triggerIds.add(id);
    return { id, discovery: trigger.discovery };
  }

  /**
   * Route an action (e.g. an SNS notification) to every alarm the scanner owns:
   * the DLQ-depth and queue-age alarms plus each per-provider discovery failure
   * alarm. Idempotent across providers added later ─ the action is replayed onto
   * alarms created by subsequent {@link addDiscoveryProvider} calls, so order
   * doesn't matter.
   */
  public addAlarmAction(action: cloudwatch.IAlarmAction): void {
    this.observability.addAlarmAction(action);
  }

  /**
   * Attach a CloudWatch Synthetics canary that validates the scan pipeline
   * end-to-end. Puts a manifest into `manifestBucket`, then polls
   * `findingsBucket` for new findings.
   *
   * Can be called multiple times with different ids to test different images.
   */
  public addCanary(
    id: string,
    props: AddCanaryProps,
  ): ScannerCanary {
    const canary = new ScannerCanary(this, `Canary${id}`, {
      ...props,
      findingsBucket: this.findingsBucket,
    });

    // Auto-delete canary findings after 3 days to avoid accumulation.
    (this.findingsBucket as s3.Bucket).addLifecycleRule({
      prefix: 'findings/canary/',
      expiration: Duration.days(3),
    });

    // Ensure VPC-attached discovery Lambdas are fully initialized before the canary starts.
    for (const [, provider] of this.discoveryProviderMap) {
      canary.node.addDependency(provider.discoveryFunction);
    }

    return canary;
  }

  /**
   * The scanner's `ImagesFailed` count (a per-image scan failure). Returns a
   * fresh {@link cloudwatch.Metric} each call so callers can alarm on or graph
   * it; defaults to SUM over 5 minutes.
   */
  public metricScanFailures(
    opts?: cloudwatch.MetricOptions,
  ): cloudwatch.Metric {
    return new cloudwatch.Metric({
      namespace: METRIC_NAMESPACE,
      metricName: 'ImagesFailed',
      // Scope to the Powertools `service` default dimension so this reads the
      // same series the dashboard graphs. The dimensionless ImagesFailed metric
      // has no data — every emitted datapoint carries at least `service`.
      dimensionsMap: { service: SCANNER_SERVICE },
      statistic: cloudwatch.Stats.SUM,
      period: Duration.minutes(5),
      ...opts,
    });
  }

  /**
   * Validate that an `add*()` id is a safe CDK construct-id token. Caller ids
   * flow into construct ids (e.g. ``Discovery${id}Lambda``); spaces, dots, or
   * symbols would munge CloudFormation logical ids unpredictably and two ids
   * differing only in punctuation could collide after sanitization.
   */
  private static validateId(kind: string, id: string): void {
    if (!/^[A-Za-z0-9]+$/.test(id)) {
      throw new Error(
        `InspectorScanner ${kind} id '${id}' is invalid. Ids must be ` +
          'alphanumeric ([A-Za-z0-9]+) ─ they become CDK construct ids.',
      );
    }
  }

  /**
   * Serialize attached registries into the camelCase JSON the Python runtime
   * parses from `BYOR_REGISTRIES`. Run from the `Lazy.string` produce callback
   * at synth. `authEnv` is nested per id (not flattened) so registries sharing
   * an auth provider don't collide on a shared env var.
   */
  private serializeRegistries(): Record<string, RegistrySerialized> {
    const out: Record<string, RegistrySerialized> = {};
    for (const [id, a] of this.registryMap) {
      out[id] = {
        url: a.url,
        authProvider: a.auth.dottedPath,
        authEnv: a.auth.environment,
        insecureTlsVerify: a.insecureTlsVerify,
      };
    }

    // Fail at synth (not with an opaque CloudFormation error) if the map nears
    // Lambda's 4 KB env cap; ~1 KB is reserved for the other env vars.
    const json = JSON.stringify(out);
    const BUDGET_BYTES = 3 * 1024;
    if (Buffer.byteLength(json, 'utf8') > BUDGET_BYTES) {
      throw new Error(
        `BYOR_REGISTRIES is ${Buffer.byteLength(json, 'utf8')} bytes, over the ` +
          `~${BUDGET_BYTES}-byte budget (Lambda's total env is capped at 4 KB). ` +
          'Reduce the number of registries, or move the registry map to S3/SSM.',
      );
    }
    return out;
  }

  /**
   * Create the owned binary layer, pre-loaded with skopeo (v1.23.0, source) +
   * inspector-sbomgen (1.14.1). Specs kept identical to `BinaryStack` so the
   * scanner and the test seeder share one asset-hashed layer build.
   */
  private createBinaryLayer(): BinaryLayer {
    const layer = new BinaryLayer(this, 'BinaryLayer', {
      description: 'skopeo + inspector-sbomgen for the BYOR scanner pipeline',
      compatibleArchitectures: [lambda.Architecture.X86_64],
      compatibleRuntimes: [lambda.Runtime.PYTHON_3_11],
    });

    layer.addBinaryFromSource('skopeo', {
      // Pinned by digest. Refresh in lockstep with the sbomgen entry below.
      buildImage:
        'golang:1.25-alpine@sha256:7143573479a34302243c6f8c33cf6c49fdde44c60e8f5dda0591adf0006cdc77',
      buildCommand: [
        'sh',
        '-c',
        [
          'apk add --no-cache git bash make',
          'git clone --depth 1 --branch v1.23.0 https://github.com/containers/skopeo /src',
          'cd /src',
          'DISABLE_CGO=1 CGO_ENABLED=0 make bin/skopeo.linux.amd64 DISABLE_DOCS=1',
          'cp /src/bin/skopeo.linux.amd64 /asset-output/skopeo',
        ].join(' && '),
      ],
    });

    layer.addBinaryFromArchive('inspector-sbomgen', {
      url: 'https://amazon-inspector-sbomgen.s3.amazonaws.com/1.14.1/linux/amd64/inspector-sbomgen.zip',
      sha256: '2b9512ea9acdc1eb1aa155f7f664f92b4dc96e14d3849fe1f1d3aa51f481b627',
      binaryInArchive: 'inspector-sbomgen-1.14.1/linux/amd64/inspector-sbomgen',
    });

    return layer;
  }
}
