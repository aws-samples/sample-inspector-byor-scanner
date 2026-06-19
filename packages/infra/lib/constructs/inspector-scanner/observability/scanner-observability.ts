import { Duration, Stack } from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as cr from 'aws-cdk-lib/custom-resources';
import { Construct } from 'constructs';
import { ScannerSlos } from './scanner-slos';
import {
  DiscoverySegment,
  IDashboardSegment,
  ScannerCoreSegment,
} from './segment';
import { BaseSlo } from './slo';

const PERIOD = Duration.minutes(5);

/**
 * Consumer-facing tuning knobs for the scanner's observability layer. Passed
 * through `InspectorScannerProps.observability` and forwarded to the facade as
 * its defaults. All optional; sensible defaults are applied per field.
 *
 * NOTE: only `dashboard` is consumed today (scanner-core tier). The remaining
 * knobs are the public surface for the per-provider SLO tier and are wired up
 * in the follow-up observability PR. Registry id is intentionally NOT a metric
 * dimension (it travels in structured logs), so there is no per-registry knob.
 */
export interface ObservabilityOptions {
  /** Whether to build the BYORScan dashboard. @default true */
  readonly dashboard?: boolean;
  /** Scanner + provider availability SLO goal (percent). @default 99.9 */
  readonly availabilityGoal?: number;
  /** Latency SLO target as a ratio of the function timeout. @default 0.8 */
  readonly latencyTargetRatio?: number;
  /** Scan-freshness SLO + queue-age alarm threshold. @default Duration.hours(14) */
  readonly freshnessThreshold?: Duration;
  /** New-image-coverage p99 threshold. @default Duration.minutes(60) */
  readonly coverageThreshold?: Duration;
  /** Burn-rate look-back windows. @default [1h, 6h, 24h] */
  readonly burnRateWindows?: Duration[];
  /** Opt OUT of per-provider availability/latency SLOs. @default true (SLOs on) */
  readonly providerSlos?: boolean;
}

/** Props for {@link ScannerObservability}. */
export interface ScannerObservabilityProps {
  /** Tuning knobs (from `InspectorScannerProps.observability`). */
  readonly defaults?: ObservabilityOptions;
  /**
   * Initial alarm action applied as a default (equivalent to calling
   * {@link ScannerObservability.addAlarmAction} once). @default - none
   */
  readonly alarmAction?: cloudwatch.IAlarmAction;
}

/** Inputs for the eager scanner-core observability tier ({@link ScannerObservability.monitorScannerCore}). */
export interface ScannerCoreProps {
  /** Scanner Lambda — its log group backs the Logs Insights widgets. */
  readonly scannerFunction: lambda.IFunction;
  /** Scan queue — drives the scan-freshness SLO (and, in PR B, the queue-age alarm). */
  readonly queue: sqs.IQueue;
  /** Scan dead-letter queue — backs the DLQ-depth alarm (relocated here in PR B). */
  readonly dlq: sqs.IQueue;
  /** Scanner Lambda timeout — used for the system SLOs. */
  readonly scannerTimeout: Duration;
  /**
   * Discovery Lambda timeout. Vestigial: {@link ScannerSlos} still requires it
   * but does not consume it. @default Duration.minutes(5)
   */
  readonly discoveryTimeout?: Duration;
}

/** Inputs for the eager per-provider tier ({@link ScannerObservability.monitorProvider}). */
export interface ProviderMonitorProps {
  /** Provider id (becomes part of the alarm's construct id). */
  readonly id: string;
  /** The provider's `source` (metric dimension); used for per-provider SLOs in the follow-up PR. */
  readonly source: string;
  /** The provider's dedicated discovery Lambda — its errors back the failure alarm. */
  readonly discoveryFunction: lambda.IFunction;
}

/**
 * Handle returned by {@link ScannerObservability.monitorProvider}. Carries the
 * per-provider failure alarm; availability/latency SLOs are added to it in the
 * follow-up PR.
 */
export interface ProviderMonitor {
  readonly failureAlarm: cloudwatch.Alarm;
}

/**
 * Alarm registry — borrowed from cdk-monitoring's "created-alarms + default
 * action" idea. Holds every alarm the facade owns plus the list of registered
 * actions, and keeps them in sync: registering an alarm replays all known
 * actions onto it, and adding an action applies it to all known alarms. Net
 * effect: {@link ScannerObservability.addAlarmAction} routes alarms minted
 * before AND after the call, regardless of order.
 *
 * Mirrors the semantics the {@link InspectorScanner} alarm registry uses today,
 * so the L3's alarms fold into this registry cleanly in a later step.
 */
class AlarmRegistry {
  /** Every alarm the facade owns (read-only view via {@link ScannerObservability.createdAlarms}). */
  public readonly all: cloudwatch.Alarm[] = [];
  private readonly actions: cloudwatch.IAlarmAction[] = [];

  /** Track an alarm and back-fill any actions already registered. */
  public register(alarm: cloudwatch.Alarm): void {
    this.all.push(alarm);
    for (const action of this.actions) alarm.addAlarmAction(action);
  }

  /** Register an action and apply it to every alarm tracked so far. */
  public addAction(action: cloudwatch.IAlarmAction): void {
    this.actions.push(action);
    for (const alarm of this.all) alarm.addAlarmAction(action);
  }
}

/**
 * The scanner's observability facade, owned by {@link InspectorScanner} and
 * exposed as `scanner.observability`. One facade per scanner; consumers reach
 * it for `addSegment` / `monitorCustom` / `dashboard` / `slos` / `createdAlarms`
 * while only `addAlarmAction` is forwarded onto the L3 for discoverability.
 *
 * Lifecycle tiers:
 *  - **scanner-core** (eager) — {@link monitorScannerCore}, called once from the
 *    L3 constructor: system SLOs (+ per-operation alarms) and the dashboard.
 *  - **per-provider** (eager) — `monitorProvider`, called from
 *    `addDiscoveryProvider`: availability/latency SLOs + failure alarm. *(Added
 *    in the per-provider PR.)*
 *  - **aggregate** (lazy) — the dashboard is assembled from registered segments
 *    at synth. *(Becomes segment-based in the per-provider PR; built eagerly in
 *    {@link monitorScannerCore} for now.)*
 */
export class ScannerObservability extends Construct {
  /** The BYORScan dashboard. `undefined` when `dashboard: false`. */
  public dashboard?: cloudwatch.Dashboard;

  /** Every SLO this facade minted, keyed by logical name (populated per-provider in the next PR). */
  public readonly slos = new Map<string, BaseSlo>();

  private readonly opts: ObservabilityOptions;
  private readonly alarms = new AlarmRegistry();

  constructor(scope: Construct, id: string, props: ScannerObservabilityProps = {}) {
    super(scope, id);
    this.opts = props.defaults ?? {};
    if (props.alarmAction) this.addAlarmAction(props.alarmAction);
  }

  /**
   * Build the eager scanner-core tier: system SLOs (+ per-operation alarms) and
   * the dashboard. Call once, from the L3 constructor.
   *
   * For now this reuses {@link ScannerSlos} verbatim and builds the dashboard
   * eagerly; the per-provider PR splits this into a `ScannerCoreSegment` and
   * relocates the DLQ-depth / queue-age alarms here from the L3.
   */
  public monitorScannerCore(props: ScannerCoreProps): void {
    // Enable Application Signals discovery at the account level so the
    // instrumented Lambdas surface as services for the SLOs to bind to.
    // StartDiscovery is idempotent and account-wide.
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

    // System SLOs + per-operation alarms; register the alarms so addAlarmAction
    // routes them (no SNS topic is created).
    const slos = new ScannerSlos(this, 'Slos', {
      queue: props.queue,
      scannerTimeout: props.scannerTimeout,
      discoveryTimeout: props.discoveryTimeout ?? Duration.minutes(5),
    });
    for (const alarm of slos.alarms) this.registerAlarm(alarm);

    // Coarse operational alarms (owned by the facade; the per-provider discovery
    // failure alarms are registered from InspectorScanner.addDiscoveryProvider).
    this.registerAlarm(
      new cloudwatch.Alarm(this, 'DlqDepthAlarm', {
        alarmDescription:
          'DLQ has at least one message - a scan was permanently abandoned. ' +
          'Investigate via CloudWatch Logs Insights filtered by the message body.',
        metric: props.dlq.metricApproximateNumberOfMessagesVisible({
          period: PERIOD,
          statistic: cloudwatch.Stats.MAXIMUM,
        }),
        threshold: 0,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
    );

    this.registerAlarm(
      new cloudwatch.Alarm(this, 'QueueAgeAlarm', {
        alarmDescription:
          'SQS oldest message age > 14h. The scanner Lambda is not keeping ' +
          'up with the discovery rate. Check scanner errors and concurrency.',
        metric: props.queue.metricApproximateAgeOfOldestMessage({
          period: PERIOD,
          statistic: cloudwatch.Stats.MAXIMUM,
        }),
        threshold: 14 * 60 * 60,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        evaluationPeriods: 3,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
    );

    this.renderSegment(new ScannerCoreSegment(props.scannerFunction));
  }

  /**
   * Route an action to every alarm the facade owns. Idempotent across alarms
   * registered later (the action is replayed onto them), so call order doesn't
   * matter. Call 0..N times — each call adds another destination. No SNS topic
   * is created by the facade.
   */
  public addAlarmAction(action: cloudwatch.IAlarmAction): void {
    this.alarms.addAction(action);
  }

  /**
   * Register an alarm with the facade so {@link addAlarmAction} routes it. Used
   * to fold in alarms minted outside the facade (the L3's coarse + per-provider
   * alarms) so a single `addAlarmAction` covers everything.
   */
  public registerAlarm(alarm: cloudwatch.Alarm): void {
    this.alarms.register(alarm);
  }

  /**
   * Build the eager per-provider tier for one discovery provider: its failure
   * alarm (registered so `addAlarmAction` routes it). The follow-up PR adds
   * availability/latency SLOs to the returned handle. Called from
   * {@link InspectorScanner.addDiscoveryProvider}.
   */
  public monitorProvider(props: ProviderMonitorProps): ProviderMonitor {
    const failureAlarm = new cloudwatch.Alarm(
      this,
      `Discovery${props.id}FailureAlarm`,
      {
        alarmDescription:
          `Discovery provider '${props.id}' failed - no images were enqueued ` +
          'for at least one cycle. The scanner is silently not running for ' +
          'this source.',
        metric: props.discoveryFunction.metricErrors({
          period: PERIOD,
          statistic: cloudwatch.Stats.SUM,
        }),
        threshold: 0,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      },
    );
    this.registerAlarm(failureAlarm);
    this.renderSegment(new DiscoverySegment(props.source, failureAlarm));
    return { failureAlarm };
  }

  /** Every alarm the facade owns/tracks, for introspection and composition. */
  public get createdAlarms(): readonly cloudwatch.Alarm[] {
    return this.alarms.all;
  }

  // ─── internals ───────────────────────────────────────────────────────

  /**
   * Lazily create the BYORScan dashboard. The name stays region-qualified
   * because CloudWatch dashboard names are account-global. Returns undefined
   * when `dashboard: false`.
   */
  private ensureDashboard(): cloudwatch.Dashboard | undefined {
    if (this.opts.dashboard === false) return undefined;
    if (!this.dashboard) {
      this.dashboard = new cloudwatch.Dashboard(this, 'Dashboard', {
        dashboardName: `BYORScan-${Stack.of(this).region}`,
      });
    }
    return this.dashboard;
  }

  /**
   * Render a segment onto the dashboard — one dashboard row per widget the
   * segment returns. Core renders eagerly from `monitorScannerCore`; each
   * provider appends its row from `monitorProvider`.
   */
  private renderSegment(segment: IDashboardSegment): void {
    const dashboard = this.ensureDashboard();
    if (!dashboard) return;
    for (const widget of segment.widgets()) dashboard.addWidgets(widget);
  }
}
