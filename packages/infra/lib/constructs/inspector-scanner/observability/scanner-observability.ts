import { Aspects, Duration, Stack } from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as cr from 'aws-cdk-lib/custom-resources';
import { Construct, IConstruct } from 'constructs';
import { ScannerSlos } from './scanner-slos';
import {
  DiscoverySegment,
  IDashboardSegment,
  ScannerCoreSegment,
} from './segment';
import { BaseSlo } from './slo';

const PERIOD = Duration.minutes(5);

/**
 * Consumer-facing tuning knobs for the scanner's observability, passed through
 * `InspectorScannerProps.observability`. All optional; sensible defaults apply.
 *
 * Registry id is intentionally NOT a metric dimension (it travels in structured
 * logs), so there is no per-registry knob.
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
  /** Scan queue — drives the scan-freshness SLO and the queue-age alarm. */
  readonly queue: sqs.IQueue;
  /** Scan dead-letter queue — backs the DLQ-depth alarm. */
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
  /** The provider's `source` metric dimension. */
  readonly source: string;
  /** The provider's dedicated discovery Lambda — its errors back the failure alarm. */
  readonly discoveryFunction: lambda.IFunction;
}

/**
 * Handle returned by {@link ScannerObservability.monitorProvider}, carrying the
 * provider's failure alarm.
 */
export interface ProviderMonitor {
  readonly failureAlarm: cloudwatch.Alarm;
}

/** One metric group rendered as a single widget by {@link ScannerObservability.monitorCustom}. */
export interface CustomMetricGroup {
  /** Widget title. */
  readonly title: string;
  /** Metrics on the left Y axis. */
  readonly left?: cloudwatch.IMetric[];
  /** Metrics on the right Y axis. */
  readonly right?: cloudwatch.IMetric[];
}

/** Options for {@link ScannerObservability.monitorCustom}: arbitrary metric groups, one widget each. */
export interface CustomMonitorOptions {
  /** Metric groups; each becomes one GraphWidget on the dashboard. */
  readonly metricGroups: CustomMetricGroup[];
}

/**
 * Alarm registry: holds every alarm the facade owns plus the registered
 * actions, keeping them in sync — registering an alarm replays all known
 * actions onto it, and adding an action applies it to all known alarms. So
 * {@link ScannerObservability.addAlarmAction} routes alarms created before AND
 * after the call, regardless of order.
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
 * it for `addSegment` / `monitorCustom` / `dashboard` / `slos` / `createdAlarms`,
 * while `addAlarmAction` is also forwarded on InspectorScanner for discoverability.
 *
 * What it builds:
 *  - {@link monitorScannerCore} (called once by InspectorScanner): the system
 *    SLOs, per-operation + coarse alarms, the Application Signals discovery
 *    resource, and the scanner-core dashboard widgets.
 *  - {@link monitorProvider} (called per discovery provider): that provider's
 *    failure alarm and dashboard widgets.
 *
 * The dashboard is created up front; its widgets are filled in at synth. Each
 * `monitor*` / `addSegment` / `monitorCustom` call just records a segment, and
 * one Aspect adds all their widgets at the end — so every provider shows up no
 * matter what order things were added.
 */
export class ScannerObservability extends Construct {
  /** The BYORScan dashboard (widgets added at synth). `undefined` when `dashboard: false`. */
  public dashboard?: cloudwatch.Dashboard;

  /** SLOs minted by the facade, keyed by logical name, for grafting extra alarms. */
  public readonly slos = new Map<string, BaseSlo>();

  private readonly opts: ObservabilityOptions;
  private readonly alarms = new AlarmRegistry();
  /** Dashboard segments collected during setup; their widgets are added at synth. */
  private readonly segments: IDashboardSegment[] = [];

  constructor(scope: Construct, id: string, props: ScannerObservabilityProps = {}) {
    super(scope, id);
    this.opts = props.defaults ?? {};
    if (props.alarmAction) this.addAlarmAction(props.alarmAction);

    // Create the dashboard now so `this.dashboard` is usable right away, but
    // add its widgets later: each setup call records a segment, and the Aspect
    // below adds them all at synth, once every segment is registered. (CDK v2
    // has no onPrepare hook, so we use an Aspect; it only edits the existing
    // dashboard, never creates one.)
    if (this.opts.dashboard !== false) {
      this.dashboard = new cloudwatch.Dashboard(this, 'Dashboard', {
        dashboardName: `BYORScan-${Stack.of(this).region}`,
      });
    }

    const self = this;
    let flushed = false;
    Aspects.of(this).add({
      visit(node: IConstruct): void {
        if (flushed || node !== self || !self.dashboard) return;
        for (const segment of self.segments) {
          for (const widget of segment.widgets()) self.dashboard.addWidgets(widget);
        }
        flushed = true;
      },
    });
  }

  /**
   * Build the scanner-core observability: system SLOs and per-operation alarms
   * (via {@link ScannerSlos}), the DLQ-depth + queue-age coarse alarms, the
   * Application Signals discovery resource, and the core dashboard widgets.
   * Call once, from the InspectorScanner constructor.
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
        alarmName: `byor-scanner-dlq-depth-${Stack.of(this).region}`,
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
        alarmName: `byor-scanner-queue-age-${Stack.of(this).region}`,
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

    this.segments.push(new ScannerCoreSegment(props.scannerFunction));
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
   * to fold in alarms minted outside the facade (the scanner's coarse +
   * per-provider alarms) so a single `addAlarmAction` covers everything.
   */
  public registerAlarm(alarm: cloudwatch.Alarm): void {
    this.alarms.register(alarm);
  }

  /**
   * Build one discovery provider's observability: its failure alarm (registered
   * so `addAlarmAction` routes it) and its dashboard widgets. Called from
   * {@link InspectorScanner.addDiscoveryProvider}.
   */
  public monitorProvider(props: ProviderMonitorProps): ProviderMonitor {
    const failureAlarm = new cloudwatch.Alarm(
      this,
      `Discovery${props.id}FailureAlarm`,
      {
        alarmName: `byor-discovery-${props.id}-failure-${Stack.of(this).region}`,
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
    this.segments.push(new DiscoverySegment(props.source));
    return { failureAlarm };
  }

  /**
   * Customer extension: add a custom {@link IDashboardSegment}'s widgets to the
   * BYORScan dashboard. No-op when `dashboard: false`.
   */
  public addSegment(segment: IDashboardSegment): void {
    this.segments.push(segment);
  }

  /**
   * Customer extension: render arbitrary metric groups onto the dashboard — one
   * GraphWidget per group. No-op when `dashboard: false`.
   */
  public monitorCustom(opts: CustomMonitorOptions): void {
    this.segments.push({
      widgets: () =>
        opts.metricGroups.map(
          (group) =>
            new cloudwatch.GraphWidget({
              title: group.title,
              left: group.left,
              right: group.right,
              width: 12,
              height: 6,
            }),
        ),
    });
  }

  /** Every alarm the facade owns/tracks, for introspection and composition. */
  public get createdAlarms(): readonly cloudwatch.Alarm[] {
    return this.alarms.all;
  }
}
