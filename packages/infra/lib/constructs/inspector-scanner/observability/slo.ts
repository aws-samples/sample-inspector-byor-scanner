import { Duration } from 'aws-cdk-lib';
import * as applicationsignals from 'aws-cdk-lib/aws-applicationsignals';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cloudwatchActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as sns from 'aws-cdk-lib/aws-sns';
import { Construct } from 'constructs';

/** Application Signals SLI comparison operators. */
export type SloComparisonOperator =
  | 'GreaterThanOrEqualTo'
  | 'GreaterThan'
  | 'LessThanOrEqualTo'
  | 'LessThan';

/** Shared props for every SLO type. */
export interface SloBaseProps {
  /** Unique SLO name. */
  readonly sloName: string;

  /** Human-readable description. */
  readonly description: string;

  /** Attainment target percentage (e.g. 99.9). */
  readonly attainmentGoal: number;

  /** Warning threshold percentage. @default - none */
  readonly warningThreshold?: number;

  /** Rolling evaluation window. @default Duration.days(1) */
  readonly rollingInterval?: Duration;

  /** Burn-rate look-back windows. @default [Duration.hours(1), Duration.hours(6)] */
  readonly burnRateWindows?: Duration[];

  /**
   * SNS topic for a burn-rate alarm on the first look-back window.
   * @default - no alarm is created (the SLO is an attainment objective only)
   */
  readonly alarmTopic?: sns.ITopic;
}

/** The SLI portion of an SLO — exactly one is supplied by each subclass. */
type SloDefinition = Pick<
  applicationsignals.CfnServiceLevelObjectiveProps,
  'sli' | 'requestBasedSli'
>;

/**
 * Base for all SLO constructs. Owns the common pieces — goal resolution, the
 * `CfnServiceLevelObjective` resource, and the optional burn-rate alarm — so
 * each subclass only supplies its SLI definition.
 */
export abstract class BaseSlo extends Construct {
  public readonly sloResource: applicationsignals.CfnServiceLevelObjective;
  public readonly alarm?: cloudwatch.Alarm;

  protected constructor(
    scope: Construct,
    id: string,
    props: SloBaseProps,
    definition: SloDefinition,
  ) {
    super(scope, id);

    const { goalConfig, burnRateConfigurations, firstWindowMinutes } =
      resolveGoal(props);

    this.sloResource = new applicationsignals.CfnServiceLevelObjective(
      this,
      'Resource',
      {
        name: props.sloName,
        description: props.description,
        ...definition,
        goal: goalConfig,
        burnRateConfigurations,
      },
    );

    this.alarm = createBurnRateAlarm(this, props, firstWindowMinutes);
  }
}

// ─── Service-bound SLO ──────────────────────────────────────────────────

export interface ServiceSloProps extends SloBaseProps {
  /** Application Signals service name (the OTel service name). */
  readonly serviceName: string;

  /** Metric type to measure. */
  readonly metricType: 'AVAILABILITY' | 'LATENCY';

  /** Statistic for LATENCY (e.g. 'p99'). @default - unused for AVAILABILITY */
  readonly statistic?: string;

  /** Threshold value (milliseconds for LATENCY, percent for AVAILABILITY). */
  readonly threshold: number;

  /** Application Signals environment. @default 'lambda:default' */
  readonly environment?: string;
}

/** Service-bound SLO — trace-correlated via Application Signals. */
export class ServiceSlo extends BaseSlo {
  constructor(scope: Construct, id: string, props: ServiceSloProps) {
    super(scope, id, props, {
      sli: {
        sliMetric: {
          keyAttributes: {
            Type: 'Service',
            Name: props.serviceName,
            Environment: props.environment ?? 'lambda:default',
          },
          metricType: props.metricType,
          ...(props.statistic && { statistic: props.statistic }),
          periodSeconds: 60,
        },
        metricThreshold: props.threshold,
        comparisonOperator:
          props.metricType === 'AVAILABILITY'
            ? 'GreaterThanOrEqualTo'
            : 'LessThanOrEqualTo',
      },
    });
  }
}

// ─── Request-based SLO ──────────────────────────────────────────────────

export interface RequestBasedSloProps extends SloBaseProps {
  /** Metric queries defining the total request count. */
  readonly totalRequestCountMetric: applicationsignals.CfnServiceLevelObjective.MetricDataQueryProperty[];

  /** Metric queries defining the good request count. Provide this OR badCountMetric. */
  readonly goodCountMetric?: applicationsignals.CfnServiceLevelObjective.MetricDataQueryProperty[];

  /** Metric queries defining the bad request count. Provide this OR goodCountMetric. */
  readonly badCountMetric?: applicationsignals.CfnServiceLevelObjective.MetricDataQueryProperty[];
}

/** Request-based SLO — good/total (or bad/total) ratio from custom metrics. */
export class RequestBasedSlo extends BaseSlo {
  constructor(scope: Construct, id: string, props: RequestBasedSloProps) {
    if (!props.goodCountMetric && !props.badCountMetric) {
      throw new Error(
        `RequestBasedSlo '${props.sloName}' requires goodCountMetric or badCountMetric`,
      );
    }
    super(scope, id, props, {
      requestBasedSli: {
        requestBasedSliMetric: {
          totalRequestCountMetric: props.totalRequestCountMetric,
          monitoredRequestCountMetric: props.goodCountMetric
            ? { goodCountMetric: props.goodCountMetric }
            : { badCountMetric: props.badCountMetric },
        },
      },
    });
  }
}

// ─── Period-based SLO ───────────────────────────────────────────────────

export interface PeriodSloProps extends SloBaseProps {
  /** A single metric to compare against the threshold. For ratios, use RequestBasedSlo. */
  readonly metric: cloudwatch.Metric;

  /** Threshold value. */
  readonly threshold: number;

  /** @default 'LessThanOrEqualTo' */
  readonly comparisonOperator?: SloComparisonOperator;
}

/** Period-based SLO — single metric vs a threshold. */
export class PeriodSlo extends BaseSlo {
  constructor(scope: Construct, id: string, props: PeriodSloProps) {
    const metricConfig = props.metric.toMetricConfig();
    if (!metricConfig.metricStat) {
      throw new Error(
        `PeriodSlo '${props.sloName}' requires a metric with a metricStat`,
      );
    }
    const metricStat = metricConfig.metricStat;

    super(scope, id, props, {
      sli: {
        sliMetric: {
          metricDataQueries: [
            {
              id: 'metric',
              metricStat: {
                metric: {
                  namespace: metricStat.namespace,
                  metricName: metricStat.metricName,
                  ...(metricStat.dimensions &&
                    metricStat.dimensions.length > 0 && {
                      dimensions: metricStat.dimensions.map((d) => ({
                        name: d.name,
                        value: d.value,
                      })),
                    }),
                },
                period: metricStat.period?.toSeconds() ?? 300,
                stat: metricStat.statistic ?? 'Sum',
              },
              returnData: true,
            },
          ],
        },
        metricThreshold: props.threshold,
        comparisonOperator: props.comparisonOperator ?? 'LessThanOrEqualTo',
      },
    });
  }
}

// ─── Shared helpers ─────────────────────────────────────────────────────

function resolveGoal(props: SloBaseProps) {
  const windows = props.burnRateWindows ?? [Duration.hours(1), Duration.hours(6)];
  const rollingDays = (props.rollingInterval ?? Duration.days(1)).toDays();

  const goalConfig = {
    attainmentGoal: props.attainmentGoal,
    interval: { rollingInterval: { duration: rollingDays, durationUnit: 'DAY' } },
    ...(props.warningThreshold !== undefined && {
      warningThreshold: props.warningThreshold,
    }),
  };

  const burnRateConfigurations = windows.map((w) => ({
    lookBackWindowMinutes: w.toMinutes(),
  }));
  const firstWindowMinutes = String(windows[0].toMinutes());

  return { goalConfig, burnRateConfigurations, firstWindowMinutes };
}

function createBurnRateAlarm(
  scope: Construct,
  props: SloBaseProps,
  firstWindowMinutes: string,
): cloudwatch.Alarm | undefined {
  if (!props.alarmTopic) {
    return undefined;
  }

  const alarm = new cloudwatch.Alarm(scope, 'BurnRate', {
    alarmName: `${props.sloName}-BurnRate`,
    metric: new cloudwatch.Metric({
      namespace: 'AWS/ApplicationSignals',
      metricName: 'BurnRate',
      dimensionsMap: {
        SloName: props.sloName,
        BurnRateWindowMinutes: firstWindowMinutes,
      },
      statistic: 'Maximum',
      period: Duration.minutes(1),
    }),
    threshold: 1,
    comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
    evaluationPeriods: 1,
    treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
  });
  alarm.addAlarmAction(new cloudwatchActions.SnsAction(props.alarmTopic));
  return alarm;
}
