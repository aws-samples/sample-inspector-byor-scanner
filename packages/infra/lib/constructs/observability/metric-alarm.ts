import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cloudwatchActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as sns from 'aws-cdk-lib/aws-sns';
import { Construct } from 'constructs';

export interface MetricAlarmProps {
  /** Unique alarm name. */
  readonly alarmName: string;

  /** Human-readable description. @default - none */
  readonly alarmDescription?: string;

  /** The metric to alarm on. */
  readonly metric: cloudwatch.IMetric;

  /** Threshold value to breach. */
  readonly threshold: number;

  /** @default GREATER_THAN_THRESHOLD */
  readonly comparisonOperator?: cloudwatch.ComparisonOperator;

  /** Number of periods to evaluate. @default 1 */
  readonly evaluationPeriods?: number;

  /** Breaching datapoints required to alarm (M of N). @default - same as evaluationPeriods */
  readonly datapointsToAlarm?: number;

  /** Behaviour when data is missing. @default NOT_BREACHING */
  readonly treatMissingData?: cloudwatch.TreatMissingData;

  /** SNS topic to notify on alarm. @default - no notification */
  readonly alarmTopic?: sns.ITopic;
}

/**
 * Thin wrapper over {@link cloudwatch.Alarm} that applies the project's alarm
 * defaults (M-of-N evaluation, missing-data handling) and optionally wires an
 * SNS action. Accepts any `IMetric`, so callers use the idiomatic L2 metric
 * helpers or a plain `Metric`/`MathExpression`.
 */
export class MetricAlarm extends Construct {
  public readonly alarm: cloudwatch.Alarm;

  constructor(scope: Construct, id: string, props: MetricAlarmProps) {
    super(scope, id);

    this.alarm = new cloudwatch.Alarm(this, 'Resource', {
      alarmName: props.alarmName,
      alarmDescription: props.alarmDescription,
      metric: props.metric,
      threshold: props.threshold,
      comparisonOperator:
        props.comparisonOperator ??
        cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: props.evaluationPeriods ?? 1,
      datapointsToAlarm: props.datapointsToAlarm,
      treatMissingData:
        props.treatMissingData ?? cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    if (props.alarmTopic) {
      this.alarm.addAlarmAction(new cloudwatchActions.SnsAction(props.alarmTopic));
    }
  }
}
