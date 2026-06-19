import { Duration } from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as sns from 'aws-cdk-lib/aws-sns';
import { Construct } from 'constructs';
import { METRIC_NAMESPACE } from './constants';
import { MetricAlarm } from './metric-alarm';

/**
 * Pipeline stages that get a dedicated alarm. Each maps to one or more
 * error codes emitted by the scanner Lambda on the `stage` dimension.
 */
const STAGE_ALARMS: ReadonlyArray<readonly [string, string]> = [
  ['Inspect', 'Inspect'],
  ['Pull', 'Pull'],
  ['SbomGen', 'SbomGen'],
  ['ScanSbom', 'ScanSbom'],
  ['Delivery', 'Delivery'],
];

export interface ScannerAlarmsProps {
  /** SNS topic that every per-operation alarm notifies. */
  readonly alarmTopic: sns.ITopic;
}

/**
 * Per-operation scanner alarms — one per pipeline stage. Each fires when
 * `ImagesFailed` with that stage dimension appears at least twice in 3 of
 * 5 five-minute periods, suppressing single-image flakiness while catching
 * sustained failure modes.
 */
export class ScannerAlarms extends Construct {
  constructor(scope: Construct, id: string, props: ScannerAlarmsProps) {
    super(scope, id);

    for (const [name, stage] of STAGE_ALARMS) {
      new MetricAlarm(this, name, {
        alarmName: `byor-scanner-${stage}`,
        alarmDescription: `${stage} stage failures detected on the scanner`,
        metric: new cloudwatch.Metric({
          namespace: METRIC_NAMESPACE,
          metricName: 'ImagesFailed',
          dimensionsMap: { stage },
          statistic: cloudwatch.Stats.SUM,
          period: Duration.minutes(5),
        }),
        threshold: 2,
        evaluationPeriods: 5,
        datapointsToAlarm: 3,
        alarmTopic: props.alarmTopic,
      });
    }
  }
}
