import { Duration, Stack } from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
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

/**
 * Per-operation scanner alarms — one per pipeline stage. Each fires when
 * `ImagesFailed` with that stage dimension appears at least twice in 3 of
 * 5 five-minute periods, suppressing single-image flakiness while catching
 * sustained failure modes.
 *
 * The alarms carry no action; they are exposed via {@link alarms} so the
 * observability facade registers them and routes actions through
 * `addAlarmAction` (no SNS topic is created here).
 */
export class ScannerAlarms extends Construct {
  /** The per-stage alarms, for the facade to register and route. */
  public readonly alarms: cloudwatch.Alarm[] = [];

  constructor(scope: Construct, id: string) {
    super(scope, id);

    const region = Stack.of(this).region;
    for (const [name, stage] of STAGE_ALARMS) {
      this.alarms.push(
        new MetricAlarm(this, name, {
          alarmName: `byor-scanner-${stage}-${region}`,
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
        }).alarm,
      );
    }
  }
}
