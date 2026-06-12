import { Duration } from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as sns from 'aws-cdk-lib/aws-sns';
import { Construct } from 'constructs';
import { METRIC_NAMESPACE } from './constants';
import { MetricAlarm } from './metric-alarm';

/**
 * Scanner error codes that warrant a dedicated per-operation alarm. These
 * are the operational failures (registry/network/Inspector/delivery) where a
 * sustained rate signals something is wrong with the pipeline rather than a
 * single bad image. Codes raised on the `ImagesFailed` metric's `errorCode`
 * dimension by the scanner Lambda (see byor_scanner/scanner.py + errors.py).
 */
const SCANNER_ALARM_CODES: ReadonlyArray<readonly [string, string]> = [
  ['AuthFailures', 'AUTH_FAILED'],
  ['ScanSbomValidation', 'SCANSBOM_VALIDATION'],
  ['S3WriteFailures', 'S3_WRITE_FAILED'],
  ['InspectFailures', 'INSPECT_FAILED'],
  ['PullFailures', 'PULL_FAILED'],
  ['PullTimeouts', 'PULL_TIMEOUT'],
  ['SbomgenFailures', 'SBOMGEN_FAILED'],
  ['ScanSbomFailures', 'SCANSBOM_FAILED'],
  ['ScanSbomThrottled', 'SCANSBOM_THROTTLED'],
];

export interface ScannerAlarmsProps {
  /** SNS topic that every per-operation alarm notifies. */
  readonly alarmTopic: sns.ITopic;
}

/**
 * Per-operation scanner alarms. Each fires when its `errorCode` appears on
 * `ImagesFailed` at least twice in 3 of 5 five-minute periods — enough to
 * suppress single-image flakiness while catching a sustained failure mode.
 *
 * These complement the stack's three coarse operational alarms (DLQ depth,
 * queue age, discovery failures); they do not duplicate them.
 */
export class ScannerAlarms extends Construct {
  constructor(scope: Construct, id: string, props: ScannerAlarmsProps) {
    super(scope, id);

    for (const [name, code] of SCANNER_ALARM_CODES) {
      new MetricAlarm(this, name, {
        alarmName: `byor-scanner-${code}`,
        alarmDescription: `${code} errors detected on the scanner`,
        metric: new cloudwatch.Metric({
          namespace: METRIC_NAMESPACE,
          metricName: 'ImagesFailed',
          dimensionsMap: { errorCode: code },
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
