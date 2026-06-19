import { Duration } from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';
import {
  METRIC_NAMESPACE,
  SCANNER_SERVICE,
} from './constants';
import { ScannerAlarms } from './scanner-alarms';
import { PeriodSlo, RequestBasedSlo } from './slo';

// Powertools emits the custom scanner metrics with a `service` default
// dimension, so SLO queries must scope to it to match the data.
const SCANNER_DIMENSIONS = [{ name: 'service', value: SCANNER_SERVICE }];

const SYSTEM_BURN_RATE_WINDOWS = [
  Duration.hours(1),
  Duration.hours(6),
  Duration.hours(24),
];

const FOURTEEN_HOURS_SECONDS = 14 * 60 * 60;
const SIXTY_MINUTES_MS = 60 * 60 * 1000;

export interface ScannerSlosProps {
  /** Scan queue — drives the scan-freshness SLO. */
  readonly queue: sqs.IQueue;

  /** Scanner Lambda timeout — used for system SLOs. */
  readonly scannerTimeout: Duration;

  /** Discovery Lambda timeout. */
  readonly discoveryTimeout: Duration;
}

/**
 * The scanner's per-operation alarms and system-level SLOs.
 *
 * System SLOs cover scan freshness, new-image coverage, and image
 * compatibility. Service-level availability and latency SLOs are managed
 * directly by Application Signals (SLO-by-service) and do not need
 * explicit CDK definitions.
 *
 * No SNS topic is created here. Every alarm this construct owns (per-stage +
 * SLO burn-rate) is exposed via {@link alarms} so the observability facade
 * registers them and routes actions through `addAlarmAction`.
 */
export class ScannerSlos extends Construct {
  /** Every alarm this construct owns, for the facade to register and route. */
  public readonly alarms: cloudwatch.Alarm[];

  constructor(scope: Construct, id: string, props: ScannerSlosProps) {
    super(scope, id);

    const perOperation = new ScannerAlarms(this, 'PerOperationAlarms');

    // ─── System SLOs ───────────────────────────────────────────────────
    new PeriodSlo(this, 'ScanFreshness', {
      sloName: 'byor-scan-freshness',
      description: 'Scan queue drains within 14 hours',
      metric: new cloudwatch.Metric({
        namespace: 'AWS/SQS',
        metricName: 'ApproximateAgeOfOldestMessage',
        dimensionsMap: { QueueName: props.queue.queueName },
        statistic: cloudwatch.Stats.MAXIMUM,
        period: Duration.minutes(5),
      }),
      threshold: FOURTEEN_HOURS_SECONDS,
      attainmentGoal: 99,
      burnRateWindows: SYSTEM_BURN_RATE_WINDOWS,
      // Attainment-only: a burn-rate alarm would duplicate QueueAgeAlarm.
    });

    const coverage = new PeriodSlo(this, 'NewImageCoverage', {
      sloName: 'byor-new-image-coverage',
      description: 'p99 scan duration under 60 minutes',
      metric: new cloudwatch.Metric({
        namespace: METRIC_NAMESPACE,
        metricName: 'ScanDuration',
        dimensionsMap: { service: SCANNER_SERVICE },
        statistic: 'p99',
        period: Duration.minutes(5),
      }),
      threshold: SIXTY_MINUTES_MS,
      attainmentGoal: 99,
      burnRateWindows: SYSTEM_BURN_RATE_WINDOWS,
      burnRateAlarm: true,
    });

    const compatibility = new RequestBasedSlo(this, 'ImageCompatibility', {
      sloName: 'byor-image-compatibility',
      description: '>=95% of images are scannable (not skipped)',
      totalRequestCountMetric: [
        {
          id: 'scanned',
          metricStat: {
            metric: {
              namespace: METRIC_NAMESPACE,
              metricName: 'ImagesScanned',
              dimensions: SCANNER_DIMENSIONS,
            },
            period: 300,
            stat: 'Sum',
          },
          returnData: false,
        },
        {
          id: 'skipped',
          metricStat: {
            metric: {
              namespace: METRIC_NAMESPACE,
              metricName: 'ImagesSkipped',
              dimensions: SCANNER_DIMENSIONS,
            },
            period: 300,
            stat: 'Sum',
          },
          returnData: false,
        },
        { id: 'total', expression: 'scanned + skipped', returnData: true },
      ],
      goodCountMetric: [
        {
          id: 'good',
          metricStat: {
            metric: {
              namespace: METRIC_NAMESPACE,
              metricName: 'ImagesScanned',
              dimensions: SCANNER_DIMENSIONS,
            },
            period: 300,
            stat: 'Sum',
          },
          returnData: true,
        },
      ],
      attainmentGoal: 95,
      warningThreshold: 90,
      burnRateWindows: SYSTEM_BURN_RATE_WINDOWS,
      burnRateAlarm: true,
    });

    this.alarms = [
      ...perOperation.alarms,
      ...[coverage.alarm, compatibility.alarm].filter(
        (a): a is cloudwatch.Alarm => a !== undefined,
      ),
    ];
  }
}
