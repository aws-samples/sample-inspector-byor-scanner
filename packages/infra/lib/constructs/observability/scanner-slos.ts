import { Duration } from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';
import {
  DISCOVERY_SERVICE,
  METRIC_NAMESPACE,
  SCANNER_SERVICE,
} from './constants';
import { ScannerAlarms } from './scanner-alarms';
import { PeriodSlo, RequestBasedSlo, ServiceSlo } from './slo';

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

  /** Scanner Lambda timeout — the latency SLO targets 80% of it. */
  readonly scannerTimeout: Duration;

  /** Discovery Lambda timeout — the latency SLO targets 80% of it. */
  readonly discoveryTimeout: Duration;

  /**
   * SNS topic for burn-rate and per-operation alarms.
   * @default - a new `byor-scanner-slo-alarms` topic is created
   */
  readonly alarmTopic?: sns.ITopic;
}

/**
 * The scanner's Application Signals SLOs plus the per-operation alarms.
 *
 * SLOs that overlap the stack's existing coarse alarms are created as
 * attainment objectives **without** a burn-rate alarm, to avoid duplicate
 * paging:
 *   - scan-freshness        ↔ existing QueueAgeAlarm
 *   - discovery-availability ↔ existing DiscoveryFailureAlarm
 */
export class ScannerSlos extends Construct {
  public readonly alarmTopic: sns.ITopic;

  constructor(scope: Construct, id: string, props: ScannerSlosProps) {
    super(scope, id);

    this.alarmTopic =
      props.alarmTopic ??
      new sns.Topic(this, 'AlarmTopic', { topicName: 'byor-scanner-slo-alarms' });

    new ScannerAlarms(this, 'PerOperationAlarms', { alarmTopic: this.alarmTopic });

    // ─── Service-bound SLOs (trace-correlated via Application Signals) ──
    new ServiceSlo(this, 'DiscoveryAvailability', {
      sloName: 'byor-discovery-availability',
      description: 'Discovery Lambda availability',
      serviceName: DISCOVERY_SERVICE,
      metricType: 'AVAILABILITY',
      threshold: 99,
      attainmentGoal: 99.9,
      // Attainment-only: a burn-rate alarm would duplicate DiscoveryFailureAlarm.
    });

    new ServiceSlo(this, 'DiscoveryLatency', {
      sloName: 'byor-discovery-latency',
      description: 'Discovery p99 latency under 80% of its timeout',
      serviceName: DISCOVERY_SERVICE,
      metricType: 'LATENCY',
      statistic: 'p99',
      threshold: props.discoveryTimeout.toMilliseconds() * 0.8,
      attainmentGoal: 99.9,
      alarmTopic: this.alarmTopic,
    });

    new ServiceSlo(this, 'ScannerAvailability', {
      sloName: 'byor-scanner-availability',
      description: 'Scanner Lambda availability',
      serviceName: SCANNER_SERVICE,
      metricType: 'AVAILABILITY',
      threshold: 99,
      attainmentGoal: 99.9,
      alarmTopic: this.alarmTopic,
    });

    new ServiceSlo(this, 'ScannerLatency', {
      sloName: 'byor-scanner-latency',
      description: 'Scanner p99 latency under 80% of its timeout',
      serviceName: SCANNER_SERVICE,
      metricType: 'LATENCY',
      statistic: 'p99',
      threshold: props.scannerTimeout.toMilliseconds() * 0.8,
      attainmentGoal: 99.9,
      alarmTopic: this.alarmTopic,
    });

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

    new PeriodSlo(this, 'NewImageCoverage', {
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
      alarmTopic: this.alarmTopic,
    });

    new RequestBasedSlo(this, 'ImageCompatibility', {
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
      alarmTopic: this.alarmTopic,
    });
  }
}
