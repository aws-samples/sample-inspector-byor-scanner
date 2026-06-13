import { Duration } from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';
import {
  APPSIGNALS_ENV,
  APPSIGNALS_NS,
  DISCOVERY_SERVICE,
  METRIC_NAMESPACE,
  SCANNER_SERVICE,
} from './constants';
import { ScannerAlarms } from './scanner-alarms';
import { PeriodSlo, RequestBasedSlo } from './slo';

// Powertools emits the custom scanner metrics with a `service` default
// dimension, so SLO queries must scope to it to match the data.
const SCANNER_DIMENSIONS = [{ name: 'service', value: SCANNER_SERVICE }];

/** Application Signals metric dimensions for a Lambda service's own operation. */
function appSignalsDims(service: string, functionName: string) {
  return [
    { name: 'Service', value: service },
    { name: 'Operation', value: `${functionName}/FunctionHandler` },
    { name: 'Environment', value: APPSIGNALS_ENV },
  ];
}

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

  /** Scanner Lambda function name — used for the Application Signals Operation dimension. */
  readonly scannerFunctionName: string;

  /** Discovery Lambda function name — used for the Application Signals Operation dimension. */
  readonly discoveryFunctionName: string;
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

    new RequestBasedSlo(this, 'ScannerAvailability', {
      sloName: 'byor-scanner-availability',
      description: 'Scanner availability — fraction of non-fault requests',
      totalRequestCountMetric: [
        {
          id: 'total',
          metricStat: {
            metric: {
              namespace: APPSIGNALS_NS,
              metricName: 'Latency',
              dimensions: appSignalsDims(SCANNER_SERVICE, props.scannerFunctionName),
            },
            period: 60,
            stat: 'SampleCount',
          },
          returnData: true,
        },
      ],
      badCountMetric: [
        {
          id: 'faults',
          metricStat: {
            metric: {
              namespace: APPSIGNALS_NS,
              metricName: 'Fault',
              dimensions: appSignalsDims(SCANNER_SERVICE, props.scannerFunctionName),
            },
            period: 60,
            stat: 'Sum',
          },
          returnData: true,
        },
      ],
      attainmentGoal: 99.9,
      alarmTopic: this.alarmTopic,
    });

    new PeriodSlo(this, 'ScannerLatency', {
      sloName: 'byor-scanner-latency',
      description: 'Scanner p99 latency under 80% of its timeout',
      metric: new cloudwatch.Metric({
        namespace: APPSIGNALS_NS,
        metricName: 'Latency',
        dimensionsMap: {
          Service: SCANNER_SERVICE,
          Operation: `${props.scannerFunctionName}/FunctionHandler`,
          Environment: APPSIGNALS_ENV,
        },
        statistic: 'p99',
        period: Duration.minutes(1),
      }),
      threshold: props.scannerTimeout.toMilliseconds() * 0.8,
      comparisonOperator: 'LessThanOrEqualTo',
      attainmentGoal: 99.9,
      alarmTopic: this.alarmTopic,
    });

    new RequestBasedSlo(this, 'DiscoveryAvailability', {
      sloName: 'byor-discovery-availability',
      description: 'Discovery availability — fraction of non-fault requests',
      totalRequestCountMetric: [
        {
          id: 'total',
          metricStat: {
            metric: {
              namespace: APPSIGNALS_NS,
              metricName: 'Latency',
              dimensions: appSignalsDims(DISCOVERY_SERVICE, props.discoveryFunctionName),
            },
            period: 60,
            stat: 'SampleCount',
          },
          returnData: true,
        },
      ],
      badCountMetric: [
        {
          id: 'faults',
          metricStat: {
            metric: {
              namespace: APPSIGNALS_NS,
              metricName: 'Fault',
              dimensions: appSignalsDims(DISCOVERY_SERVICE, props.discoveryFunctionName),
            },
            period: 60,
            stat: 'Sum',
          },
          returnData: true,
        },
      ],
      attainmentGoal: 99.9,
      // Attainment-only: a burn-rate alarm would duplicate DiscoveryFailureAlarm.
    });

    new PeriodSlo(this, 'DiscoveryLatency', {
      sloName: 'byor-discovery-latency',
      description: 'Discovery p99 latency under 80% of its timeout',
      metric: new cloudwatch.Metric({
        namespace: APPSIGNALS_NS,
        metricName: 'Latency',
        dimensionsMap: {
          Service: DISCOVERY_SERVICE,
          Operation: `${props.discoveryFunctionName}/FunctionHandler`,
          Environment: APPSIGNALS_ENV,
        },
        statistic: 'p99',
        period: Duration.minutes(1),
      }),
      threshold: props.discoveryTimeout.toMilliseconds() * 0.8,
      comparisonOperator: 'LessThanOrEqualTo',
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
