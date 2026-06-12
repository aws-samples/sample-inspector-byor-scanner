import { Duration } from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';
import { METRIC_NAMESPACE, SCANNER_SERVICE } from './constants';
import { ScannerSlos } from './scanner-slos';

const PERIOD = Duration.minutes(5);

export interface ObservabilityProps {
  /** Scanner Lambda — its log group backs the Logs Insights widgets. */
  readonly scannerFunction: lambda.IFunction;

  /** Scan queue — passed through to the scan-freshness SLO. */
  readonly queue: sqs.IQueue;

  /** Scanner Lambda timeout (for the latency SLO). */
  readonly scannerTimeout: Duration;

  /** Discovery Lambda timeout (for the latency SLO). */
  readonly discoveryTimeout: Duration;

  /**
   * SNS topic for SLO / per-operation alarms.
   * @default - a new topic is created by ScannerSlos
   */
  readonly alarmTopic?: sns.ITopic;
}

/**
 * The scanner's observability layer: Application Signals SLOs (+ per-operation
 * alarms) and a CloudWatch dashboard. The dashboard's Logs Insights widgets
 * read the scanner Lambda's structured logs; the graph widgets read the
 * `BYORScan` custom metrics (scoped to the `service` dimension Powertools adds).
 */
export class Observability extends Construct {
  public readonly slos: ScannerSlos;

  constructor(scope: Construct, id: string, props: ObservabilityProps) {
    super(scope, id);

    this.slos = new ScannerSlos(this, 'Slos', {
      queue: props.queue,
      scannerTimeout: props.scannerTimeout,
      discoveryTimeout: props.discoveryTimeout,
      alarmTopic: props.alarmTopic,
    });

    const logGroup = `/aws/lambda/${props.scannerFunction.functionName}`;
    const dashboard = new cloudwatch.Dashboard(this, 'Dashboard', {
      dashboardName: 'BYORScan',
    });

    // ─── Logs Insights widgets ─────────────────────────────────────────
    dashboard.addWidgets(
      new cloudwatch.LogQueryWidget({
        title: 'Top 10 Images by Critical Findings',
        logGroupNames: [logGroup],
        queryLines: [
          'filter outcome = "success"',
          'stats latest(findingsCritical) as Critical, latest(findingsHigh) as High, latest(findingsMedium) as Medium, latest(findingsLow) as Low, latest(findingsTotal) as Total, latest(ref) as Ref, latest(digest) as Digest, latest(findingsKey) as FindingsURL by image',
          'sort Critical desc',
          'limit 10',
        ],
        width: 24,
        height: 8,
      }),
    );

    dashboard.addWidgets(
      new cloudwatch.LogQueryWidget({
        title: 'All Images — Latest Findings',
        logGroupNames: [logGroup],
        queryLines: [
          'filter outcome = "success"',
          'stats latest(findingsCritical) as Critical, latest(findingsHigh) as High, latest(findingsMedium) as Medium, latest(findingsLow) as Low, latest(findingsTotal) as Total, latest(ref) as Ref, latest(digest) as Digest, latest(findingsKey) as FindingsURL by image',
          'sort Critical desc',
          'limit 50',
        ],
        width: 24,
        height: 8,
      }),
    );

    dashboard.addWidgets(
      new cloudwatch.LogQueryWidget({
        title: 'Repeatedly Failed Images',
        logGroupNames: [logGroup],
        // Failures log "Scan failed" with an errorCode (no outcome field).
        queryLines: [
          'filter message = "Scan failed"',
          'stats count(*) as failCount, latest(errorCode) as lastError, max(@timestamp) as lastFailed by image, ref',
          'sort failCount desc',
          'limit 25',
        ],
        width: 24,
        height: 6,
      }),
    );

    dashboard.addWidgets(
      new cloudwatch.LogQueryWidget({
        title: 'Failures by Error Code',
        logGroupNames: [logGroup],
        queryLines: [
          'filter message = "Scan failed"',
          'stats count(*) as failures by errorCode',
          'sort failures desc',
        ],
        width: 24,
        height: 6,
      }),
    );

    // ─── Metric graph widgets ──────────────────────────────────────────
    const scannerDimensions = { service: SCANNER_SERVICE };

    dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'Scan Volume',
        left: [
          new cloudwatch.Metric({
            namespace: METRIC_NAMESPACE,
            metricName: 'ImagesScanned',
            dimensionsMap: scannerDimensions,
            statistic: cloudwatch.Stats.SUM,
            period: PERIOD,
            label: 'Scanned',
          }),
        ],
        right: [
          new cloudwatch.Metric({
            namespace: METRIC_NAMESPACE,
            metricName: 'ImagesFailed',
            dimensionsMap: scannerDimensions,
            statistic: cloudwatch.Stats.SUM,
            period: PERIOD,
            label: 'Failed',
          }),
        ],
        width: 12,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'Scan Success Rate (%)',
        left: [
          new cloudwatch.MathExpression({
            expression: 'IF(scanned + failed > 0, 100 * scanned / (scanned + failed), 100)',
            usingMetrics: {
              scanned: new cloudwatch.Metric({
                namespace: METRIC_NAMESPACE,
                metricName: 'ImagesScanned',
                dimensionsMap: scannerDimensions,
                statistic: cloudwatch.Stats.SUM,
                period: PERIOD,
              }),
              failed: new cloudwatch.Metric({
                namespace: METRIC_NAMESPACE,
                metricName: 'ImagesFailed',
                dimensionsMap: scannerDimensions,
                statistic: cloudwatch.Stats.SUM,
                period: PERIOD,
              }),
            },
            label: 'Success %',
            period: PERIOD,
          }),
        ],
        leftYAxis: { min: 0, max: 100 },
        width: 12,
        height: 6,
      }),
    );

    dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'Discovery Volume',
        // ImagesEnqueued carries both `service` and `mode` dimensions, so sum
        // every matching series to get total enqueued across modes.
        left: [
          new cloudwatch.MathExpression({
            expression:
              'SUM(SEARCH(\'{BYORScan,mode,service} MetricName="ImagesEnqueued"\', \'Sum\', 300))',
            usingMetrics: {},
            label: 'Enqueued (all modes)',
            period: PERIOD,
          }),
        ],
        width: 12,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'Scan Duration',
        left: [
          new cloudwatch.Metric({
            namespace: METRIC_NAMESPACE,
            metricName: 'ScanDuration',
            dimensionsMap: scannerDimensions,
            statistic: 'p50',
            period: PERIOD,
            label: 'p50',
          }),
          new cloudwatch.Metric({
            namespace: METRIC_NAMESPACE,
            metricName: 'ScanDuration',
            dimensionsMap: scannerDimensions,
            statistic: 'p99',
            period: PERIOD,
            label: 'p99',
          }),
        ],
        leftYAxis: { label: 'ms', min: 0 },
        width: 12,
        height: 6,
      }),
    );
  }
}
