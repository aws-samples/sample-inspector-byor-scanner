import { Duration } from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { DISCOVERY_SERVICE, METRIC_NAMESPACE, SCANNER_SERVICE } from './constants';

const PERIOD = Duration.minutes(5);

/**
 * A dashboard segment: a unit that contributes widgets to the BYORScan
 * dashboard. The facade renders every segment's widgets (borrowed from
 * cdk-monitoring-constructs' `IDashboardSegment`).
 *
 * Each element of {@link widgets} becomes one dashboard row (a full-width
 * widget on its own, or a {@link cloudwatch.Row} of side-by-side widgets), so
 * the facade can render a segment by adding its widgets one row at a time.
 *
 * Segments are pure view objects — they mint no resources. The scanner-core
 * SLOs/alarms and the per-provider failure alarm are created by the facade's
 * `monitorScannerCore` / `monitorProvider`; segments only render.
 */
export interface IDashboardSegment {
  /** Dashboard rows this segment contributes, top-to-bottom. */
  widgets(): cloudwatch.IWidget[];
}

/**
 * Scanner-wide dashboard widgets: Logs Insights findings tables plus the scan
 * volume / success-rate / discovery-volume / duration graphs. One per scanner.
 */
export class ScannerCoreSegment implements IDashboardSegment {
  private readonly logGroup: string;

  constructor(scannerFunction: lambda.IFunction) {
    this.logGroup = `/aws/lambda/${scannerFunction.functionName}`;
  }

  public widgets(): cloudwatch.IWidget[] {
    const scannerDimensions = { service: SCANNER_SERVICE };
    return [
      new cloudwatch.LogQueryWidget({
        title: 'Top 10 Images by Critical Findings',
        logGroupNames: [this.logGroup],
        queryLines: [
          'filter outcome = "success"',
          'stats latest(ref) as Ref, latest(findingsCritical) as Critical, latest(findingsHigh) as High, latest(findingsMedium) as Medium, latest(findingsLow) as Low, latest(findingsTotal) as Total, latest(digest) as Digest, latest(findingsKey) as FindingsURL by image',
          'sort Critical desc',
          'limit 10',
        ],
        width: 24,
        height: 8,
      }),
      new cloudwatch.LogQueryWidget({
        title: 'All Images — Latest Findings',
        logGroupNames: [this.logGroup],
        queryLines: [
          'filter outcome = "success"',
          'stats latest(ref) as Ref, latest(findingsCritical) as Critical, latest(findingsHigh) as High, latest(findingsMedium) as Medium, latest(findingsLow) as Low, latest(findingsTotal) as Total, latest(digest) as Digest, latest(findingsKey) as FindingsURL by image',
          'sort Critical desc',
          'limit 1000',
        ],
        width: 24,
        height: 8,
      }),
      new cloudwatch.LogQueryWidget({
        title: 'Recent Failed Images',
        logGroupNames: [this.logGroup],
        // Failures log "Scan failed" with an errorCode (no outcome field).
        queryLines: [
          'filter message = "Scan failed"',
          'stats count(*) as failCount, latest(errorCode) as lastError, latest(traceUrl) as Trace, max(@timestamp) as lastFailed by image, ref',
          'sort lastFailed desc',
          'limit 50',
        ],
        width: 24,
        height: 6,
      }),
      new cloudwatch.Row(
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
      ),
      new cloudwatch.Row(
        new cloudwatch.GraphWidget({
          title: 'Discovery Volume',
          left: [
            new cloudwatch.MathExpression({
              expression:
                'SUM(SEARCH(\'{BYORScan,source,service} MetricName="ImagesEnqueued"\', \'Sum\', 300))',
              usingMetrics: {},
              label: 'Enqueued (all sources)',
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
      ),
    ];
  }
}

/**
 * Per-provider dashboard widget, keyed by `source`: that provider's enqueue
 * volume. One per discovery provider.
 *
 * No SLOs: scanner/discovery availability and latency are managed by
 * Application Signals SLO-by-service rather than defined in CDK, so this
 * segment is purely a dashboard breakdown. The provider's failure alarm still
 * exists (created by the facade) and is routed via addAlarmAction.
 */
export class DiscoverySegment implements IDashboardSegment {
  constructor(
    /** The provider's `source` dimension value. */
    public readonly source: string,
  ) {}

  public widgets(): cloudwatch.IWidget[] {
    return [
      new cloudwatch.GraphWidget({
        title: `Discovery Volume — ${this.source}`,
        left: [
          new cloudwatch.Metric({
            namespace: METRIC_NAMESPACE,
            metricName: 'ImagesEnqueued',
            dimensionsMap: { service: DISCOVERY_SERVICE, source: this.source },
            statistic: cloudwatch.Stats.SUM,
            period: PERIOD,
            label: 'Enqueued',
          }),
        ],
        width: 12,
        height: 6,
      }),
    ];
  }
}
