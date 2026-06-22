import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import {
  InspectorScanner,
  S3ManifestDiscoveryProvider,
} from '@constructs/inspector-scanner';

/**
 * Assertions over the observability the InspectorScanner construct owns via
 * `scanner.observability` (the ScannerObservability facade): the scanner-core
 * SLOs, alarms, dashboard, Application Signals discovery, and per-provider
 * failure alarms.
 *
 * Docker-free: `aws:cdk:bundling-stacks: []` skips PythonFunction bundling.
 */
describe('ScannerObservability (scanner-core tier, via InspectorScanner)', () => {
  function build(): { stack: Stack; scanner: InspectorScanner } {
    const app = new App({ context: { 'aws:cdk:bundling-stacks': [] } });
    const stack = new Stack(app, 'TestStack', {
      env: { account: '111111111111', region: 'us-west-2' },
    });
    const vpc = new ec2.Vpc(stack, 'Vpc');
    const scanner = new InspectorScanner(stack, 'Scanner', { vpc });
    return { stack, scanner };
  }

  it('owns the dashboard and the three system SLOs', () => {
    const { stack, scanner } = build();
    expect(scanner.observability.dashboard).toBeDefined();

    const template = Template.fromStack(stack);
    template.resourceCountIs('AWS::CloudWatch::Dashboard', 1);
    template.resourceCountIs(
      'AWS::ApplicationSignals::ServiceLevelObjective',
      3,
    );
  });

  it('names the dashboard region-qualified (no cross-region collisions)', () => {
    const { stack } = build();
    Template.fromStack(stack).hasResourceProperties(
      'AWS::CloudWatch::Dashboard',
      { DashboardName: 'BYORScan-us-west-2' },
    );
  });

  it('enables Application Signals discovery via a StartDiscovery custom resource', () => {
    const { stack } = build();
    // The AwsCustomResource synthesizes as a Custom::AWS resource.
    Template.fromStack(stack).resourceCountIs('Custom::AWS', 1);
  });

  it('registers the fixed (provider-independent) alarms', () => {
    const { scanner } = build();
    // The provider-independent alarms, spelled out so adding/removing one is a
    // deliberate test change rather than a mystery off-by-one.
    const COARSE = 2; // DLQ-depth + queue-age
    const PER_STAGE = 5; // Inspect, Pull, SbomGen, ScanSbom, Delivery
    const SLO_BURN_RATE = 2; // new-image-coverage + image-compatibility
    expect(scanner.observability.createdAlarms).toHaveLength(
      COARSE + PER_STAGE + SLO_BURN_RATE,
    );
  });

  it('region-qualifies every alarm name', () => {
    const { stack, scanner } = build();
    scanner.addDiscoveryProvider(
      'manifest',
      new S3ManifestDiscoveryProvider(stack, 'Manifest'),
    );
    const template = Template.fromStack(stack);
    // Coarse, per-stage, burn-rate, and per-provider alarms all carry the region.
    for (const name of [
      'byor-scanner-dlq-depth-us-west-2',
      'byor-scanner-queue-age-us-west-2',
      'byor-scanner-Pull-us-west-2',
      'byor-new-image-coverage-BurnRate-us-west-2',
      'byor-discovery-manifest-failure-us-west-2',
    ]) {
      template.hasResourceProperties('AWS::CloudWatch::Alarm', {
        AlarmName: name,
      });
    }
  });

  it('metricScanFailures is scoped to the service dimension (reads a real series)', () => {
    const { scanner } = build();
    // Totals are {service}-dimensioned; the dimensionless metric has no data,
    // so this guards against it regressing to an empty stream.
    expect(scanner.metricScanFailures().dimensions).toEqual({
      service: 'byor-scanner',
    });
  });

  it('adds exactly one failure alarm per discovery provider (delta over baseline)', () => {
    const { stack, scanner } = build();
    const baseline = scanner.observability.createdAlarms.length;

    const a = scanner.addDiscoveryProvider(
      'manifesta',
      new S3ManifestDiscoveryProvider(stack, 'ManifestA'),
    );
    const b = scanner.addDiscoveryProvider(
      'manifestb',
      new S3ManifestDiscoveryProvider(stack, 'ManifestB'),
    );

    // N providers ⇒ baseline + N alarms — no absolute total hardcoded — and each
    // provider's alarm is registered, so addAlarmAction routes it.
    expect(scanner.observability.createdAlarms).toHaveLength(baseline + 2);
    expect(scanner.observability.createdAlarms).toEqual(
      expect.arrayContaining([a.failureAlarm, b.failureAlarm]),
    );
  });

  it('dashboard:false creates no Dashboard resource', () => {
    const app = new App({ context: { 'aws:cdk:bundling-stacks': [] } });
    const stack = new Stack(app, 'TestStack', {
      env: { account: '111111111111', region: 'us-west-2' },
    });
    const vpc = new ec2.Vpc(stack, 'Vpc');
    const scanner = new InspectorScanner(stack, 'Scanner', {
      vpc,
      observability: { dashboard: false },
    });

    expect(scanner.observability.dashboard).toBeUndefined();
    Template.fromStack(stack).resourceCountIs('AWS::CloudWatch::Dashboard', 0);
  });

  it('monitorCustom adds a widget to the dashboard', () => {
    const { stack, scanner } = build();
    scanner.observability.monitorCustom({
      metricGroups: [
        { title: 'Registry Mirror Lag', left: [scanner.metricScanFailures()] },
      ],
    });
    // DashboardBody is an Fn::Join of literals + tokens; the widget title is a
    // literal, so it shows up in the stringified body.
    const dashboards = Template.fromStack(stack).findResources(
      'AWS::CloudWatch::Dashboard',
    );
    const body = JSON.stringify(
      Object.values(dashboards)[0].Properties.DashboardBody,
    );
    expect(body).toContain('Registry Mirror Lag');
  });

  it('flushes every segment at synth in registration order (core → provider → custom)', () => {
    const { stack, scanner } = build();

    // Register a provider, then a custom segment AFTER it. Under the lazy
    // flush, both must still land on the dashboard, in order — this guards
    // against an entry point that forgets to collect into segments[].
    scanner.addDiscoveryProvider(
      'manifest',
      new S3ManifestDiscoveryProvider(stack, 'Manifest'),
    );
    scanner.observability.monitorCustom({
      metricGroups: [
        { title: 'Custom Team Widget', left: [scanner.metricScanFailures()] },
      ],
    });

    // Template.fromStack triggers Aspect invocation, which flushes the segments.
    const dashboards = Template.fromStack(stack).findResources(
      'AWS::CloudWatch::Dashboard',
    );
    const body = JSON.stringify(
      Object.values(dashboards)[0].Properties.DashboardBody,
    );

    const core = body.indexOf('Top 10 Images by Critical Findings'); // core segment
    const provider = body.indexOf('Discovery Volume — manifest'); // provider segment
    const custom = body.indexOf('Custom Team Widget'); // custom segment

    // All segments rendered — none dropped by the conversion.
    expect(core).toBeGreaterThanOrEqual(0);
    expect(provider).toBeGreaterThanOrEqual(0);
    expect(custom).toBeGreaterThanOrEqual(0);
    // Registration order preserved: core (constructor) → provider → custom.
    expect(core).toBeLessThan(provider);
    expect(provider).toBeLessThan(custom);
  });

  it('throws for a region with no ADOT layer ARN', () => {
    const app = new App({ context: { 'aws:cdk:bundling-stacks': [] } });
    const stack = new Stack(app, 'TestStack', {
      env: { account: '111111111111', region: 'eu-west-1' },
    });
    const vpc = new ec2.Vpc(stack, 'Vpc');
    expect(() => new InspectorScanner(stack, 'Scanner', { vpc })).toThrow(
      /No ADOT Python layer ARN configured for region 'eu-west-1'/,
    );
  });
});
