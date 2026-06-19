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

  it('registers the coarse + system alarms before any provider is added', () => {
    const { scanner } = build();
    // 2 coarse (DLQ-depth + queue-age) + 5 per-stage + 2 SLO burn-rate.
    expect(scanner.observability.createdAlarms.length).toBe(9);
  });

  it('metricScanFailures is scoped to the service dimension (reads a real series)', () => {
    const { scanner } = build();
    // Totals are {service}-dimensioned; the dimensionless metric has no data,
    // so this guards against it regressing to an empty stream.
    expect(scanner.metricScanFailures().dimensions).toEqual({
      service: 'byor-scanner',
    });
  });

  it('mints + registers a failure alarm per discovery provider', () => {
    const { stack, scanner } = build();
    const provider = scanner.addDiscoveryProvider(
      'manifest',
      new S3ManifestDiscoveryProvider(stack, 'Manifest'),
    );
    expect(provider.failureAlarm).toBeDefined();
    // The per-provider alarm is in the facade's registry (so addAlarmAction routes it).
    expect(scanner.observability.createdAlarms).toContain(provider.failureAlarm);
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
