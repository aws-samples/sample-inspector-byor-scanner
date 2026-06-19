import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { InspectorScanner } from '@constructs/inspector-scanner';

/**
 * Assertions over the observability the InspectorScanner construct now owns via
 * `scanner.observability` (the ScannerObservability facade). Per-provider SLOs
 * and the segment-based dashboard land in the follow-up PR; this covers the
 * scanner-core tier wired in PR A.
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
});
