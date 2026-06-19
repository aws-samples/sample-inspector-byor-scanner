import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import {
  InspectorScanner,
  MtlsRepositoryAuth,
  S3ManifestDiscoveryProvider,
  S3ManifestTrigger,
} from '@constructs/inspector-scanner';

/** Minimal alarm action that records the ARN it would notify. */
class FakeAlarmAction implements cloudwatch.IAlarmAction {
  public bind(): cloudwatch.AlarmActionConfig {
    return { alarmActionArn: 'arn:aws:sns:us-west-2:111111111111:ops' };
  }
}

/**
 * End-to-end assertions over the methodful `add*()` surface, wired the way the
 * sample stack does: addRegistry → addDiscoveryProvider → addTrigger.
 *
 * Docker-free: `aws:cdk:bundling-stacks: []` skips PythonFunction asset
 * bundling, and the tests never read `binaryLayer.layer` (which would trigger
 * the synth-time skopeo Docker build via the lazy-attach Aspect).
 */
describe('InspectorScanner methodful surface (end-to-end)', () => {
  function freshStack(): Stack {
    const app = new App({ context: { 'aws:cdk:bundling-stacks': [] } });
    return new Stack(app, 'TestStack', {
      env: { account: '111111111111', region: 'us-west-2' },
    });
  }

  function newScanner(stack: Stack): InspectorScanner {
    const vpc = new ec2.Vpc(stack, 'Vpc');
    return new InspectorScanner(stack, 'Scanner', { vpc });
  }

  it('requires only a vpc — foundational resources exist with no registries', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);

    expect(scanner.findingsBucket).toBeDefined();
    expect(scanner.scanQueue).toBeDefined();
    expect(scanner.scanDeadLetterQueue).toBeDefined();
    expect(scanner.scannerFunction).toBeDefined();
    // No discovery provider attached yet → no discovery Lambdas.
    expect(scanner.discoveryProviders.size).toBe(0);
    expect(scanner.registries.size).toBe(0);
  });

  it('wires the full sample chain: registry → provider → trigger', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);
    const secret = secretsmanager.Secret.fromSecretNameV2(
      stack,
      'Secret',
      'scanner/test-certs',
    );

    const registry = scanner.addRegistry('default', {
      url: 'registry.example.com',
      auth: new MtlsRepositoryAuth(stack, 'Auth', { secret }),
    });
    const manifest = new S3ManifestDiscoveryProvider(stack, 'Manifest');
    const provider = scanner.addDiscoveryProvider('manifest', manifest);
    const s3Trigger = new S3ManifestTrigger(stack, 'Trigger', {
      discovery: provider,
      bucket: manifest.bucket,
    });
    const trigger = scanner.addTrigger('manifest', s3Trigger);

    expect(registry.id).toBe('default');
    expect(scanner.registries.get('default')).toBe(registry);
    expect(scanner.discoveryProviders.get('manifest')).toBe(provider);
    expect(trigger.discovery).toBe(provider);
    // The provider reads, and the trigger fires on, the SAME bucket — the
    // core invariant of the provider-owns-bucket design (they can't diverge).
    expect(s3Trigger.bucket).toBe(manifest.bucket);
  });

  it('serializes attached registries into the BYOR_REGISTRIES env token', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);
    const secret = secretsmanager.Secret.fromSecretNameV2(
      stack,
      'Secret',
      'scanner/test-certs',
    );
    scanner.addRegistry('default', {
      url: 'registry.example.com',
      auth: new MtlsRepositoryAuth(stack, 'Auth', { secret }),
    });

    const cfn = scanner.scannerFunction.node.defaultChild as lambda.CfnFunction;
    const resolved = stack.resolve(cfn.environment) as {
      variables: Record<string, string>;
    };
    const parsed = JSON.parse(resolved.variables.BYOR_REGISTRIES);
    expect(parsed.default.url).toBe('registry.example.com');
    expect(parsed.default.authProvider).toBe(
      'byor_scanner.backends.auth.mtls.MtlsAuth',
    );
    expect(parsed.default.insecureTlsVerify).toBe(false);
  });

  it('rejects a trigger whose discovery handle is from another scanner', () => {
    const stack = freshStack();
    const a = newScanner(stack);
    const bVpc = new ec2.Vpc(stack, 'VpcB');
    const b = new InspectorScanner(stack, 'ScannerB', { vpc: bVpc });

    const manifest = new S3ManifestDiscoveryProvider(stack, 'Manifest');
    const foreignProvider = b.addDiscoveryProvider('manifest', manifest);

    expect(() =>
      a.addTrigger(
        'manifest',
        new S3ManifestTrigger(stack, 'Trigger', {
          discovery: foreignProvider,
          bucket: manifest.bucket,
        }),
      ),
    ).toThrow(/does not belong to this InspectorScanner/);
  });

  it('rejects non-alphanumeric ids (they become construct ids)', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);
    const secret = secretsmanager.Secret.fromSecretNameV2(stack, 'S', 'x');
    const auth = new MtlsRepositoryAuth(stack, 'Auth', { secret });

    expect(() => scanner.addRegistry('has space', { url: 'r', auth })).toThrow(
      /must be alphanumeric/,
    );
    expect(() =>
      scanner.addDiscoveryProvider(
        'dot.id',
        new S3ManifestDiscoveryProvider(stack, 'Manifest'),
      ),
    ).toThrow(/must be alphanumeric/);
  });

  it('rejects a duplicate trigger id', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);
    const manifest = new S3ManifestDiscoveryProvider(stack, 'Manifest');
    const provider = scanner.addDiscoveryProvider('manifest', manifest);

    scanner.addTrigger(
      'drop',
      new S3ManifestTrigger(stack, 'T1', {
        discovery: provider,
        bucket: manifest.bucket,
      }),
    );
    expect(() =>
      scanner.addTrigger(
        'drop',
        new S3ManifestTrigger(stack, 'T2', {
          discovery: provider,
          bucket: manifest.bucket,
        }),
      ),
    ).toThrow(/already has a trigger with id 'drop'/);
  });

  it('routes addAlarmAction onto every owned alarm, including later providers', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);

    // Register the action BEFORE attaching a provider — its failure alarm is
    // created later and must still receive the action (replay).
    scanner.addAlarmAction(new FakeAlarmAction());
    scanner.addDiscoveryProvider(
      'manifest',
      new S3ManifestDiscoveryProvider(stack, 'Manifest'),
    );

    const template = Template.fromStack(stack);
    // DLQ-depth + queue-age (coarse) + 5 per-stage + 2 SLO burn-rate (scanner
    // core) + 1 per-provider discovery failure alarm.
    template.resourceCountIs('AWS::CloudWatch::Alarm', 10);
    // Every alarm carries the action ARN.
    const alarms = template.findResources('AWS::CloudWatch::Alarm');
    for (const alarm of Object.values(alarms)) {
      expect(alarm.Properties.AlarmActions).toEqual([
        'arn:aws:sns:us-west-2:111111111111:ops',
      ]);
    }
  });

  it('metricScanFailures targets the BYORScan/ImagesFailed metric', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);

    const metric = scanner.metricScanFailures();
    expect(metric.namespace).toBe('BYORScan');
    expect(metric.metricName).toBe('ImagesFailed');
    expect(metric.statistic).toBe('Sum');
  });
});
