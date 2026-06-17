import { App, Stack } from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as scheduler from 'aws-cdk-lib/aws-scheduler';
import {
  DiscoveryAttachment,
  IDiscoveryProvider,
  InspectorScanner,
  S3ManifestTrigger,
  ScheduledTrigger,
  TriggerAttachment,
} from '@constructs/inspector-scanner';

/**
 * Triggers reference a discovery provider BY HANDLE.
 *
 * Docker-free: `aws:cdk:bundling-stacks: []` skips asset bundling so the
 * per-provider `PythonFunction` never shells out to Docker. We assert against
 * the returned handles + the eager event-source wiring done in `bind`, and the
 * cross-instance ownership validation. We deliberately do NOT call
 * `Template.fromStack` ─ a full synth would read `binaryLayer.layer` via the
 * lazy-attach Aspect and trigger the skopeo Docker build.
 */
describe('InspectorScanner addTrigger', () => {
  function freshStack(): Stack {
    const app = new App({ context: { 'aws:cdk:bundling-stacks': [] } });
    return new Stack(app, 'TestStack', {
      env: { account: '111111111111', region: 'us-west-2' },
    });
  }

  function newScanner(stack: Stack, idSuffix = ''): InspectorScanner {
    const vpc = new ec2.Vpc(stack, `Vpc${idSuffix}`);
    return new InspectorScanner(stack, `Scanner${idSuffix}`, { vpc });
  }

  function fakeProvider(dottedPath: string): IDiscoveryProvider {
    return {
      dottedPath,
      environment: {},
      grantRead() {},
    };
  }

  it('binds a trigger to its provider Lambda (bind sees the provider function)', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);
    const provider = scanner.addDiscoveryProvider(
      'manifests',
      fakeProvider('p.S3Manifest'),
    );
    const trigger = new S3ManifestTrigger(stack, 'Trigger', {
      discovery: provider,
      bucket: new s3.Bucket(stack, 'Bucket'),
    });

    let boundFn: lambda.IFunction | undefined;
    const origBind = trigger.bind.bind(trigger);
    trigger.bind = (scope, fn) => {
      boundFn = fn;
      origBind(scope, fn);
    };

    const attachment: TriggerAttachment = scanner.addTrigger('drop', trigger);

    expect(attachment.id).toBe('drop');
    expect(attachment.discovery).toBe(provider);
    // The L3 binds onto the provider's OWN discovery Lambda.
    expect(boundFn).toBe(provider.discoveryFunction);
  });

  it('a scheduled trigger eagerly creates its EventBridge schedule on bind', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);
    const provider = scanner.addDiscoveryProvider(
      'nightly',
      fakeProvider('p.Scheduled'),
    );
    const trigger = new ScheduledTrigger(stack, 'Cron', {
      discovery: provider,
      schedules: [{ id: 'Nightly', schedule: 'rate(1 day)' }],
    });

    scanner.addTrigger('cron', trigger);

    // `bind` creates the CfnSchedule construct eagerly (no synth needed).
    const schedules = stack.node
      .findAll()
      .filter((c) => c instanceof scheduler.CfnSchedule);
    expect(schedules).toHaveLength(1);
  });

  it('runs the trigger grantInvoke seam against the provider Lambda role', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);
    const provider = scanner.addDiscoveryProvider(
      'manifests',
      fakeProvider('p.S3Manifest'),
    );
    const trigger = new S3ManifestTrigger(stack, 'Trigger', {
      discovery: provider,
      bucket: new s3.Bucket(stack, 'Bucket'),
    });

    let grantedRole: iam.IRole | undefined;
    const origGrant = trigger.grantInvoke.bind(trigger);
    trigger.grantInvoke = (role) => {
      grantedRole = role;
      origGrant(role);
    };

    scanner.addTrigger('drop', trigger);
    expect(grantedRole).toBe(provider.discoveryFunction.role);
  });

  it('rejects a discovery handle that belongs to a DIFFERENT scanner', () => {
    const stack = freshStack();
    const scannerA = newScanner(stack, 'A');
    const scannerB = newScanner(stack, 'B');
    // Provider attached to A; trigger references A's handle but is added to B.
    const providerA = scannerA.addDiscoveryProvider(
      'manifests',
      fakeProvider('p.S3Manifest'),
    );
    const trigger = new S3ManifestTrigger(stack, 'Trigger', {
      discovery: providerA,
      bucket: new s3.Bucket(stack, 'Bucket'),
    });

    expect(() => scannerB.addTrigger('drop', trigger)).toThrow(
      /does not belong to this InspectorScanner/,
    );
  });

  it('rejects a fabricated discovery handle not produced by addDiscoveryProvider', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);
    const real = scanner.addDiscoveryProvider('real', fakeProvider('p.Backend'));
    // Same id as a real provider, but a different (fabricated) object identity.
    const fake: DiscoveryAttachment = {
      id: real.id,
      source: real.source,
      discoveryFunction: real.discoveryFunction,
      failureAlarm: real.failureAlarm,
    };
    const trigger = new S3ManifestTrigger(stack, 'Trigger', {
      discovery: fake,
      bucket: new s3.Bucket(stack, 'Bucket'),
    });

    expect(() => scanner.addTrigger('drop', trigger)).toThrow(
      /does not belong to this InspectorScanner/,
    );
  });
});
