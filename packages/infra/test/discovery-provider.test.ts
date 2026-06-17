import { App, Stack } from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import {
  DiscoveryAttachment,
  IDiscoveryProvider,
  InspectorScanner,
  RegistryAttachment,
} from '@constructs/inspector-scanner';

/**
 * `addDiscoveryProvider` — a discovery Lambda per provider.
 *
 * Docker-free: `aws:cdk:bundling-stacks: []` makes CDK skip asset bundling, so
 * the per-provider `PythonFunction` never shells out to Docker (uv/SAM build
 * image). We assert against the construct's in-memory handles + the produced
 * Lambda/alarm, never reading `binaryLayer.layer` (which would freeze + build).
 */
describe('InspectorScanner addDiscoveryProvider', () => {
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

  /** Minimal `IDiscoveryProvider` test double. */
  function fakeProvider(
    dottedPath: string,
    opts: {
      environment?: Record<string, string>;
      layer?: lambda.ILayerVersion;
      registries?: RegistryAttachment[];
    } = {},
  ): IDiscoveryProvider & { grantReadCalls: iam.IRole[] } {
    const grantReadCalls: iam.IRole[] = [];
    return {
      dottedPath,
      environment: opts.environment ?? {},
      layer: opts.layer,
      registries: opts.registries,
      grantRead(role: iam.IRole) {
        grantReadCalls.push(role);
      },
      grantReadCalls,
    };
  }

  it('returns an attachment with its own discovery function + failure alarm', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);

    const attachment: DiscoveryAttachment = scanner.addDiscoveryProvider(
      'catalog',
      fakeProvider('byor_scanner.backends.discovery.static.StaticDiscovery'),
    );

    expect(attachment.id).toBe('catalog');
    expect(attachment.source).toBe('catalog');
    expect(attachment.discoveryFunction).toBeDefined();
    expect(attachment.failureAlarm).toBeInstanceOf(cloudwatch.Alarm);
    // Each provider gets its own dedicated Lambda, registered on the scanner.
    expect(scanner.discoveryProviders.get('catalog')).toBe(attachment);
    expect(scanner.discoveryProviders.size).toBe(1);
  });

  it('builds a distinct Lambda per provider', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);

    const a = scanner.addDiscoveryProvider('catalog', fakeProvider('p.A'));
    const b = scanner.addDiscoveryProvider('manifest', fakeProvider('p.B'));

    expect(a.discoveryFunction).not.toBe(b.discoveryFunction);
    expect(scanner.discoveryProviders.size).toBe(2);
  });

  it('grants send-messages + the provider grantRead on its own Lambda role', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);
    const provider = fakeProvider('p.Backend');

    const attachment = scanner.addDiscoveryProvider('catalog', provider);

    expect(provider.grantReadCalls).toHaveLength(1);
    expect(provider.grantReadCalls[0]).toBe(attachment.discoveryFunction.role);
  });

  it('throws on a duplicate provider id', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);
    scanner.addDiscoveryProvider('catalog', fakeProvider('p.Backend'));

    expect(() =>
      scanner.addDiscoveryProvider('catalog', fakeProvider('p.Other')),
    ).toThrow(/already has a discovery provider with id 'catalog'/);
  });

  it('accepts a registry handle that was added to this scanner', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);
    const prod = scanner.addRegistry('prod', {
      url: 'registry.example.com',
      auth: { dottedPath: 'p.Auth', environment: {}, grantRead() {} },
    });

    expect(() =>
      scanner.addDiscoveryProvider(
        'catalog',
        fakeProvider('p.Backend', { registries: [prod] }),
      ),
    ).not.toThrow();
  });

  it('throws when a provider references an unknown registry handle', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);
    // A handle never returned by THIS scanner's addRegistry.
    const foreign: RegistryAttachment = {
      id: 'ghost',
      url: 'ghost.example.com',
      auth: { dottedPath: 'p.Auth', environment: {}, grantRead() {} },
      insecureTlsVerify: false,
    };

    expect(() =>
      scanner.addDiscoveryProvider(
        'catalog',
        fakeProvider('p.Backend', { registries: [foreign] }),
      ),
    ).toThrow(/references registry 'ghost'/);
  });

  it('throws when a provider references a registry from a DIFFERENT scanner', () => {
    const stack = freshStack();
    const scannerA = newScanner(stack, 'A');
    const scannerB = newScanner(stack, 'B');
    // Registry attached to A, then referenced from a provider added to B.
    const prodA = scannerA.addRegistry('prod', {
      url: 'registry.example.com',
      auth: { dottedPath: 'p.Auth', environment: {}, grantRead() {} },
    });

    expect(() =>
      scannerB.addDiscoveryProvider(
        'catalog',
        fakeProvider('p.Backend', { registries: [prodA] }),
      ),
    ).toThrow(/references registry 'prod'/);
  });
});
