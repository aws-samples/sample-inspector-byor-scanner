import { App, Stack } from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import {
  InspectorScanner,
  IRepositoryAuth,
  RegistryAttachment,
} from '@constructs/inspector-scanner';

/**
 * `addRegistry` + the Lazy `BYOR_REGISTRIES` env var.
 *
 * These tests are Docker-free: setting `aws:cdk:bundling-stacks: []` makes CDK
 * skip asset bundling, so the scanner's `PythonFunction` never shells out to
 * Docker (uv/SAM build image) at construction. We assert against the construct's
 * in-memory state + resolve the Lazy `BYOR_REGISTRIES` token via `stack.resolve`
 * — no full synth (which would need Docker) required.
 *
 * `grantRead` is asserted via a fake `IRepositoryAuth` spy (no Docker / no IAM
 * template synth needed).
 */
describe('InspectorScanner addRegistry', () => {
  function freshStack(): Stack {
    const app = new App({ context: { 'aws:cdk:bundling-stacks': [] } });
    // Region pinned so the ADOT layer ARN lookup resolves.
    return new Stack(app, 'TestStack', {
      env: { account: '111111111111', region: 'us-west-2' },
    });
  }

  function newScanner(stack: Stack): InspectorScanner {
    const vpc = new ec2.Vpc(stack, 'Vpc');
    return new InspectorScanner(stack, 'Scanner', { vpc });
  }

  /** Minimal `IRepositoryAuth` test double that records `grantRead` calls. */
  function fakeAuth(
    dottedPath: string,
    environment: Record<string, string>,
    opts: { layer?: lambda.ILayerVersion } = {},
  ): IRepositoryAuth & { grantReadCalls: iam.IRole[] } {
    const grantReadCalls: iam.IRole[] = [];
    return {
      dottedPath,
      environment,
      layer: opts.layer,
      grantRead(role: iam.IRole) {
        grantReadCalls.push(role);
      },
      grantReadCalls,
    };
  }

  /** Resolve the scanner Lambda's `BYOR_REGISTRIES` env to a parsed JSON object. */
  function resolveByorRegistries(
    stack: Stack,
    scanner: InspectorScanner,
  ): Record<string, unknown> {
    const fn = scanner.scannerFunction as lambda.Function;
    // `environment` is private on Function; reach it through the CfnFunction.
    const cfn = fn.node.defaultChild as lambda.CfnFunction;
    const resolved = stack.resolve(cfn.environment) as {
      variables: Record<string, string>;
    };
    return JSON.parse(resolved.variables.BYOR_REGISTRIES);
  }

  it('returns an attachment with the right id / url / auth', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);
    const auth = fakeAuth('byor_scanner.backends.auth.mtls.MtlsAuth', {
      BYOR_MTLS_SECRET_NAME: 'scanner/prod-certs',
    });

    const attachment: RegistryAttachment = scanner.addRegistry('prod', {
      url: 'registry.example.com',
      auth,
    });

    expect(attachment.id).toBe('prod');
    expect(attachment.url).toBe('registry.example.com');
    expect(attachment.auth).toBe(auth);
    expect(scanner.registries.get('prod')).toBe(attachment);
    expect(scanner.registries.size).toBe(1);
  });

  it('calls grantRead eagerly on the scanner role', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);
    const auth = fakeAuth('byor_scanner.backends.auth.mtls.MtlsAuth', {
      BYOR_MTLS_SECRET_NAME: 'scanner/prod-certs',
    });

    scanner.addRegistry('prod', { url: 'registry.example.com', auth });

    expect(auth.grantReadCalls).toHaveLength(1);
    expect(auth.grantReadCalls[0]).toBe(scanner.scannerFunction.role);
  });

  it('throws on a duplicate id', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);
    scanner.addRegistry('prod', {
      url: 'registry.example.com',
      auth: fakeAuth('p.Auth', {}),
    });

    expect(() =>
      scanner.addRegistry('prod', {
        url: 'other.example.com',
        auth: fakeAuth('p.Auth', {}),
      }),
    ).toThrow(/already has a registry with id 'prod'/);
  });

  it('serializes BYOR_REGISTRIES with both ids in the camelCase shape, authEnv nested per id', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);

    scanner.addRegistry('prod', {
      url: 'registry.example.com',
      auth: fakeAuth('byor_scanner.backends.auth.mtls.MtlsAuth', {
        BYOR_MTLS_SECRET_NAME: 'scanner/prod-certs',
      }),
    });
    scanner.addRegistry('staging', {
      url: 'staging.example.com',
      auth: fakeAuth('byor_scanner.backends.auth.basic.BasicAuth', {
        BYOR_BASIC_SECRET_NAME: 'scanner/stg-creds',
      }),
      insecureTlsVerify: true,
    });

    const registries = resolveByorRegistries(stack, scanner);

    expect(Object.keys(registries).sort()).toEqual(['prod', 'staging']);
    expect(registries.prod).toEqual({
      url: 'registry.example.com',
      authProvider: 'byor_scanner.backends.auth.mtls.MtlsAuth',
      authEnv: { BYOR_MTLS_SECRET_NAME: 'scanner/prod-certs' },
      insecureTlsVerify: false,
    });
    expect(registries.staging).toEqual({
      url: 'staging.example.com',
      authProvider: 'byor_scanner.backends.auth.basic.BasicAuth',
      authEnv: { BYOR_BASIC_SECRET_NAME: 'scanner/stg-creds' },
      insecureTlsVerify: true,
    });
  });

  it('two registries sharing an auth env do NOT collide (authEnv nested, not flattened)', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);

    // Both use the SAME env var name but different values — the whole point of
    // nesting authEnv per id.
    scanner.addRegistry('prod', {
      url: 'prod.example.com',
      auth: fakeAuth('byor_scanner.backends.auth.mtls.MtlsAuth', {
        BYOR_MTLS_SECRET_NAME: 'scanner/prod-certs',
      }),
    });
    scanner.addRegistry('staging', {
      url: 'staging.example.com',
      auth: fakeAuth('byor_scanner.backends.auth.mtls.MtlsAuth', {
        BYOR_MTLS_SECRET_NAME: 'scanner/stg-certs',
      }),
    });

    const registries = resolveByorRegistries(stack, scanner) as Record<
      string,
      { authEnv: Record<string, string> }
    >;

    expect(registries.prod.authEnv.BYOR_MTLS_SECRET_NAME).toBe('scanner/prod-certs');
    expect(registries.staging.authEnv.BYOR_MTLS_SECRET_NAME).toBe('scanner/stg-certs');
  });

  it('BYOR_REGISTRIES resolves to an empty map when no registry is added (Lazy avoids the empty-map trap differently — it is computed at synth)', () => {
    const stack = freshStack();
    const scanner = newScanner(stack);

    // With no addRegistry calls the produce callback returns {} — but because it
    // is Lazy, adding registries AFTER construction (above tests) is honored.
    expect(resolveByorRegistries(stack, scanner)).toEqual({});
  });
});
