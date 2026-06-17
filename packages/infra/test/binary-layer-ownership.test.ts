import { App, Stack } from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { BinaryLayer } from '@constructs/binary-layer';
import { InspectorScanner } from '@constructs/inspector-scanner';

/**
 * Owned BinaryLayer. These tests are Docker-free: they exercise the construct's
 * API surface WITHOUT reading `binaryLayer.layer` (which would trigger the
 * synth-time skopeo Docker build and freeze the layer). Asserting an actual
 * `addLayers` attach requires a full synth (Docker) and is therefore out of
 * scope here. The structural guarantee we CAN prove cheaply is the one that
 * matters for the lazy-attach design: constructing the scanner must NOT freeze
 * the layer in the constructor, so post-construction `addBinary*` calls still
 * succeed.
 */
describe('InspectorScanner owned BinaryLayer', () => {
  function newScanner(stack: Stack): InspectorScanner {
    const vpc = new ec2.Vpc(stack, 'Vpc');
    return new InspectorScanner(stack, 'Scanner', { vpc });
  }

  function freshStack(): Stack {
    // `aws:cdk:bundling-stacks: []` makes CDK skip asset bundling for all
    // stacks, so the scanner's `PythonFunction` does NOT shell out to Docker
    // (`uv`/SAM build image) at construction. This keeps the test Docker-free.
    // The binary layer is unaffected — it only builds when `.layer` is read,
    // which these tests deliberately never do.
    const app = new App({ context: { 'aws:cdk:bundling-stacks': [] } });
    // Region pinned so the ADOT layer ARN lookup resolves.
    return new Stack(app, 'TestStack', {
      env: { account: '111111111111', region: 'us-west-2' },
    });
  }

  it('exposes a construct-owned binaryLayer', () => {
    const scanner = newScanner(freshStack());
    expect(scanner.binaryLayer).toBeInstanceOf(BinaryLayer);
  });

  it('exposes chainable addBinaryFromSource / addBinaryFromArchive', () => {
    const scanner = newScanner(freshStack());
    expect(typeof scanner.addBinaryFromSource).toBe('function');
    expect(typeof scanner.addBinaryFromArchive).toBe('function');
  });

  it('does NOT freeze the layer in the constructor (addBinaryFromArchive after construction succeeds)', () => {
    const scanner = newScanner(freshStack());

    // If the constructor had read `.layer`, the BinaryLayer would be
    // materialized and this would throw "already materialized". It must not.
    expect(() =>
      scanner.addBinaryFromArchive('trivy', {
        url: 'https://example.com/trivy.zip',
        sha256:
          '0000000000000000000000000000000000000000000000000000000000000000',
      }),
    ).not.toThrow();
  });

  it('does NOT freeze the layer in the constructor (addBinaryFromSource after construction succeeds)', () => {
    const scanner = newScanner(freshStack());

    expect(() =>
      scanner.addBinaryFromSource('custom-tool', {
        buildImage: 'golang:1.25-alpine',
        buildCommand: ['sh', '-c', 'cp /bin/true /asset-output/custom-tool'],
      }),
    ).not.toThrow();
  });

  it('addBinary* return the scanner for chaining', () => {
    const scanner = newScanner(freshStack());
    const returned = scanner.addBinaryFromArchive('extra', {
      url: 'https://example.com/extra.zip',
      sha256:
        '1111111111111111111111111111111111111111111111111111111111111111',
    });
    expect(returned).toBe(scanner);
  });

  it('rejects a duplicate binary name (skopeo is pre-loaded)', () => {
    const scanner = newScanner(freshStack());
    // Proves the owned layer really is pre-loaded with skopeo: re-adding it
    // hits the BinaryLayer uniqueness guard.
    expect(() =>
      scanner.addBinaryFromArchive('skopeo', {
        url: 'https://example.com/skopeo.zip',
        sha256:
          '2222222222222222222222222222222222222222222222222222222222222222',
      }),
    ).toThrow(/already has a binary named 'skopeo'/);
  });
});
