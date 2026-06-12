import { Stack, StackProps } from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';
import { BinaryLayer } from '@constructs/binary-layer';

/**
 * Standalone stack that holds the shared Lambda Layer with `skopeo` and
 * `inspector-sbomgen` binaries.
 *
 * Lives in its own stack so both ScannerStack and TestingStack (the
 * registry seeder) can attach the same layer without a circular
 * stack-to-stack dependency. Deployed first; the layer's ARN is exported
 * implicitly via the CDK cross-stack reference machinery when
 * ``binaryLayer`` is read by another stack.
 *
 * Updating skopeo / sbomgen versions: edit the build inputs in this
 * file. The asset hash is keyed on (image pin, build command, URL,
 * SHA256), so only changing those triggers a rebuild on next ``synth``.
 */
export class BinaryStack extends Stack {
  public readonly binaryLayer: lambda.ILayerVersion;

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const layer = new BinaryLayer(this, 'BinaryLayer', {
      description: 'skopeo + inspector-sbomgen for the BYOR scanner pipeline',
      compatibleArchitectures: [lambda.Architecture.X86_64],
      compatibleRuntimes: [lambda.Runtime.PYTHON_3_11],
    });

    layer.addBinaryFromSource('skopeo', {
      // Pinned by digest. Refresh in lockstep with the sbomgen entry below.
      buildImage:
        'golang:1.25-alpine@sha256:7143573479a34302243c6f8c33cf6c49fdde44c60e8f5dda0591adf0006cdc77',
      buildCommand: [
        'sh',
        '-c',
        [
          'apk add --no-cache git bash make',
          'git clone --depth 1 --branch v1.23.0 https://github.com/containers/skopeo /src',
          'cd /src',
          'DISABLE_CGO=1 CGO_ENABLED=0 make bin/skopeo.linux.amd64 DISABLE_DOCS=1',
          'cp /src/bin/skopeo.linux.amd64 /asset-output/skopeo',
        ].join(' && '),
      ],
    });

    layer.addBinaryFromArchive('inspector-sbomgen', {
      url: 'https://amazon-inspector-sbomgen.s3.amazonaws.com/1.14.1/linux/amd64/inspector-sbomgen.zip',
      sha256: '2b9512ea9acdc1eb1aa155f7f664f92b4dc96e14d3849fe1f1d3aa51f481b627',
      binaryInArchive: 'inspector-sbomgen-1.14.1/linux/amd64/inspector-sbomgen',
    });

    this.binaryLayer = layer.layer;
  }
}
