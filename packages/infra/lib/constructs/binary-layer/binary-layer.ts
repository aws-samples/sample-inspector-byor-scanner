import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';
import {
  ArchiveBinarySpec,
  SourceBinarySpec,
  buildSourceBinary,
  computeAssetHash,
  fetchArchiveBinary,
} from './staging';

export interface BinaryLayerProps {
  /** Layer description shown in the AWS console. */
  readonly description?: string;
  /** Compatible architectures. Defaults to x86_64 only. */
  readonly compatibleArchitectures?: lambda.Architecture[];
  /** Compatible Lambda runtimes. Defaults to none (compatible with all). */
  readonly compatibleRuntimes?: lambda.Runtime[];
}

export interface AddBinaryFromSourceOptions {
  /**
   * Pinned Docker image used to build the binary. The image SHOULD be
   * digest-pinned (``name:tag@sha256:...``) for reproducible builds; we
   * forward the string into the asset hash so cached output is reused
   * only when the build inputs match exactly.
   */
  readonly buildImage: string;
  /**
   * Command run inside the build container. It MUST copy the resulting
   * binary to ``/asset-output/<name>`` ─ that path is the staging dir
   * mounted from the host.
   */
  readonly buildCommand: string[];
}

export interface AddBinaryFromArchiveOptions {
  /** HTTPS URL of the archive (zip). */
  readonly url: string;
  /** Hex-encoded SHA256 of the downloaded archive. Verified before extraction. */
  readonly sha256: string;
  /**
   * Path of the binary inside the archive. Defaults to the binary name.
   * Use this when the archive nests files under a versioned dir.
   */
  readonly binaryInArchive?: string;
}

/**
 * A Lambda Layer holding one or more static binaries.
 *
 * Use this construct as a *builder*: instantiate, call
 * :meth:`addBinaryFromSource` and/or :meth:`addBinaryFromArchive`, then
 * read :attr:`layer` to attach to a Lambda function. The actual layer
 * resource is materialized lazily on first read of :attr:`layer`. After
 * that, no further binaries can be added.
 *
 * Layer layout (after Lambda mounts at ``/opt``)::
 *
 *   /opt/bin/<name1>
 *   /opt/bin/<name2>
 *
 * ``/opt/bin`` is automatically on ``$PATH`` for Lambda.
 *
 * Build mechanics (synth time):
 *
 * - **From source** ─ runs the pinned Docker image with the staging
 *   dir mounted as ``/asset-output``; the build command copies the
 *   produced binary there.
 * - **From archive** ─ downloads the URL via ``curl``, verifies SHA256,
 *   extracts the named entry via ``unzip -p``, places at ``bin/<name>``.
 *
 * Asset cache: keyed by ``CUSTOM`` hash over (image pin, build command,
 * URL, SHA256). Re-runs only when inputs change.
 *
 * Requirements on the build host: ``docker`` (for source builds),
 * ``curl`` and ``unzip`` (for archive fetches). All three are present
 * on standard macOS / Linux dev machines and CI runners.
 */
export class BinaryLayer extends Construct {
  private readonly sources: SourceBinarySpec[] = [];
  private readonly archives: ArchiveBinarySpec[] = [];
  private readonly props: BinaryLayerProps;
  private _layer?: lambda.LayerVersion;

  constructor(scope: Construct, id: string, props: BinaryLayerProps = {}) {
    super(scope, id);
    this.props = props;
  }

  /**
   * Add a binary built from source via Docker.
   *
   * @param name  Filename under ``bin/`` in the layer.
   * @param opts  Build image (digest-pinned) + command.
   */
  public addBinaryFromSource(
    name: string,
    opts: AddBinaryFromSourceOptions,
  ): this {
    this.assertNotMaterialized();
    this.assertUniqueName(name);
    this.sources.push({
      name,
      buildImage: cdk.DockerImage.fromRegistry(opts.buildImage),
      buildCommand: opts.buildCommand,
      buildImagePin: opts.buildImage,
    });
    return this;
  }

  /**
   * Add a binary downloaded from a URL and extracted from a zip.
   *
   * @param name  Filename under ``bin/`` in the layer.
   * @param opts  URL + SHA256 + (optional) path inside the archive.
   */
  public addBinaryFromArchive(
    name: string,
    opts: AddBinaryFromArchiveOptions,
  ): this {
    this.assertNotMaterialized();
    this.assertUniqueName(name);
    this.archives.push({
      name,
      url: opts.url,
      sha256: opts.sha256,
      binaryInArchive: opts.binaryInArchive,
    });
    return this;
  }

  /**
   * The materialized Lambda Layer. Reading this property triggers the
   * synth-time build / fetch of every added binary. After the first
   * read, no further binaries can be added.
   */
  public get layer(): lambda.LayerVersion {
    if (!this._layer) {
      this._layer = this.materialize();
    }
    return this._layer;
  }

  // ─── internals ─────────────────────────────────────────────────────

  private materialize(): lambda.LayerVersion {
    if (this.sources.length === 0 && this.archives.length === 0) {
      throw new Error(
        `BinaryLayer ${this.node.id} has no binaries. Call ` +
          'addBinaryFromSource() or addBinaryFromArchive() before attaching.',
      );
    }

    const assetHash = computeAssetHash(this.sources, this.archives);
    const stagingDir = path.join(
      os.tmpdir(),
      'cdk-binary-layer',
      `${this.node.id}-${assetHash.slice(0, 12)}`,
    );

    if (!this.allBinariesPresent(stagingDir)) {
      fs.rmSync(stagingDir, { recursive: true, force: true });
      fs.mkdirSync(stagingDir, { recursive: true });
      for (const spec of this.sources) {
        buildSourceBinary(spec, stagingDir);
      }
      for (const spec of this.archives) {
        fetchArchiveBinary(spec, stagingDir);
      }
    }

    return new lambda.LayerVersion(this, 'LayerVersion', {
      code: lambda.Code.fromAsset(stagingDir, {
        assetHash,
        assetHashType: cdk.AssetHashType.CUSTOM,
      }),
      compatibleArchitectures: this.props.compatibleArchitectures ?? [
        lambda.Architecture.X86_64,
      ],
      compatibleRuntimes: this.props.compatibleRuntimes,
      description: this.props.description,
    });
  }

  private allBinariesPresent(stagingDir: string): boolean {
    const binDir = path.join(stagingDir, 'bin');
    if (!fs.existsSync(binDir)) return false;
    const expected = [
      ...this.sources.map((s) => s.name),
      ...this.archives.map((a) => a.name),
    ];
    return expected.every((n) => fs.existsSync(path.join(binDir, n)));
  }

  private assertNotMaterialized(): void {
    if (this._layer) {
      throw new Error(
        `BinaryLayer ${this.node.id} is already materialized; ` +
          'add binaries before reading .layer.',
      );
    }
  }

  private assertUniqueName(name: string): void {
    const existing = [
      ...this.sources.map((s) => s.name),
      ...this.archives.map((a) => a.name),
    ];
    if (existing.includes(name)) {
      throw new Error(
        `BinaryLayer ${this.node.id} already has a binary named '${name}'`,
      );
    }
  }
}
