import { execFileSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib';

/**
 * Pure-TS helpers used by the BinaryLayer construct at synth time.
 *
 * These are split out of the construct so they can be unit-tested in
 * isolation ─ no CDK scope or constructs needed.
 *
 * All filesystem writes target a single staging directory which CDK
 * later wraps with `lambda.Code.fromAsset`.
 */

/** Spec for one binary built from source via Docker. */
export interface SourceBinarySpec {
  readonly name: string;
  readonly buildImage: cdk.DockerImage;
  readonly buildCommand: string[];
  /**
   * Pinned image identifier (digest-suffixed) used for asset hashing.
   * We capture this separately because `cdk.DockerImage` doesn't expose
   * the underlying string, and we need it to invalidate the asset cache
   * when the image changes.
   */
  readonly buildImagePin: string;
}

/** Spec for one binary downloaded from a URL and extracted from an archive. */
export interface ArchiveBinarySpec {
  readonly name: string;
  readonly url: string;
  readonly sha256: string;
  /**
   * Path of the binary inside the archive. Defaults to `name`.
   * Use this when the archive nests files under a versioned dir, e.g.
   * `inspector-sbomgen-1.14.1/linux/amd64/inspector-sbomgen`.
   */
  readonly binaryInArchive?: string;
}

/**
 * Build one source-spec binary into the staging dir's bin/ folder.
 *
 * Runs the build command inside the pinned Docker image, mounts the
 * staging bin/ as `/asset-output`, expects the command to deposit the
 * built binary there at `/asset-output/<name>`.
 */
export const buildSourceBinary = (
  spec: SourceBinarySpec,
  stagingDir: string,
): void => {
  const binDir = path.join(stagingDir, 'bin');
  fs.mkdirSync(binDir, { recursive: true });

  spec.buildImage.run({
    command: spec.buildCommand,
    volumes: [
      {
        hostPath: binDir,
        containerPath: '/asset-output',
      },
    ],
  });

  const expected = path.join(binDir, spec.name);
  if (!fs.existsSync(expected)) {
    throw new Error(
      `BinaryLayer build for '${spec.name}' did not produce ${expected}. ` +
        `The buildCommand must copy the binary to /asset-output/${spec.name}.`,
    );
  }
  fs.chmodSync(expected, 0o755);
};

/**
 * Fetch one archive-spec binary (synchronously), verify SHA256, extract
 * the named entry, place at `<stagingDir>/bin/<name>`, chmod +x.
 *
 * Uses `curl` for the download (synchronous via `execFileSync`) ─ this
 * keeps the construct's lifecycle synchronous, which CDK requires.
 * `curl` is universally available on macOS/Linux dev machines and CI
 * runners; on the rare Windows-only setup, the user needs to provide
 * an alternative download path.
 */
export const fetchArchiveBinary = (
  spec: ArchiveBinarySpec,
  stagingDir: string,
): void => {
  const binDir = path.join(stagingDir, 'bin');
  fs.mkdirSync(binDir, { recursive: true });

  const tmp = path.join(stagingDir, `.${spec.name}.archive`);
  downloadFileSync(spec.url, tmp);
  verifySha256Sync(tmp, spec.sha256);
  const inArchive = spec.binaryInArchive ?? spec.name;
  extractZipEntrySync(tmp, inArchive, path.join(binDir, spec.name));
  fs.chmodSync(path.join(binDir, spec.name), 0o755);
  fs.rmSync(tmp, { force: true });
};

/**
 * Asset hash that flips on any input change (image pin, build command,
 * URL, SHA256). Avoids the SOURCE-mode pitfall where bundling.command
 * changes don't invalidate the cache, and the OUTPUT-mode pitfall of
 * re-bundling on every synth.
 */
export const computeAssetHash = (
  sources: SourceBinarySpec[],
  archives: ArchiveBinarySpec[],
): string => {
  const inputs = {
    sources: sources.map((s) => ({
      name: s.name,
      image: s.buildImagePin,
      command: s.buildCommand,
    })),
    archives: archives.map((a) => ({
      name: a.name,
      url: a.url,
      sha256: a.sha256,
      inArchive: a.binaryInArchive ?? a.name,
    })),
  };
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(inputs))
    .digest('hex');
};

// ─── internal helpers ────────────────────────────────────────────────

const downloadFileSync = (url: string, dest: string): void => {
  // -fSL: fail-on-HTTP-error, silent, follow redirects.
  // -o: output file. Don't shell out to a string ─ argv array passed to
  // execFileSync sidesteps shell injection on the URL.
  execFileSync('curl', ['-fSL', '-o', dest, url], { stdio: 'inherit' });
};

const verifySha256Sync = (file: string, expected: string): void => {
  const buf = fs.readFileSync(file);
  const actual = crypto.createHash('sha256').update(buf).digest('hex');
  if (actual !== expected) {
    throw new Error(
      `SHA256 mismatch for ${file}: expected ${expected}, got ${actual}`,
    );
  }
};

/**
 * Synchronously extract a single entry from a zip via `unzip` CLI.
 *
 * yauzl is async-only; we'd need a `runSync` adapter to use it inside
 * a synchronous CDK construct. Since `unzip` is universally available
 * (macOS, Linux dev machines, CI runners), shell out to it. The argv
 * form of execFileSync prevents shell injection on the entry name.
 */
const extractZipEntrySync = (
  archive: string,
  entryPath: string,
  dest: string,
): void => {
  // Use yauzl's sync-style API isn't available, so spawn `unzip -p`
  // (extract entry to stdout) and redirect to the destination file.
  // This avoids reading the whole archive into memory at once.
  const data = execFileSync('unzip', ['-p', archive, entryPath], {
    stdio: ['ignore', 'pipe', 'inherit'],
    maxBuffer: 200 * 1024 * 1024, // 200 MB ─ headroom over current sbomgen size
  });
  if (data.length === 0) {
    throw new Error(`Entry ${entryPath} not found or empty in ${archive}`);
  }
  fs.writeFileSync(dest, data);
};
