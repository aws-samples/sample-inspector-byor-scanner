import * as synthetics from '@aws/synthetics-puppeteer';
import {
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';

const MANIFEST_BUCKET = process.env.MANIFEST_BUCKET!;
const FINDINGS_BUCKET = process.env.FINDINGS_BUCKET!;
const TEST_IMAGE = process.env.TEST_IMAGE ?? 'alpine';
const TEST_IMAGE_TAG = process.env.TEST_IMAGE_TAG ?? '3.19';

const POLL_INTERVAL_MS = 10_000;
const POLL_TIMEOUT_MS = 5 * 60_000;

export const handler = async (): Promise<void> => {
  const s3 = new S3Client({});
  const startTime = new Date();

  await synthetics.executeStep('triggerScan', async () => {
    const manifestKey = `canary/${startTime.toISOString().replace(/[:.]/g, '-')}.json`;
    const manifest = [{ image: TEST_IMAGE, ref: TEST_IMAGE_TAG, sourceType: 'canary' }];

    await s3.send(
      new PutObjectCommand({
        Bucket: MANIFEST_BUCKET,
        Key: manifestKey,
        Body: JSON.stringify(manifest),
        ContentType: 'application/json',
      }),
    );
  });

  await synthetics.executeStep('waitForFindings', async () => {
    const deadline = Date.now() + POLL_TIMEOUT_MS;
    // Poll broadly under findings/<image>/ since the scanner uses a resolved
    // digest (not the tag) as the next path segment. The startTime filter
    // ensures we only match findings produced by this canary run.
    const prefix = `findings/canary/${TEST_IMAGE}/`;

    while (Date.now() < deadline) {
      const result = await s3.send(
        new ListObjectsV2Command({
          Bucket: FINDINGS_BUCKET,
          Prefix: prefix,
        }),
      );

      const recent = (result.Contents ?? []).filter(
        (obj) => obj.LastModified && obj.LastModified > startTime,
      );

      if (recent.length > 0) {
        return;
      }

      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    }

    throw new Error(
      `Timed out after ${POLL_TIMEOUT_MS}ms waiting for findings at ${prefix}`,
    );
  });
};
