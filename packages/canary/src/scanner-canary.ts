import * as synthetics from '@aws/synthetics-puppeteer';
import { InvokeCommand, LambdaClient } from '@aws-sdk/client-lambda';
import { HeadObjectCommand, S3Client } from '@aws-sdk/client-s3';

const PUSHER_FUNCTION_NAME = process.env.PUSHER_FUNCTION_NAME!;
const FINDINGS_BUCKET = process.env.FINDINGS_BUCKET!;
const TEST_IMAGE = process.env.TEST_IMAGE ?? 'registry.test.internal:5000/alpine';
const TEST_IMAGE_TAG = process.env.TEST_IMAGE_TAG ?? '3.19';

const POLL_INTERVAL_MS = 10_000;
const POLL_TIMEOUT_MS = 5 * 60_000;

const lambda = new LambdaClient({});
const s3 = new S3Client({});

const scannerCanary = async (): Promise<void> => {
  const runId = `canary-${Date.now()}`;

  await synthetics.executeStep('triggerScan', async () => {
    await lambda.send(
      new InvokeCommand({
        FunctionName: PUSHER_FUNCTION_NAME,
        Payload: Buffer.from(
          JSON.stringify({
            mode: 'manual',
            canaryRunId: runId,
            images: [{ image: TEST_IMAGE, ref: TEST_IMAGE_TAG }],
          }),
        ),
      }),
    );
  });

  await synthetics.executeStep('waitForProcessing', async () => {
    const key = `findings/${TEST_IMAGE}/${TEST_IMAGE_TAG}/${runId}.json`;
    const deadline = Date.now() + POLL_TIMEOUT_MS;

    while (Date.now() < deadline) {
      try {
        await s3.send(
          new HeadObjectCommand({ Bucket: FINDINGS_BUCKET, Key: key }),
        );
        return;
      } catch (err) {
        const status = (err as { $metadata?: { httpStatusCode?: number } })
          .$metadata?.httpStatusCode;
        if (status !== 404) {
          throw err;
        }
      }
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    }

    throw new Error(
      `Timed out after ${POLL_TIMEOUT_MS}ms waiting for s3://${FINDINGS_BUCKET}/${key}`,
    );
  });
};

export const handler = async (): Promise<void> => scannerCanary();
