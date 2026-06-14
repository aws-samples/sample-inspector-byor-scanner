import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';

/**
 * ADOT (AWS Distro for OpenTelemetry) Python layer ARNs, keyed by region.
 * Provides Application Signals + auto-instrumentation. Account 615299751070 is
 * AWS-owned. Layer revisions advance independently per region; refresh ~quarterly.
 *
 * A typed region→ARN map (borrowed from the official alpha package's
 * version-enum idea) so an unlisted region fails fast with an actionable error
 * instead of synthesizing a broken function — the us-east-1 ARN-drift class of
 * bug.
 *
 * @see https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Application-Signals-Lambda.html
 */
export const ADOT_PYTHON_LAYER_ARNS: Readonly<Record<string, string>> = {
  'us-west-2':
    'arn:aws:lambda:us-west-2:615299751070:layer:AWSOpenTelemetryDistroPython:29',
  'us-west-1':
    'arn:aws:lambda:us-west-1:615299751070:layer:AWSOpenTelemetryDistroPython:29',
  'us-east-1':
    'arn:aws:lambda:us-east-1:615299751070:layer:AWSOpenTelemetryDistroPython:25',
};

/**
 * Resolve the ADOT Python layer for `region`, or throw a clear error listing
 * the supported regions when it isn't mapped.
 */
export function adotPythonLayer(
  scope: Construct,
  id: string,
  region: string,
): lambda.ILayerVersion {
  const arn = ADOT_PYTHON_LAYER_ARNS[region];
  if (!arn) {
    throw new Error(
      `No ADOT Python layer ARN configured for region '${region}'. ` +
        `Supported regions: ${Object.keys(ADOT_PYTHON_LAYER_ARNS).sort().join(', ')}. ` +
        'Add the ARN to ADOT_PYTHON_LAYER_ARNS in observability/adot-layer.ts ' +
        '(see the AWS Application Signals Lambda docs).',
    );
  }
  return lambda.LayerVersion.fromLayerVersionArn(scope, id, arn);
}
