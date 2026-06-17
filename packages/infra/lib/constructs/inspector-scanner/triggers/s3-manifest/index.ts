import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as s3n from 'aws-cdk-lib/aws-s3-notifications';
import { Construct } from 'constructs';
import { DiscoveryAttachment, ITrigger } from '../discovery-trigger';

export interface S3ManifestTriggerProps {
  /**
   * The discovery provider this trigger fires, by handle (returned by
   * {@link InspectorScanner.addDiscoveryProvider}). The S3 OBJECT_CREATED
   * notification is wired onto this provider's Lambda.
   */
  readonly discovery: DiscoveryAttachment;

  /**
   * The bucket whose OBJECT_CREATED events fire the provider. MUST be the SAME
   * bucket the paired {@link S3ManifestDiscoveryProvider} provider reads ─ pass
   * the provider's `bucket` here. The provider OWNS the bucket (creates one if
   * not supplied); the trigger only attaches a notification to it, so there is
   * no way to point the trigger and provider at different buckets.
   */
  readonly bucket: s3.IBucket;

  /**
   * Optional prefix filter on the OBJECT_CREATED notification. Only
   * objects whose keys start with this value fire the discovery Lambda.
   * Useful when the bucket is shared with other tooling.
   */
  readonly manifestPrefix?: string;

  /**
   * Optional logical source name (informational only ─ the `source` stamped on
   * messages + metrics comes from the provider). Keep it short, unique within
   * the deploy, and bounded ─ unbounded values blow up CloudWatch metric
   * cardinality.
   */
  readonly source?: string;
}

/**
 * S3-bucket trigger: drop a JSON manifest into the bucket → the referenced
 * provider's discovery Lambda fires → SBOM scan kicks off.
 *
 * The bucket is owned by the paired {@link S3ManifestDiscoveryProvider} provider
 * (which reads the manifests); this trigger only attaches an OBJECT_CREATED
 * notification to it, optionally filtered by `manifestPrefix`. Pass the
 * provider's `bucket` as {@link S3ManifestTriggerProps.bucket}.
 *
 * Default manifest schema (the JSON file customers drop in):
 *
 *     [
 *       { "image": "library/nginx", "ref": "1.25" },
 *       { "image": "myorg/api",     "ref": "sha256:abc..." }
 *     ]
 */
export class S3ManifestTrigger extends Construct implements ITrigger {
  public readonly discovery: DiscoveryAttachment;
  public readonly source?: string;
  public readonly bucket: s3.IBucket;

  private readonly manifestPrefix?: string;

  constructor(scope: Construct, id: string, props: S3ManifestTriggerProps) {
    super(scope, id);

    this.discovery = props.discovery;
    this.source = props.source;
    this.bucket = props.bucket;
    this.manifestPrefix = props.manifestPrefix;
  }

  public bind(_scope: Construct, discoveryFn: lambda.IFunction): void {
    const filters: s3.NotificationKeyFilter[] = this.manifestPrefix
      ? [{ prefix: this.manifestPrefix }]
      : [];
    this.bucket.addEventNotification(
      s3.EventType.OBJECT_CREATED,
      new s3n.LambdaDestination(discoveryFn),
      ...filters,
    );
  }

  public grantInvoke(_role: iam.IRole): void {
    // `addEventNotification` (in `bind`) attaches the `lambda:InvokeFunction`
    // resource policy allowing S3 to invoke the discovery Lambda, so there is
    // nothing extra to grant against the discovery role here.
  }
}
