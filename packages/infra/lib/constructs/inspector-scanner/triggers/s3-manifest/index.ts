import { Duration, RemovalPolicy } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as s3n from 'aws-cdk-lib/aws-s3-notifications';
import { Construct } from 'constructs';
import { IDiscoveryPlugin, IDiscoveryTrigger } from '../discovery-trigger';
import { S3ManifestDiscoveryPlugin } from './plugin';

export interface S3ManifestTriggerProps {
  /**
   * BYO bucket. If omitted, the construct creates one with
   * `removalPolicy: DESTROY` + `autoDeleteObjects: true` so `cdk destroy`
   * is clean ─ manifests are inputs, not audit data, and the customer's
   * org-wide bucket policies typically govern BYO production buckets.
   */
  readonly bucket?: s3.IBucket;

  /**
   * Optional prefix filter on the OBJECT_CREATED notification. Only
   * objects whose keys start with this value fire the discovery Lambda.
   * Useful when the bucket is shared with other tooling.
   */
  readonly manifestPrefix?: string;

  /**
   * Logical source name emitted as the `source` dimension on metrics and
   * the `source` field on every SQS message. Keep it short, unique within
   * the deploy, and bounded ─ unbounded values blow up CloudWatch metric
   * cardinality.
   */
  readonly source: string;

  /**
   * Override the discovery plugin. Defaults to
   * {@link S3ManifestDiscoveryPlugin} bound to this trigger's bucket.
   */
  readonly plugin?: IDiscoveryPlugin;
}

/**
 * S3-bucket trigger: drop a JSON manifest into the bucket → discovery
 * Lambda fires → SBOM scan kicks off.
 *
 * The bucket is auto-created (or BYO). On `bind`, an OBJECT_CREATED
 * notification is wired to the discovery Lambda, optionally filtered by
 * `manifestPrefix`. The default plugin reads each manifest as a JSON
 * array of `{image, ref}` entries.
 *
 * Default manifest schema (the JSON file customers drop in):
 *
 *     [
 *       { "image": "library/nginx", "ref": "1.25" },
 *       { "image": "myorg/api",     "ref": "sha256:abc..." }
 *     ]
 */
export class S3ManifestTrigger extends Construct implements IDiscoveryTrigger {
  public readonly source: string;
  public readonly plugin: IDiscoveryPlugin;
  public readonly bucket: s3.IBucket;

  private readonly manifestPrefix?: string;
  private readonly ownsBucket: boolean;

  constructor(scope: Construct, id: string, props: S3ManifestTriggerProps) {
    super(scope, id);

    this.source = props.source;
    this.manifestPrefix = props.manifestPrefix;

    if (props.bucket) {
      this.bucket = props.bucket;
      this.ownsBucket = false;
    } else {
      this.bucket = new s3.Bucket(this, 'Bucket', {
        // Manifests are inputs, not audit data ─ safe to drop on destroy.
        // The findings bucket (in InspectorScanner) keeps its RETAIN policy
        // because findings are valuable history.
        removalPolicy: RemovalPolicy.DESTROY,
        autoDeleteObjects: true,
        enforceSSL: true,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
        encryption: s3.BucketEncryption.S3_MANAGED,
        lifecycleRules: [
          // Keep manifests around for a week so an operator can replay
          // recent triggers; longer retention has no audit value.
          { expiration: Duration.days(7) },
        ],
      });
      this.ownsBucket = true;
    }

    this.plugin = props.plugin ?? new S3ManifestDiscoveryPlugin({ bucket: this.bucket });
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

  public grantRead(role: iam.IRole): void {
    // Plugin already grants its own read, but a BYO plugin override might
    // forget; granting here too is idempotent and keeps the trigger's
    // contract honest.
    this.bucket.grantRead(role);
  }

  /** Whether this trigger created its own bucket (vs BYO). */
  public get isBucketOwned(): boolean {
    return this.ownsBucket;
  }
}
