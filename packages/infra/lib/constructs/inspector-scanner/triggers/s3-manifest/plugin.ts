import { Duration, RemovalPolicy } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import { IDiscoveryProvider } from '../discovery-trigger';

const ENV_MANIFEST_BUCKET = 'BYOR_MANIFEST_BUCKET';

export interface S3ManifestDiscoveryProviderProps {
  /**
   * Bucket the provider reads manifests from. If omitted, the provider creates
   * one (exposed via {@link bucket}). Pass that same bucket to the paired
   * {@link S3ManifestTrigger}.
   */
  readonly bucket?: s3.IBucket;
}

/**
 * Discovery provider for S3-manifest-driven scans. Pairs with the Python
 * `S3ManifestDiscovery` backend, which reads each OBJECT_CREATED record and
 * parses the manifest as a JSON array of `{image, ref}`.
 *
 * Owns the manifest bucket (creates one if not supplied) and exposes it via
 * {@link bucket} so the paired {@link S3ManifestTrigger} wires its notification
 * onto the exact bucket this provider reads ─ they can't diverge. A Construct
 * (not a plain class) because it owns an AWS resource.
 */
export class S3ManifestDiscoveryProvider
  extends Construct
  implements IDiscoveryProvider
{
  public readonly dottedPath =
    'byor_scanner.backends.discovery.s3_manifest.S3ManifestDiscovery';
  public readonly environment: Record<string, string>;

  /** The manifest bucket this provider reads (created here unless BYO). */
  public readonly bucket: s3.IBucket;

  constructor(scope: Construct, id: string, props: S3ManifestDiscoveryProviderProps = {}) {
    super(scope, id);

    this.bucket =
      props.bucket ??
      new s3.Bucket(this, 'Bucket', {
        // Manifests are inputs, not audit data ─ safe to drop on destroy.
        // The findings bucket (in InspectorScanner) keeps RETAIN because
        // findings are valuable history.
        removalPolicy: RemovalPolicy.DESTROY,
        autoDeleteObjects: true,
        enforceSSL: true,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
        serverAccessLogsPrefix: 'access-logs/',
        encryption: s3.BucketEncryption.S3_MANAGED,
        // Keep manifests a week so an operator can replay recent triggers;
        // longer retention has no audit value.
        lifecycleRules: [{ expiration: Duration.days(7) }],
      });

    this.environment = { [ENV_MANIFEST_BUCKET]: this.bucket.bucketName };
  }

  public grantRead(role: iam.IRole): void {
    this.bucket.grantRead(role);
  }
}
