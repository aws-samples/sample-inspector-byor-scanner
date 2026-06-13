import * as iam from 'aws-cdk-lib/aws-iam';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { IDiscoveryPlugin } from '../discovery-trigger';

const ENV_MANIFEST_BUCKET = 'BYOR_MANIFEST_BUCKET';

export interface S3ManifestDiscoveryPluginProps {
  /** Bucket the plugin reads manifests from. Provided by the trigger. */
  readonly bucket: s3.IBucket;
}

/**
 * Default plugin for {@link S3ManifestTrigger}.
 *
 * Pairs with `byor_scanner.backends.discovery.s3_manifest.S3ManifestDiscovery`,
 * which reads each S3 OBJECT_CREATED record from `event['payload']`,
 * GETs the manifest object, and parses it as a JSON array of
 * `{image, ref}` entries. The plugin grants the discovery Lambda
 * `s3:GetObject` on the trigger's bucket.
 */
export class S3ManifestDiscoveryPlugin implements IDiscoveryPlugin {
  public readonly dottedPath =
    'byor_scanner.backends.discovery.s3_manifest.S3ManifestDiscovery';
  public readonly environment: Record<string, string>;

  private readonly bucket: s3.IBucket;

  constructor(props: S3ManifestDiscoveryPluginProps) {
    this.bucket = props.bucket;
    this.environment = { [ENV_MANIFEST_BUCKET]: props.bucket.bucketName };
  }

  public grantRead(role: iam.IRole): void {
    this.bucket.grantRead(role);
  }
}
