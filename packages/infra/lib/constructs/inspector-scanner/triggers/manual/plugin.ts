import * as iam from 'aws-cdk-lib/aws-iam';
import { IDiscoveryPlugin } from '../discovery-trigger';

/**
 * Default plugin for {@link ManualTrigger}.
 *
 * Pairs with `byor_scanner.backends.discovery.static.StaticDiscovery`,
 * which reads `event['payload']['images']` and returns it verbatim.
 * No env vars, no IAM grants, no plugin layer ─ ships in the scanner zip.
 */
export class StaticDiscoveryPlugin implements IDiscoveryPlugin {
  public readonly dottedPath = 'byor_scanner.backends.discovery.static.StaticDiscovery';
  public readonly environment: Record<string, string> = {};

  public grantRead(_role: iam.IRole): void {
    // Nothing to grant ─ the plugin only reads its own event.
  }
}
