import * as iam from 'aws-cdk-lib/aws-iam';
import { IDiscoveryProvider } from '../discovery-trigger';

/**
 * Default plugin for {@link ScheduledTrigger}.
 *
 * Pairs with `byor_scanner.backends.discovery.scheduled_static.ScheduledStaticDiscovery`,
 * which reads `event['payload']['images']` from the schedule's input
 * payload. Customers wanting time-window queries (e.g. "scan everything
 * launched in the last hour") write their own plugin that reads other
 * fields from `payload` ─ the schedule's `payload` is opaque to this
 * construct.
 */
export class ScheduledStaticDiscoveryProvider implements IDiscoveryProvider {
  public readonly dottedPath =
    'byor_scanner.backends.discovery.scheduled_static.ScheduledStaticDiscovery';
  public readonly environment: Record<string, string> = {};

  public grantRead(_role: iam.IRole): void {
    // Nothing to grant ─ the plugin only reads its own event.
  }
}
