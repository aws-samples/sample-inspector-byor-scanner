import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';
import { IDiscoveryPlugin, IDiscoveryTrigger } from '../discovery-trigger';
import { StaticDiscoveryPlugin } from './plugin';

export interface ManualTriggerProps {
  /**
   * Logical source name emitted as the `source` dimension on metrics and
   * the `source` field on every SQS message. Keep it short, unique within
   * the deploy, and bounded ─ unbounded values blow up CloudWatch metric
   * cardinality.
   */
  readonly source: string;

  /**
   * Override the discovery plugin. Defaults to {@link StaticDiscoveryPlugin}
   * which reads `event['payload']['images']` from the invoke payload.
   */
  readonly plugin?: IDiscoveryPlugin;
}

/**
 * No-op trigger: the discovery Lambda is invoked directly (canary, manual,
 * external orchestrator) rather than from any AWS event source.
 *
 * The default plugin is {@link StaticDiscoveryPlugin}; payloads look like
 * `{"images": [{"image": "library/nginx", "ref": "1.25"}, ...]}`.
 */
export class ManualTrigger extends Construct implements IDiscoveryTrigger {
  public readonly source: string;
  public readonly plugin: IDiscoveryPlugin;

  constructor(scope: Construct, id: string, props: ManualTriggerProps) {
    super(scope, id);
    this.source = props.source;
    this.plugin = props.plugin ?? new StaticDiscoveryPlugin();
  }

  public bind(_scope: Construct, _discoveryFn: lambda.IFunction): void {
    // No event source to wire ─ caller invokes the Lambda directly.
  }

  public grantRead(_role: iam.IRole): void {
    // No resources owned by this trigger.
  }
}
