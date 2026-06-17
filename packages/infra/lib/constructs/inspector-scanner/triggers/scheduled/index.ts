import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as scheduler from 'aws-cdk-lib/aws-scheduler';
import { Construct } from 'constructs';
import { DiscoveryAttachment, ITrigger } from '../discovery-trigger';

/**
 * One EventBridge schedule entry. Each entry becomes its own
 * `CfnSchedule` whose `input` JSON is the {source, payload} envelope the
 * discovery handler expects.
 *
 * `payload` is opaque ─ the construct passes it through verbatim. The
 * provider owns parsing it. Examples:
 *
 *   - `{ window: 'PT1H' }` for a "scan everything launched in the last
 *     hour" plugin.
 *   - `{ images: [{...}] }` for the default {@link ScheduledStaticDiscoveryProvider}.
 *   - `{ tags: ['prod'], window: 'PT12H' }` for a custom plugin that
 *     filters by both tag and time window.
 */
export interface ScheduledTriggerEntry {
  /**
   * Logical id used as the schedule's CDK construct id and as the
   * per-event `source` value on the SQS message + metric dimension.
   * Must be unique within this trigger's `schedules` array.
   */
  readonly id: string;

  /**
   * EventBridge Scheduler expression (cron / rate). See
   * https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
   * for the full syntax.
   */
  readonly schedule: string;

  /**
   * Opaque JSON payload delivered to the discovery Lambda alongside the
   * schedule's `id` as `source`. Plugin-specific.
   */
  readonly payload?: Record<string, unknown>;

  /** Schedule retry attempts on Lambda failure. Defaults to 2. */
  readonly retryAttempts?: number;
}

export interface ScheduledTriggerProps {
  /**
   * The discovery provider these schedules fire, by handle (returned by
   * {@link InspectorScanner.addDiscoveryProvider}). Each schedule invokes this
   * provider's Lambda with its own `{ source, payload }` envelope.
   */
  readonly discovery: DiscoveryAttachment;

  /** One or more schedule entries. Each becomes a `CfnSchedule`. */
  readonly schedules: ScheduledTriggerEntry[];

  /**
   * Optional trigger-level source name (informational only). Each schedule's
   * own ``id`` is what lands on the SQS message + metric dimension at fire
   * time. Keep it short, unique within the deploy, and bounded.
   */
  readonly source?: string;
}

/**
 * Cadence-driven trigger: N EventBridge schedules, each with its own
 * opaque payload. Replaces the old `mode: 'hourly' | 'full'` enum ─
 * customers now author cadence + payload together so the plugin can
 * decide what to query without a hardcoded enum value.
 *
 * Example: hourly "last 1h" + 12-hourly "last 12h":
 *
 *     new ScheduledTrigger(this, 'Cron', {
 *       schedules: [
 *         { id: 'Hourly',       schedule: 'cron(0 1-11,13-23 * * ? *)',
 *           payload: { window: 'PT1H' } },
 *         { id: 'TwelveHourly', schedule: 'cron(0 0,12 * * ? *)',
 *           payload: { window: 'PT12H' } },
 *       ],
 *     });
 *
 * The paired plugin reads `event['payload']['window']` and decides what
 * to query. Adding a new cadence = one new entry; no Python change.
 */
export class ScheduledTrigger extends Construct implements ITrigger {
  public readonly discovery: DiscoveryAttachment;
  public readonly source?: string;

  private readonly schedules: ScheduledTriggerEntry[];

  constructor(scope: Construct, id: string, props: ScheduledTriggerProps) {
    super(scope, id);
    if (props.schedules.length === 0) {
      throw new Error(
        `ScheduledTrigger '${id}' requires at least one entry in 'schedules'`,
      );
    }
    const ids = new Set<string>();
    for (const entry of props.schedules) {
      if (ids.has(entry.id)) {
        throw new Error(
          `ScheduledTrigger '${id}' has duplicate schedule id '${entry.id}'`,
        );
      }
      ids.add(entry.id);
    }
    this.discovery = props.discovery;
    this.source = props.source;
    this.schedules = props.schedules;
  }

  public bind(scope: Construct, discoveryFn: lambda.IFunction): void {
    const role = new iam.Role(scope, `${this.node.id}SchedulerRole`, {
      assumedBy: new iam.ServicePrincipal('scheduler.amazonaws.com'),
    });
    discoveryFn.grantInvoke(role);

    for (const entry of this.schedules) {
      new scheduler.CfnSchedule(scope, `${this.node.id}${entry.id}Schedule`, {
        scheduleExpression: entry.schedule,
        flexibleTimeWindow: { mode: 'OFF' },
        target: {
          arn: discoveryFn.functionArn,
          roleArn: role.roleArn,
          input: JSON.stringify({
            source: entry.id,
            payload: entry.payload ?? {},
          }),
          retryPolicy: { maximumRetryAttempts: entry.retryAttempts ?? 2 },
        },
      });
    }
  }

  public grantInvoke(_role: iam.IRole): void {
    // The EventBridge Scheduler invoke permission is granted in `bind` onto
    // this trigger's own scheduler role ─ nothing extra to grant against the
    // discovery Lambda role here.
  }
}
