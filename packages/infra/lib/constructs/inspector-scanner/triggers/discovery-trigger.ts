import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';

/**
 * A discovery plugin: the Python class that turns a trigger's event payload
 * into a list of {image, ref} entries.
 *
 * Plugins are paired with a single trigger ─ each trigger ships its default
 * plugin and accepts an override via its `plugin` prop. The trigger's
 * `bind` is responsible for setting `BYOR_DISCOVERY_BACKEND` on the
 * discovery Lambda to this plugin's dotted path.
 *
 * Mirrors the {@link IRegistryAuth} pattern from `docker-registry/auth/`:
 * narrow interface, env-var injection, optional layer for plugin-bearing
 * payloads, `grantRead` for IAM.
 */
export interface IDiscoveryPlugin {
  /** Dotted Python path (`module.path.ClassName`). Set as `BYOR_DISCOVERY_BACKEND`. */
  readonly dottedPath: string;

  /** Env vars the plugin needs at runtime (e.g. `BYOR_MANIFEST_BUCKET`). */
  readonly environment: Record<string, string>;

  /**
   * Optional layer carrying the plugin's Python source. Built-in plugins
   * shipped in the scanner zip leave this undefined.
   */
  readonly layer?: lambda.ILayerVersion;

  /** Grant the discovery Lambda anything the plugin reads (S3, Secrets, ...). */
  grantRead(role: iam.IRole): void;
}

/**
 * A discovery trigger: the CDK seam that wires an event source onto the
 * discovery Lambda and pairs it with a {@link IDiscoveryPlugin}.
 *
 * Today's triggers:
 *  - {@link S3ManifestTrigger}  ─ default; an S3 bucket fires the Lambda on PUT
 *  - {@link ScheduledTrigger}    ─ N EventBridge schedules with opaque payloads
 *  - {@link ManualTrigger}       ─ no auto-trigger; invoke by hand
 *
 * Adding a new trigger = one file implementing this interface. The L3
 * (`InspectorScanner`) doesn't need to change.
 */
export interface IDiscoveryTrigger {
  /**
   * Logical id emitted as the `source` value on every SQS message and the
   * `source` dimension on the discovery + scanner metrics.
   *
   * Keep it short, unique within the deploy, and bounded ─ unbounded
   * values blow up CloudWatch metric cardinality.
   */
  readonly source: string;

  /** Plugin paired with this trigger (each trigger ships a sensible default). */
  readonly plugin: IDiscoveryPlugin;

  /**
   * Wire event source (S3 notification, schedules, ...) onto the discovery
   * Lambda. Called once by the L3 during construction.
   */
  bind(scope: Construct, discoveryFn: lambda.IFunction): void;

  /** Grant the discovery Lambda anything the trigger reads. */
  grantRead(role: iam.IRole): void;
}
