import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';
import { RegistryAttachment } from '../inspector-scanner';

/**
 * A discovery provider: the CDK metadata describing a Python backend that turns
 * an event payload into a list of {image, ref} entries. Attached via
 * {@link InspectorScanner.addDiscoveryProvider}, which stands up a dedicated
 * discovery Lambda for it. Mirrors the {@link IRepositoryAuth} pattern: narrow
 * interface, env-var injection, optional layer, `grantRead` for IAM.
 */
export interface IDiscoveryProvider {
  /** Dotted Python path (`module.path.ClassName`). Set as `BYOR_DISCOVERY_BACKEND`. */
  readonly dottedPath: string;

  /** Env vars the provider needs at runtime (e.g. `BYOR_MANIFEST_BUCKET`). */
  readonly environment: Record<string, string>;

  /**
   * Optional layer carrying the provider's Python source. Built-in providers
   * shipped in the scanner zip leave this undefined.
   */
  readonly layer?: lambda.ILayerVersion;

  /**
   * Registries this provider enqueues images for. Optional ─ a provider that
   * stamps a `registry` field per image references these handles. Every entry
   * MUST have been attached via {@link InspectorScanner.addRegistry} on the
   * SAME scanner the provider is added to; foreign/unknown handles are rejected
   * by {@link InspectorScanner.addDiscoveryProvider}.
   */
  readonly registries?: RegistryAttachment[];

  /** Grant the discovery Lambda anything the provider reads (S3, Secrets, ...). */
  grantRead(role: iam.IRole): void;
}

/**
 * Handle returned by {@link InspectorScanner.addDiscoveryProvider}. Carries the
 * provider `id`, its resolved `source` (the value stamped on SQS messages +
 * the `source` metric dimension), the dedicated discovery Lambda built for it,
 * and its per-provider failure alarm ─ so callers can reach what was created
 * (extra grants, extra alarm actions) and so triggers can reference the
 * Lambda by handle.
 */
export interface DiscoveryAttachment {
  /** The provider id, unique within the scanner. */
  readonly id: string;
  /** Source value stamped on SQS messages + the `source` metric dimension. */
  readonly source: string;
  /** The dedicated discovery Lambda built for this provider. */
  readonly discoveryFunction: lambda.IFunction;
  /** Per-provider failure alarm (fires when this discovery Lambda errors). */
  readonly failureAlarm: cloudwatch.IAlarm;
}

/**
 * Handle returned by {@link InspectorScanner.addTrigger}. Carries the trigger
 * `id` and the {@link DiscoveryAttachment} it fires, so callers can correlate a
 * trigger back to its provider.
 */
export interface TriggerAttachment {
  /** The trigger id, unique within the scanner. */
  readonly id: string;
  /** The discovery provider this trigger fires. */
  readonly discovery: DiscoveryAttachment;
}

/**
 * A trigger: an event source wired onto a discovery provider's Lambda. It
 * references the provider it drives by handle ({@link DiscoveryAttachment})
 * rather than owning a backend ─ purely "which event source fires which
 * provider". Built-ins: {@link S3ManifestTrigger} (S3 PUT) and
 * {@link ScheduledTrigger} (EventBridge schedules). A provider with no trigger
 * is manual-invoke only. Add a trigger = one file implementing this interface.
 */
export interface ITrigger {
  /**
   * The discovery provider this trigger fires, by handle. MUST be a handle
   * returned by {@link InspectorScanner.addDiscoveryProvider} on the SAME
   * scanner the trigger is added to ─ {@link InspectorScanner.addTrigger}
   * rejects a handle from another scanner instance (it would bind the event
   * source to the wrong Lambda).
   */
  readonly discovery: DiscoveryAttachment;

  /**
   * Optional logical source name. Informational only ─ the actual `source`
   * stamped on messages + metrics comes from the provider
   * ({@link DiscoveryAttachment.source}) or the per-event payload. Keep it
   * short, unique within the deploy, and bounded.
   */
  readonly source?: string;

  /**
   * Wire the event source (S3 notification, schedules, ...) onto the provider's
   * discovery Lambda. Called once by the L3 from {@link InspectorScanner.addTrigger}.
   */
  bind(scope: Construct, discoveryFn: lambda.IFunction): void;

  /**
   * Hook for extra invoke wiring against the provider's discovery Lambda role.
   * The built-ins self-wire invoke perms in `bind`, so they no-op this; it
   * exists for custom triggers that need to grant against the role.
   */
  grantInvoke(role: iam.IRole): void;

  /**
   * The `source` values this trigger stamps on its events, when it overrides
   * the provider default. Omit if the trigger doesn't set `source` (the Lambda
   * then falls back to the provider id); implement it so the dashboard graphs
   * the sources actually emitted.
   */
  metricSources?(): string[];
}
