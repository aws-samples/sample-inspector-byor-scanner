import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';

/**
 * Authentication used by the scanner Lambda when it pulls images from the
 * customer's container registry.
 *
 * Mirrors the {@link IRegistryAuth} pattern from `docker-registry/auth/`,
 * but on the scanner side: declares the Python class to load
 * (`BYOR_AUTH_PROVIDER`), the env vars / layer it needs, and a grant
 * helper for IAM wiring.
 *
 * Today's only built-in implementation is {@link MtlsRepositoryAuth}.
 * Adding a new auth provider (basic, bearer, authfile, OIDC, ...) is one
 * new file implementing this interface plus a Python class implementing
 * `byor_scanner.protocols.AuthProvider`.
 */
export interface IRepositoryAuth {
  /** Dotted Python path (`module.path.ClassName`). Set as `BYOR_AUTH_PROVIDER`. */
  readonly dottedPath: string;

  /** Env vars the provider needs at runtime (e.g. `BYOR_MTLS_SECRET_NAME`). */
  readonly environment: Record<string, string>;

  /**
   * Optional layer carrying the provider's Python source. Built-in
   * providers shipped in the scanner zip leave this undefined.
   */
  readonly layer?: lambda.ILayerVersion;

  /** Grant the scanner Lambda anything the provider reads (Secrets, KMS, ...). */
  grantRead(role: iam.IRole): void;
}
