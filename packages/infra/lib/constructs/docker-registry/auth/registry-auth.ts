import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';

/**
 * Wiring contract between a registry-auth construct and the DockerRegistry.
 *
 * Each auth construct (MtlsRegistryAuth, HtpasswdRegistryAuth, ...) owns its
 * own secrets and tells the registry container how to materialize them at
 * runtime via env vars + a bootstrap shell snippet that runs before the
 * Distribution entrypoint.
 */
export interface IRegistryAuth {
  /**
   * Distribution config + TLS env vars the registry container needs at runtime
   * (e.g. REGISTRY_HTTP_TLS_CERTIFICATE, REGISTRY_AUTH=htpasswd).
   */
  readonly environment: Record<string, string>;

  /**
   * Secrets injected into the registry container as ECS secrets. Values are
   * read at task-start and exposed as env vars; the bootstrap script writes
   * them to disk where Distribution expects them.
   */
  readonly secrets: Record<string, ecs.Secret>;

  /**
   * Shell snippet inserted before `exec /entrypoint.sh` in the registry
   * container's command. Materializes secrets to /certs, /auth, etc.
   * MUST be idempotent and `set -e`-safe.
   */
  readonly bootstrapCommand: string;

  /**
   * Secret the scanner Lambda reads to authenticate to this registry.
   * Shape depends on the auth mode:
   *  - mTLS:     {ca, cert, key}
   *  - htpasswd: {username, password}
   *  - token:    {token} (placeholder)
   */
  readonly clientSecret: secretsmanager.ISecret;

  /**
   * Grant the registry's task role read access to whatever secrets this auth
   * construct created. Called by DockerRegistry during construction.
   */
  grantRead(taskRole: iam.IRole): void;
}
