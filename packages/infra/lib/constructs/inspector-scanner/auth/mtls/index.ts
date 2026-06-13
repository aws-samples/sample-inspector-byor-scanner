import * as iam from 'aws-cdk-lib/aws-iam';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';
import { IRepositoryAuth } from '../repository-auth';

const DOTTED_PATH = 'byor_scanner.backends.auth.mtls.MtlsAuth';
const ENV_MTLS_SECRET_NAME = 'BYOR_MTLS_SECRET_NAME';

export interface MtlsRepositoryAuthProps {
  /**
   * Secret holding the mTLS client material the scanner Lambda uses to
   * authenticate to the registry. Schema: ``{ca, cert, key}``.
   *
   * Pair with `MtlsRegistryAuth.clientSecret` from the testing stack to
   * reuse the auto-generated test certificates, or supply an existing
   * `ISecret` reference for production.
   */
  readonly secret: secretsmanager.ISecret;
}

/**
 * Repository-side counterpart to {@link MtlsRegistryAuth}.
 *
 * Wires the scanner Lambda to load
 * `byor_scanner.backends.auth.mtls.MtlsAuth` and pass the secret name in
 * via `BYOR_MTLS_SECRET_NAME`. The Python class fetches the secret on
 * every invocation (so rotated certs are picked up automatically) and
 * writes the PEM material to /tmp/certs/ for skopeo's `--cert-dir`.
 */
export class MtlsRepositoryAuth extends Construct implements IRepositoryAuth {
  public readonly dottedPath = DOTTED_PATH;
  public readonly environment: Record<string, string>;

  private readonly secret: secretsmanager.ISecret;

  constructor(scope: Construct, id: string, props: MtlsRepositoryAuthProps) {
    super(scope, id);
    this.secret = props.secret;
    this.environment = { [ENV_MTLS_SECRET_NAME]: props.secret.secretName };
  }

  public grantRead(role: iam.IRole): void {
    this.secret.grantRead(role);
  }
}
