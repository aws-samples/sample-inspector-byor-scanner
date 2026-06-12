import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';
import { IRegistryAuth } from '../registry-auth';
import { GenerateCerts } from './generate-certs';

export interface MtlsRegistryAuthProps {
  /**
   * Server-side {ca, cert, key} secret. If omitted, a self-signed CA + server
   * + client cert are generated at deploy time via the GenerateCerts
   * sub-construct.
   *
   * Must be supplied together with `clientCertSecret` ─ mixing BYO and
   * generated certs would produce a CA mismatch.
   */
  readonly serverCertSecret?: secretsmanager.ISecret;

  /**
   * Client-side {ca, cert, key} secret read by the scanner Lambda. See
   * `serverCertSecret` for the BYO/auto-gen contract.
   */
  readonly clientCertSecret?: secretsmanager.ISecret;

  /**
   * DNS name(s) the server cert is valid for. Only used when auto-generating
   * certs. Defaults to ['registry.local'].
   */
  readonly subjectAlternativeNames?: string[];

  /**
   * Cert validity in days when auto-generating. Defaults to 365.
   */
  readonly validityDays?: number;
}

const SERVER_CERT_DIR = '/certs';

/**
 * mTLS auth for a Docker Registry. Either consumes BYO server/client secrets
 * or auto-generates a self-signed CA + server + client cert via GenerateCerts.
 *
 * Two secrets by design ─ matches IAM least-privilege: the registry task
 * reads only the server bundle, the scanner reads only the client bundle.
 *
 * Distribution config wired by this construct:
 *   REGISTRY_HTTP_TLS_CERTIFICATE  = /certs/server.cert
 *   REGISTRY_HTTP_TLS_KEY          = /certs/server.key
 *   REGISTRY_HTTP_TLS_CLIENTCAS_0  = /certs/ca.crt   (forces mTLS)
 */
export class MtlsRegistryAuth extends Construct implements IRegistryAuth {
  public readonly environment: Record<string, string>;
  public readonly secrets: Record<string, ecs.Secret>;
  public readonly bootstrapCommand: string;
  public readonly clientSecret: secretsmanager.ISecret;

  private readonly serverSecret: secretsmanager.ISecret;

  constructor(scope: Construct, id: string, props: MtlsRegistryAuthProps = {}) {
    super(scope, id);

    const byoServer = props.serverCertSecret;
    const byoClient = props.clientCertSecret;

    if (byoServer && byoClient) {
      this.serverSecret = byoServer;
      this.clientSecret = byoClient;
    } else if (!byoServer && !byoClient) {
      const certs = new GenerateCerts(this, 'Certs', {
        subjectAlternativeNames: props.subjectAlternativeNames,
        validityDays: props.validityDays,
      });
      this.serverSecret = certs.serverSecret;
      this.clientSecret = certs.clientSecret;
    } else {
      throw new Error(
        'MtlsRegistryAuth: serverCertSecret and clientCertSecret must both be ' +
          'provided together, or both omitted to auto-generate. Mixing them ' +
          'would produce mismatched CAs.',
      );
    }

    this.environment = {
      REGISTRY_HTTP_TLS_CERTIFICATE: `${SERVER_CERT_DIR}/server.cert`,
      REGISTRY_HTTP_TLS_KEY: `${SERVER_CERT_DIR}/server.key`,
      REGISTRY_HTTP_TLS_CLIENTCAS_0: `${SERVER_CERT_DIR}/ca.crt`,
    };

    this.secrets = {
      MTLS_CA: ecs.Secret.fromSecretsManager(this.serverSecret, 'ca'),
      MTLS_CERT: ecs.Secret.fromSecretsManager(this.serverSecret, 'cert'),
      MTLS_KEY: ecs.Secret.fromSecretsManager(this.serverSecret, 'key'),
    };

    this.bootstrapCommand = [
      `mkdir -p ${SERVER_CERT_DIR}`,
      `printf "%s" "$MTLS_CA"   > ${SERVER_CERT_DIR}/ca.crt`,
      `printf "%s" "$MTLS_CERT" > ${SERVER_CERT_DIR}/server.cert`,
      `printf "%s" "$MTLS_KEY"  > ${SERVER_CERT_DIR}/server.key`,
      `chmod 600 ${SERVER_CERT_DIR}/server.key`,
    ].join(' && ');
  }

  public grantRead(taskRole: iam.IRole): void {
    this.serverSecret.grantRead(taskRole);
  }
}
