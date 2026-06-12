import { CustomResource, Duration, RemovalPolicy } from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Provider } from 'aws-cdk-lib/custom-resources';
import { Construct } from 'constructs';
import * as path from 'path';

export interface GenerateCertsProps {
  /**
   * DNS name(s) the server cert is valid for (subjectAltName).
   * Must include whatever name(s) the client uses to reach the server.
   * Defaults to ['registry.local'].
   */
  readonly subjectAlternativeNames?: string[];

  /**
   * Common name applied to the CA, server, and client certs.
   * Defaults to 'docker-registry'.
   */
  readonly commonName?: string;

  /**
   * Cert validity in days. Defaults to 365.
   * Changing this on an existing stack will trigger regeneration.
   */
  readonly validityDays?: number;
}

/**
 * Generates a self-signed CA + server cert + client cert at deploy time and
 * writes them into two Secrets Manager secrets:
 *
 *  - serverSecret  → {ca, cert, key}  (the server's TLS material)
 *  - clientSecret  → {ca, cert, key}  (the client's TLS material)
 *
 * Both secrets share the same CA. The CA private key is never persisted ─
 * once both leaf certs are signed it is discarded with the Lambda invocation.
 *
 * Use for sample / test environments. For production, bring your own CA.
 */
export class GenerateCerts extends Construct {
  public readonly serverSecret: secretsmanager.Secret;
  public readonly clientSecret: secretsmanager.Secret;

  constructor(scope: Construct, id: string, props: GenerateCertsProps = {}) {
    super(scope, id);

    this.serverSecret = new secretsmanager.Secret(this, 'ServerSecret', {
      description: 'Self-signed server cert + CA for docker-registry mTLS',
      removalPolicy: RemovalPolicy.DESTROY,
    });
    this.clientSecret = new secretsmanager.Secret(this, 'ClientSecret', {
      description: 'Self-signed client cert + CA for docker-registry mTLS',
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const fn = new NodejsFunction(this, 'Function', {
      entry: path.join(__dirname, 'handler', 'index.ts'),
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: Duration.minutes(2),
      memorySize: 256,
      logRetention: logs.RetentionDays.ONE_WEEK,
    });

    this.serverSecret.grantWrite(fn);
    this.clientSecret.grantWrite(fn);

    const provider = new Provider(this, 'Provider', {
      onEventHandler: fn,
      logRetention: logs.RetentionDays.ONE_WEEK,
    });

    new CustomResource(this, 'Resource', {
      serviceToken: provider.serviceToken,
      properties: {
        ServerSecretArn: this.serverSecret.secretArn,
        ClientSecretArn: this.clientSecret.secretArn,
        SubjectAlternativeNames: props.subjectAlternativeNames ?? ['registry.local'],
        CommonName: props.commonName ?? 'docker-registry',
        ValidityDays: String(props.validityDays ?? 365),
        // Bumped to force a re-run when the cert library swaps. Drop on
        // next clean PR after this lands and we're confident the handler
        // is stable.
        HandlerRevision: 'peculiar-x509-v1',
      },
    });
  }
}
