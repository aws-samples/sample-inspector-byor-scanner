import { CustomResource, Duration } from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Provider } from 'aws-cdk-lib/custom-resources';
import { Construct } from 'constructs';

export interface DockerRegistrySeederProps {
  /**
   * Path to the scanner Lambda's deployment directory (the same one
   * ScannerStack consumes). The seeder runs the
   * ``byor_scanner.seeder.handler`` entry point from this zip ─ shares
   * the MtlsAuth module with the scanner so cert handling stays in one
   * place.
   *
   * Typical value: ``packages/scanner/dist/lambda``.
   */
  readonly scannerLambdaCodePath: string;

  /**
   * Layer holding the ``skopeo`` binary at ``/opt/bin/skopeo``. Pass the
   * same BinaryLayer the ScannerStack uses so the seeder, scanner, and
   * discovery Lambdas all run an identical binary.
   */
  readonly binaryLayer: lambda.ILayerVersion;

  /** VPC the seeder runs in. Must reach the registry NLB. */
  readonly vpc: ec2.IVpc;
  /**
   * Security group for the seeder. Must be allowed to reach the registry
   * NLB on 443. Easiest: reuse the scanner Lambda's SG.
   */
  readonly securityGroups?: ec2.ISecurityGroup[];

  /** Registry hostname (NLB DNS) to push images to. */
  readonly registryEndpoint: string;
  /** Client mTLS secret ({ca, cert, key}). */
  readonly clientSecret: secretsmanager.ISecret;
  /**
   * Public image URIs to copy into the registry. Defaults to
   * ``alpine:3.19`` from ECR Public.
   */
  readonly seedImages?: string[];
}

const DEFAULT_SEED_IMAGES = ['public.ecr.aws/docker/library/alpine:3.19'];

/**
 * Pushes test images into the docker-registry on stack deploy.
 *
 * The registry's storage is ephemeral ─ images are lost when the ECS task
 * restarts (deploys, cert rotations). This construct re-seeds via a
 * lightweight Lambda invoked from a CDK Custom Resource on every deploy.
 *
 * The Lambda reuses the scanner Lambda's zip (same skopeo binary, same
 * MtlsAuth code path) ─ just a different handler entry point.
 */
export class DockerRegistrySeeder extends Construct {
  constructor(scope: Construct, id: string, props: DockerRegistrySeederProps) {
    super(scope, id);

    const seedImages = props.seedImages ?? DEFAULT_SEED_IMAGES;

    const seederFn = new lambda.Function(this, 'Function', {
      runtime: lambda.Runtime.PYTHON_3_11,
      architecture: lambda.Architecture.X86_64,
      handler: 'byor_scanner.seeder.handler',
      code: lambda.Code.fromAsset(props.scannerLambdaCodePath),
      timeout: Duration.minutes(10),
      memorySize: 1024,
      vpc: props.vpc,
      securityGroups: props.securityGroups,
      layers: [props.binaryLayer],
      logRetention: logs.RetentionDays.ONE_WEEK,
      environment: {
        BYOR_MTLS_SECRET_NAME: props.clientSecret.secretName,
        // Skopeo is on the BinaryLayer at /opt/bin/skopeo; the default
        // in byor_scanner.constants matches, so no override needed.
      },
    });

    props.clientSecret.grantRead(seederFn);

    const provider = new Provider(this, 'Provider', {
      onEventHandler: seederFn,
      logRetention: logs.RetentionDays.ONE_WEEK,
    });

    new CustomResource(this, 'Resource', {
      serviceToken: provider.serviceToken,
      properties: {
        RegistryEndpoint: props.registryEndpoint,
        Images: seedImages,
      },
    });
  }
}
