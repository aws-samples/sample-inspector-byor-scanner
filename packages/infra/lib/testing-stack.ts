import { CfnOutput, Stack, StackProps } from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';
import {
  DockerRegistry,
  DockerRegistrySeeder,
  MtlsRegistryAuth,
} from '@constructs/docker-registry';

export interface TestingStackProps extends StackProps {
  /**
   * Layer holding ``skopeo`` at ``/opt/bin/skopeo``. Provided by
   * ``BinaryStack`` and shared with ``ScannerStack``.
   */
  readonly binaryLayer: lambda.ILayerVersion;
}

/**
 * Testing infrastructure: a VPC, an mTLS-protected Docker registry running on
 * Fargate, self-signed certs generated at deploy time, and a one-shot
 * Lambda seeder that pushes ``alpine:3.19`` into the registry every deploy.
 *
 * Exposes the artifacts ScannerStack needs (vpc, registryEndpoint,
 * clientSecret) plus CloudShell-friendly outputs for manual verification.
 */
export class TestingStack extends Stack {
  public readonly vpc: ec2.IVpc;
  public readonly registryEndpoint: string;
  public readonly clientSecret: secretsmanager.ISecret;

  constructor(scope: Construct, id: string, props: TestingStackProps) {
    super(scope, id, props);

    this.vpc = new ec2.Vpc(this, 'Vpc', {
      maxAzs: 2,
      natGateways: 1,
    });

    // CloudShell-in-VPC needs an SG it can use; expose one that already has
    // egress to AWS APIs and the registry NLB.
    const cloudShellSg = new ec2.SecurityGroup(this, 'CloudShellSg', {
      vpc: this.vpc,
      description: 'Attach CloudShell sessions to this security group',
      allowAllOutbound: true,
    });

    const auth = new MtlsRegistryAuth(this, 'RegistryAuth', {
      // Wildcard SAN matches whatever NLB DNS CDK provisions in this region.
      // 'localhost' is included so we can test from inside the registry task
      // via `aws ecs execute-command` if needed.
      subjectAlternativeNames: [
        `*.elb.${this.region}.amazonaws.com`,
        'localhost',
      ],
    });

    const registry = new DockerRegistry(this, 'Registry', {
      vpc: this.vpc,
      auth,
    });

    // Allow CloudShell SG to reach the registry on 443.
    registry.service.connections.allowFrom(
      cloudShellSg,
      ec2.Port.tcp(registry.endpointPort),
      'CloudShell verification traffic',
    );

    // ─── Seeder ─────────────────────────────────────────────────────────
    // Lambda that pushes alpine:3.19 (and optionally other public images)
    // into the registry on every deploy ─ the registry's storage is
    // ephemeral, so we re-seed any time the ECS task restarts.
    const seederSg = new ec2.SecurityGroup(this, 'SeederSg', {
      vpc: this.vpc,
      description: 'Egress only - seeder Lambda pushing into the registry',
      allowAllOutbound: true,
    });
    registry.service.connections.allowFrom(
      seederSg,
      ec2.Port.tcp(registry.endpointPort),
      'Seeder Lambda to registry',
    );

    new DockerRegistrySeeder(this, 'RegistrySeeder', {
      binaryLayer: props.binaryLayer,
      vpc: this.vpc,
      securityGroups: [seederSg],
      registryEndpoint: registry.endpoint,
      clientSecret: auth.clientSecret,
    });

    this.registryEndpoint = registry.endpoint;
    this.clientSecret = auth.clientSecret;

    new CfnOutput(this, 'VpcId', { value: this.vpc.vpcId });
    new CfnOutput(this, 'PrivateSubnetIds', {
      value: this.vpc.privateSubnets.map((s) => s.subnetId).join(','),
    });
    new CfnOutput(this, 'CloudShellSecurityGroupId', {
      value: cloudShellSg.securityGroupId,
    });
    new CfnOutput(this, 'RegistryEndpoint', { value: registry.endpoint });
    new CfnOutput(this, 'ClientCertSecretArn', {
      value: auth.clientSecret.secretArn,
    });
  }
}
