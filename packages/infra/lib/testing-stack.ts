import { CfnOutput, Stack, StackProps, Validations } from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct, IConstruct } from 'constructs';
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

    acknowledgeNagFindings(this);
  }
}

/**
 * Granular cdk-nag finding ids. Rules that report per-finding (IAM4/IAM5) are
 * matched by the exact `RuleId[Finding]` string, so they must be acknowledged
 * finding-by-finding — acknowledging `AwsSolutions-IAM5` alone has no effect.
 */
const IAM4_BASIC =
  'AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole]';
const IAM4_VPC =
  'AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole]';
const IAM5_ANY_RESOURCE = 'AwsSolutions-IAM5[Resource::*]';

function acknowledgeNagFindings(stack: Stack): void {
  const SAMPLE =
    'Sample-only test registry harness (non-production; see README disclaimer). ';
  const REASON = {
    vpc7: SAMPLE + 'VPC flow logs omitted to keep the sample lean; adopters enable them in production.',
    elb2: SAMPLE + 'NLB access logs omitted for the sample.',
    ecs4: SAMPLE + 'ECS Container Insights omitted for the sample.',
    ecs2: SAMPLE + 'Task env vars carry only non-secret config (registry endpoint/port); mTLS material is delivered via Secrets Manager, not environment variables.',
    sgCidr: SAMPLE + 'Registry SG ingress is scoped to the VPC CIDR (Fn::GetAtt Vpc.CidrBlock); cdk-nag cannot evaluate the intrinsic and reports it as a validation failure. Not open to 0.0.0.0/0.',
    smg4: SAMPLE + 'Self-signed mTLS cert secrets are re-generated by the cert Custom Resource on each deploy, not via Secrets Manager automatic rotation.',
    runtime: SAMPLE + 'Lambda runtime pinned for skopeo/binary compatibility; intentionally not the newest runtime.',
    execRole: SAMPLE + 'CDK-default Lambda execution role; AWSLambda{Basic,VPCAccess}ExecutionRole grant only CloudWatch Logs + VPC ENI management, scoped by AWS.',
    cdkManaged: SAMPLE + 'CDK-framework-managed custom-resource / log-retention provider; role and policy are generated by aws-cdk-lib, not application code.',
  };
  const A = (path: string, ids: string[], reason: string) => {
    const target = constructAt(stack, path);
    for (const id of ids) acknowledgeFinding(target, id, reason);
  };

  A('TestingStack/Vpc/Resource', ['AwsSolutions-VPC7'], REASON.vpc7);
  A('TestingStack/Registry/NLB/Resource', ['AwsSolutions-ELB2'], REASON.elb2);
  A('TestingStack/Registry/Cluster/Resource', ['AwsSolutions-ECS4'], REASON.ecs4);
  A('TestingStack/Registry/TaskDef/Resource', ['AwsSolutions-ECS2'], REASON.ecs2);
  A('TestingStack/Registry/SecurityGroup/Resource', ['AwsSolutions::AwsSolutions-EC23'], REASON.sgCidr);

  A('TestingStack/RegistryAuth/Certs/ClientSecret/Resource', ['AwsSolutions-SMG4'], REASON.smg4);
  A('TestingStack/RegistryAuth/Certs/ServerSecret/Resource', ['AwsSolutions-SMG4'], REASON.smg4);
  A('TestingStack/RegistryAuth/Certs/Function/Resource', ['AwsSolutions-L1'], REASON.runtime);
  A('TestingStack/RegistryAuth/Certs/Function/ServiceRole/Resource', [IAM4_BASIC], REASON.execRole);
  A('TestingStack/RegistryAuth/Certs/Provider/framework-onEvent/ServiceRole/Resource', [IAM4_BASIC], REASON.cdkManaged);
  A(
    'TestingStack/RegistryAuth/Certs/Provider/framework-onEvent/ServiceRole/DefaultPolicy/Resource',
    ['AwsSolutions-IAM5[Resource::<RegistryAuthCertsFunctionDA23C17E.Arn>:*]'],
    REASON.cdkManaged,
  );

  A('TestingStack/RegistrySeeder/Function/Resource', ['AwsSolutions-L1'], REASON.runtime);
  A('TestingStack/RegistrySeeder/Function/ServiceRole/Resource', [IAM4_BASIC, IAM4_VPC], REASON.execRole);
  A('TestingStack/RegistrySeeder/Provider/framework-onEvent/ServiceRole/Resource', [IAM4_BASIC], REASON.cdkManaged);
  A(
    'TestingStack/RegistrySeeder/Provider/framework-onEvent/ServiceRole/DefaultPolicy/Resource',
    ['AwsSolutions-IAM5[Resource::<RegistrySeederFunctionB9916C90.Arn>:*]'],
    REASON.cdkManaged,
  );

  A('TestingStack/LogRetentionaae0aa3c5b4d4f87b02d85b201efdd8a/ServiceRole/Resource', [IAM4_BASIC], REASON.cdkManaged);
  A('TestingStack/LogRetentionaae0aa3c5b4d4f87b02d85b201efdd8a/ServiceRole/DefaultPolicy/Resource', [IAM5_ANY_RESOURCE], REASON.cdkManaged);
}

/**
 * Record a cdk-nag acknowledgement on `target`.
 *
 * Writes the acknowledgement metadata directly instead of calling
 * `Validations.acknowledge()`, because that method rejects any id containing
 * more than one `::` — which every granular IAM4/IAM5 finding id does, since
 * they embed ARNs (`Policy::arn:<AWS::Partition>:iam::aws:policy/...`). See
 * cdklabs/cdk-nag#2351 and #2359. cdk-nag reads this same metadata key when
 * deciding whether a finding is acknowledged, so the effect is identical for
 * the ids `acknowledge()` does accept.
 */
function acknowledgeFinding(target: IConstruct, id: string, reason: string): void {
  target.node.addMetadata(Validations.ACKNOWLEDGED_RULES_METADATA_KEY, {
    [id]: reason,
  });
}

/**
 * Resolve a construct from its stack-relative path (the form cdk-nag reports),
 * so acknowledgements can be attached to CDK-managed resources we hold no
 * reference to.
 */
function constructAt(stack: Stack, path: string): IConstruct {
  return path
    .split('/')
    .slice(1)
    .reduce<IConstruct>((node, id) => node.node.findChild(id), stack);
}
