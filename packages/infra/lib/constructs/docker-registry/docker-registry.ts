import { CfnOutput } from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';
import { IRegistryAuth } from './auth';

export interface DockerRegistryProps {
  /** VPC the registry runs in. Lambdas / clients must reach the NLB privately. */
  readonly vpc: ec2.IVpc;

  /**
   * Auth construct that configures TLS / authentication for the registry.
   * Today only {@link MtlsRegistryAuth} is supported; other modes can be
   * added without changing this construct.
   */
  readonly auth: IRegistryAuth;

  /**
   * Distribution image. Defaults to `public.ecr.aws/docker/library/registry:2`
   * (the ECR Public mirror — pulled with authenticated rate limits via the
   * task execution role, no Docker Hub credentials required).
   *
   * To use the newer v3 image, pass `'distribution/distribution:3.0.0'` from
   * Docker Hub. Anonymous pulls are rate-limited; busy environments should
   * mirror to ECR or supply Docker Hub credentials.
   */
  readonly registryImage?: string;

  /** Number of Fargate tasks. Defaults to 1. */
  readonly desiredCount?: number;

  /** Task CPU. Defaults to 512. */
  readonly cpu?: number;

  /** Task memory in MiB. Defaults to 1024. */
  readonly memoryLimitMiB?: number;
}

const DEFAULT_REGISTRY_IMAGE = 'public.ecr.aws/docker/library/registry:2';
const REGISTRY_PORT = 443;

const V2_CONFIG_PATH = '/etc/docker/registry/config.yml';
const V3_CONFIG_PATH = '/etc/distribution/config.yml';

/**
 * Pick the right Distribution config-file path for the image.
 *
 * v2 (registry:2)                     → /etc/docker/registry/config.yml
 * v3 (distribution/distribution:3.x)  → /etc/distribution/config.yml
 *
 * Falls back to v2 (the default image) when the tag is ambiguous ─
 * digest pins, `latest`, or unrecognized images.
 */
const resolveConfigPath = (registryImage: string): string => {
  // Digest pin (e.g. registry@sha256:...) ─ can't infer version, use default.
  if (registryImage.includes('@sha256:')) {
    return V2_CONFIG_PATH;
  }
  const tag = registryImage.split(':').pop() ?? '';
  // distribution/distribution:3.x.x or :3 ─ v3
  if (registryImage.includes('distribution/distribution') && tag.startsWith('3')) {
    return V3_CONFIG_PATH;
  }
  return V2_CONFIG_PATH;
};

/**
 * Self-hosted Docker Registry (https://github.com/distribution/distribution)
 * running on ECS Fargate behind an internal Network Load Balancer.
 *
 * Storage is ephemeral ─ images are lost when the task restarts. Suitable for
 * test / sample environments. For a persistent registry, swap the
 * Distribution backend storage env vars to point at S3 / EFS as a follow-up.
 *
 * The NLB is internal-only (private subnets, TCP passthrough). TLS, if any,
 * is terminated by the auth construct inside the registry container ─
 * not by the load balancer.
 */
export class DockerRegistry extends Construct {
  /** NLB DNS name. Use this as the registry hostname for clients (skopeo etc.). */
  public readonly endpoint: string;
  /** Listener port on the NLB. */
  public readonly endpointPort: number = REGISTRY_PORT;
  public readonly cluster: ecs.Cluster;
  public readonly service: ecs.FargateService;
  public readonly loadBalancer: elbv2.NetworkLoadBalancer;

  constructor(scope: Construct, id: string, props: DockerRegistryProps) {
    super(scope, id);

    const { vpc, auth } = props;

    this.cluster = new ecs.Cluster(this, 'Cluster', { vpc });

    const securityGroup = new ec2.SecurityGroup(this, 'SecurityGroup', {
      vpc,
      description: 'docker-registry ingress',
      allowAllOutbound: true,
    });
    securityGroup.addIngressRule(
      ec2.Peer.ipv4(vpc.vpcCidrBlock),
      ec2.Port.tcp(REGISTRY_PORT),
      'Registry traffic from within the VPC',
    );

    const taskDefinition = new ecs.FargateTaskDefinition(this, 'TaskDef', {
      cpu: props.cpu ?? 512,
      memoryLimitMiB: props.memoryLimitMiB ?? 1024,
    });

    auth.grantRead(taskDefinition.taskRole);

    const registryImage = props.registryImage ?? DEFAULT_REGISTRY_IMAGE;
    const configPath = resolveConfigPath(registryImage);

    taskDefinition.addContainer('registry', {
      image: ecs.ContainerImage.fromRegistry(registryImage),
      portMappings: [{ containerPort: REGISTRY_PORT, hostPort: REGISTRY_PORT }],
      logging: ecs.LogDrivers.awsLogs({
        streamPrefix: 'registry',
        logRetention: logs.RetentionDays.ONE_WEEK,
      }),
      environment: {
        REGISTRY_HTTP_ADDR: `0.0.0.0:${REGISTRY_PORT}`,
        ...auth.environment,
      },
      secrets: auth.secrets,
      entryPoint: ['/bin/sh', '-c'],
      command: [`${auth.bootstrapCommand} && exec /entrypoint.sh ${configPath}`],
    });

    this.service = new ecs.FargateService(this, 'Service', {
      cluster: this.cluster,
      taskDefinition,
      desiredCount: props.desiredCount ?? 1,
      assignPublicIp: false,
      securityGroups: [securityGroup],
      circuitBreaker: { rollback: true },
      minHealthyPercent: 0,
    });

    this.loadBalancer = new elbv2.NetworkLoadBalancer(this, 'NLB', {
      vpc,
      internetFacing: false,
      crossZoneEnabled: true,
    });

    const listener = this.loadBalancer.addListener('Listener', {
      port: REGISTRY_PORT,
      protocol: elbv2.Protocol.TCP,
    });

    listener.addTargets('FargateTarget', {
      port: REGISTRY_PORT,
      protocol: elbv2.Protocol.TCP,
      targets: [this.service],
      healthCheck: {
        protocol: elbv2.Protocol.TCP,
        port: String(REGISTRY_PORT),
      },
    });

    this.endpoint = this.loadBalancer.loadBalancerDnsName;

    new CfnOutput(this, 'Endpoint', {
      value: this.endpoint,
      description: 'Internal NLB DNS name for the docker-registry',
    });
  }
}
