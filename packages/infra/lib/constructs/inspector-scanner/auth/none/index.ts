import * as iam from 'aws-cdk-lib/aws-iam';
import { IRepositoryAuth } from '../repository-auth';

const DOTTED_PATH = 'byor_scanner.backends.auth.none.NoAuth';

/**
 * Repository auth for public registries that need no client authentication
 * (e.g. `public.ecr.aws`, public Docker Hub images).
 *
 * Wires the scanner Lambda to load `byor_scanner.backends.auth.none.NoAuth`,
 * which fetches nothing and emits only `--tls-verify=true`. A plain class (not
 * a Construct) ─ it owns no resources and grants nothing.
 */
export class NoAuth implements IRepositoryAuth {
  public readonly dottedPath = DOTTED_PATH;
  public readonly environment: Record<string, string> = {};

  public grantRead(_role: iam.IRole): void {
    // Public registry ─ nothing to grant.
  }
}
