/**
 * Shared identifiers for the observability layer.
 *
 * These mirror the values the scanner emits at runtime and MUST stay in sync
 * with `packages/scanner/byor_scanner/constants.py`:
 *   - METRIC_NAMESPACE → METRIC_NAMESPACE
 *   - SCANNER_SERVICE  → SERVICE_SCANNER   (Powertools service / OTEL service name)
 *   - DISCOVERY_SERVICE → SERVICE_DISCOVERY
 *
 * (TypeScript can't import the Python constants, so this is the CDK-side
 * single source of truth.)
 */
export const METRIC_NAMESPACE = 'BYORScan';
export const SCANNER_SERVICE = 'byor-scanner';
export const DISCOVERY_SERVICE = 'byor-discovery';
