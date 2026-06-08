import { build } from 'esbuild';
import { rmSync } from 'node:fs';

const outdir = 'dist/nodejs/node_modules';

rmSync('dist', { recursive: true, force: true });

await build({
  entryPoints: { index: 'src/scanner-canary.ts' },
  bundle: true,
  platform: 'node',
  target: 'node22',
  format: 'cjs',
  outdir,
  sourcemap: 'inline',
  external: [
    '@aws/synthetics-puppeteer',
    '@aws/synthetics-logger',
    'puppeteer-core',
  ],
  logLevel: 'info',
});
