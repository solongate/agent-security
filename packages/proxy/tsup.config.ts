import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    // The `solongate` bin. Hands human subcommands to the Go binary and falls
    // back to index.ts, which is why it is its own entry rather than a prelude
    // inside it: ESM hoists imports, so a prelude would pay for index.ts's whole
    // module graph before it could decide not to use it.
    'src/cli-launch.ts',
    'src/index.ts',
    'src/lib.ts',
    'src/inject.ts',
    'src/create.ts',
    'src/pull-push.ts',
    'src/login.ts',
    'src/shield.ts',
    'src/global-install.ts',
    'src/audit/index.ts',
    // Management CLI: scriptable commands + interactive Ink TUI. Both are only
    // reached via dynamic import() from src/index.ts, so the proxy runtime never
    // pulls in the API-client / React / Ink code.
    'src/commands/index.ts',
    'src/tui/index.tsx',
  ],
  format: ['esm'],
  target: 'node18',
  platform: 'node',
  // Automatic JSX runtime (react/jsx-runtime) so .tsx needs no React import.
  esbuildOptions(options) {
    options.jsx = 'automatic';
  },
  // JS bundling only; .d.ts is emitted by a separate lenient `tsc` step in the
  // build script (tsup's rollup-dts is too strict for the pre-existing errors).
  dts: false,
  clean: true,
  splitting: false,
  // Keep these as external — users install them via package.json dependencies.
  // react/ink stay external so they load only when the TUI entry runs.
  external: [
    '@modelcontextprotocol/sdk',
    'zod',
    'react',
    'ink',
    'ink-text-input',
    'ink-spinner',
  ],
});
