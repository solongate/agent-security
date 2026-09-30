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
    'src/global-install.ts',
    'src/audit/index.ts',
    // FIVE MORE ENTRIES USED TO BE LISTED HERE — inject, create, pull-push, login
    // and shield — and every one of those files is deleted. tsup skips a missing
    // entry WITHOUT failing, so the build stayed green while the config described a
    // package that no longer existed. Left alone, the next person reads this list to
    // find out what ships.
    //
    // The store the CLI reads and writes. It is bundled into the entries that use it
    // as well, so this is not how the product loads it — it is here because it is a
    // module in its own right with its own contract (test/local-cli.mjs holds the
    // built artifact to it), and a surface worth testing is a surface worth emitting.
    'src/api-client/index.ts',
    // The evaluator the MCP proxy uses, for the same reason: test/proxy-parity.mjs
    // feeds one policy to this and to the guard hook and requires the same verdict
    // from both, which is the check that a policy cannot mean two things on one
    // machine. It can only do that if this is a file it can import.
    'src/policy-engine/engine.ts',
    // Where this machine's audit trail is. Pure module, no React — and it has to be
    // importable on its own because test/log-location.mjs holds it to the resolution
    // the HOOKS use. The two answering differently is how a viewer ends up showing an
    // empty log while entries land correctly somewhere else.
    'src/tui/local-log.ts',
    // The MCP proxy's config: how it reads the policy file, and how it decides what a
    // policy file even IS. test/proxy-parity.mjs holds loadPolicy to both spellings of
    // that file, having found it crashing on the one the CLI writes — so it has to be
    // importable, and importable from the BUILT package rather than the source.
    'src/config.ts',
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
