# @solongate/hooks

The hook programs, and the two scripts that build what ships.

This package used to be the product: a CLI, a TUI, an MCP proxy and the hooks,
all in TypeScript, published to npm. The CLI and the TUI are in Go now
(`packages/app`), distribution is over git, and the TypeScript that is left
is the part nothing replaced.

For what SolonGate is and how to install it, read the
[root README](../../README.md).

## What is in here

```
hooks/guard.mjs           the guard: decides every tool call
hooks/guard.bundled.mjs   the above with its imports inlined, which is what installs
hooks/policy-eval.mjs     the decision itself, shared
hooks/dlp.mjs             the pattern list, shared
hooks/audit.mjs           PostToolUse: records the calls that ran
hooks/tokens.mjs          Stop: what the turn cost
hooks/shield.mjs          masks the prompt, through a shell shim
hooks/stop.mjs            end of turn
hooks/opencode-plugin.mjs the OpenCode adapter
```

The hooks import node builtins and each other. Nothing else.

## Building

```sh
pnpm build        # bundles guard.mjs into guard.bundled.mjs
pnpm build:go     # cross-compiles the Go guard and CLI, one directory per platform
```

`pnpm build:go` with no argument builds all six targets, which is what a release
needs. Pass a tag (`linux-x64`) for just this machine.

The Go installer reads `hooks/` from this directory and copies it onto the
machine, so `pnpm build` has to have run before `solongate repair` means
anything.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
