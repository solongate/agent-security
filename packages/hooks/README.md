# @solongate/hooks

The guard and CLI binaries, and the script that builds what ships.

This package used to be the product: a CLI, a TUI, an MCP proxy and the hooks,
all in TypeScript, published to npm. All of that is Go now (`packages/guard`,
`packages/app`), distribution is over git, and what is left here is the one
piece that has to stay JavaScript: the OpenCode plugin shim.

For what SolonGate is and how to install it, read the
[root README](../../README.md).

## What is in here

```
opencode-plugin.mjs   the OpenCode adapter: spawns the Go guard binary
scripts/build-platforms.sh   cross-compiles the Go binaries, one directory per platform
platforms/            build output, laid out per platform tag
VERSION                the version stamped into the binaries
```

OpenCode loads plugins as native JS modules; there is no way to register a
bare Go binary as one. `opencode-plugin.mjs` is a thin protocol translator:
every event it receives spawns the Go guard binary's matching subcommand and
relays its JSON verdict back to OpenCode. No policy, DLP, or tamper logic
lives in this file.

## Building

```sh
packages/hooks/scripts/build-platforms.sh            # all six release targets
packages/hooks/scripts/build-platforms.sh linux-x64   # just this machine
```

The Go installer reads `platforms/<tag>/` and copies the binaries it finds
there onto the machine, so this script has to have run before `solongate
repair` means anything.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).