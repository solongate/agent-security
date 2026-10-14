# Contributing to SolonGate

Thanks for being here. Read this once before your first pull request please.

## Setting up

```bash
git clone https://github.com/solongate/agent-security.git
cd agent-security
./scripts/shell/install.sh
```

### What lives where

| Package | What it is |
| --- | --- |
| `packages/guard` | The guard. Runs on every tool call and decides. |
| `packages/policy` | The policy engine: JSON rules compiled to Rego, evaluated in process. |
| `packages/shared` | Shapes more than one program has to agree about. No dependencies, on purpose. |
| `packages/sandbox` | The kernel confinement: Landlock, Seatbelt, a Windows deny, and the closed box. |
| `packages/core` | What both surfaces stand on: config, the local store, install state, health. |
| `packages/cli` | The subcommands. Prints and exits. |
| `packages/tui` | The TUI. Full screen, stays open. |
| `packages/app` | The binary: dispatch, the human-only gate, and `--help`. |
| `packages/hooks` | The hook programs, and the scripts that build what ships. |

## Checking your change

```bash
./scripts/shell/sg-unit-check.sh
```

That runs the unit tests for `shared`, `sandbox`, `guard`, `policy` and `core`.
`cli`, `tui` and `app` have none: they just print to the screen and run
commands, so there's nothing to unit-test in them.

Four end-to-end scripts too (Seatbelt needs a Mac):

```bash
./scripts/shell/sg-parity-check.sh      # the Go guard and the Node hook must agree
./scripts/shell/sg-layers-check.sh      # every layer (DLP, rate limit, tamper, etc.) must block what it says it blocks
./scripts/shell/sg-box-check.sh         # the sandbox must actually lock the agent in   (Linux, needs bwrap)
./scripts/shell/sg-seatbelt-check.sh    # same check, for macOS's Seatbelt              (macOS)
```

These scripts don't cover everything, so also try your change by hand against
a real agent, and say in the pull request which client you used and whether
the result matched what you expected.

## Code style

- **Go code**: run `gofmt` and make sure `go vet` is clean. No other linter.
- **Hook files** (`.mjs`): edit `guard.mjs` directly, never the bundled file.
  Rerun `./scripts/shell/install.sh` after so the bundle matches your edit.
- **Comment the "why", not the "what"**: say what a piece of code is
  protecting against, not what it does. If you delete a check, explain in the
  pull request why it's safe to remove.
- **Don't add new dependencies to the guard's decision path** (the code that
  runs before every tool call) without explaining why in the pull request.

## Commit messages

Say what you did and why, in plain English. Keep the first sentence as a short
summary, and add more detail below it if the change needs context.

## Pull requests

Keep one concern per pull request, so a fix can be reverted without taking a
refactor with it. Say exactly what you tested, since there's no test suite to
back that up. CI has to be fully green. And if the change affects what an
existing policy means, say so in the title, since somebody's live setup will
behave differently.

## Security issues

Found a security bypass? Report it privately per [SECURITY.md](SECURITY.md),
not as a public issue or pull request. Once it's fixed, the fix itself ships
as a normal pull request.

## Licensing of contributions

This project is under the **Apache License 2.0**. By submitting a contribution,
you agree it's licensed under the same terms, you keep the copyright, there's
no CLA to sign, and nobody needs to assign anything.

Apache 2.0 also grants a patent licence on your contribution to everyone who
uses the project, and revokes that licence for anyone who sues the project
over a patent claim.