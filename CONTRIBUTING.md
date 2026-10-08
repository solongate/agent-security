# Contributing to SolonGate

Thanks for being here. This is a security control: when it works, nothing
happens, and a change that quietly weakens it looks exactly like a change that
does nothing. Most of what follows exists to keep that from happening.

Read this once before your first pull request. The code comments carry the rest:
they say what a piece is defending against and what broke before it was written
that way.

## Setting up

```bash
git clone https://github.com/solongate/agent-security.git
cd agent-security
pnpm install
pnpm build
```

`pnpm install` warns four times that it could not create a bin: `solongate`,
`solongate-proxy`, `proxy`, `solongate-audit`. It is linking commands at files
that the build has not produced yet, and the next command produces them. Nothing
is wrong and nothing needs rerunning.

If you want the tool actually installed on your machine while you work on it,
`./install.sh` does that from the checkout. You do not need it installed to run
the tests.

### What lives where

| Package | What it is |
| --- | --- |
| `packages/guard-go` | The guard. Runs on every tool call and decides. |
| `packages/proxy` | The hook programs, and the scripts that build what ships. |
| `packages/proxy-go` | The CLI and the TUI, in Go. This is what ships as the binary. |
| `packages/sgpolicy` | The policy engine: JSON rules compiled to Rego, evaluated in process. |
| `packages/sgshared` | Shapes more than one program has to agree about. |

## Checking your change

```bash
pnpm install
pnpm build          # bundles the hooks

for m in guard-go proxy-go sgpolicy sgshared; do
  (cd "packages/$m" && gofmt -l . && go vet ./...)
done
```

That is all of it. There is no test suite in this repository. The conformance
suite that used to judge both guards against each other was removed, and so was
every Go test, and nothing replaced them. The commands above tell you the code
compiles. They do not tell you it still decides the way it did yesterday.

Which puts the burden on the pull request. Run your change against a real agent
and write down what you did: which client, which tool calls, what you expected,
what happened. That description is the only evidence a reviewer has.

Both directions, every time. A rule that blocks everything passes every "was it
blocked?" check anybody can think of, so the call that must go through is the
half that finds walls.

Some of this was never scriptable anyway. The CLI needs a terminal on both
stdin and stdout, and enforcement only happens on a real tool call. If your
change touches the CLI surface or a client adapter, exercise it by hand and say
on which clients.

## Code style

- **Go**: `gofmt`, and `go vet` clean. No lint config beyond that.
- **The hooks** are plain `.mjs`, node builtins only, no build step beyond the
  bundler and nothing typechecking them. Edit `guard.mjs`, never the bundled
  output, and run `pnpm build` so the two match. Formatting follows the file.
- **Comments carry the reasoning.** This repository comments heavily and
  deliberately: not what the code does, but what it is defending against, what
  was tried before, and what broke. If you remove a guard clause, the comment
  explaining why it was there is part of what you are removing, so make the pull
  request say what replaced it.
- **No new dependency on the decision path** without a reason in the pull
  request. The guard runs before every tool call, and `packages/sgshared` has no
  external dependencies on purpose.

## Commit messages

Commits here describe the behaviour, usually the wrong behaviour being fixed, as
a plain sentence. A few from the log:

```
A denied call showed you its arguments and never said why
Twelve rules went in and eight came out, and it said every one succeeded
The rate limit had no key that stopped editing without writing
```

That style is not mandatory, but the property behind it is: the subject line
should tell a reader what changed in the product, not which function was edited.
No prefixes are required.

## Pull requests

- One concern per pull request. A refactor and a fix in the same diff means the
  fix cannot be reverted on its own.
- Say what you ran, in detail. With no suite behind the change, a vague "tested
  locally" is not reviewable. Name the client, the calls, and the outcome.
- CI runs gofmt and vet over the four Go modules, the hook bundle, the release
  build, and a secret scan. All of it has to be green, and all of it together
  still says nothing about whether the guard decides correctly.
- If your change alters what a policy means, say so in the pull request title.
  Somebody's live policy will behave differently, and that is a release note.

## Security issues

Do not open a public issue or pull request for a guard bypass, a tamper
protection hole, or a DLP pattern that can be walked past. Follow
[SECURITY.md](SECURITY.md), which uses GitHub private advisories.

A fix for a reported vulnerability is still a normal pull request once the
advisory is resolved, and we will credit you in the release notes unless you ask
us not to.

## Licensing of contributions

This project is licensed under the **Apache License 2.0**, and that licence says
what happens to your contribution without anybody signing anything. Section 5:
unless you state otherwise in writing, anything you deliberately submit for
inclusion is under the same terms as the licence itself.

So there is no CLA and no copyright assignment. You keep the copyright in what
you wrote.

Two things Apache 2.0 carries that MIT did not, both worth knowing before you
send a patch:

- **A patent grant.** Contributing code grants everyone who uses this project a
  licence to any of your patents that the contribution necessarily infringes. If
  you are contributing on behalf of an employer who holds patents, that is their
  decision to be aware of, not a formality.
- **A patent retaliation clause.** Anybody who sues this project claiming it
  infringes their patent loses their own licence to it.

A `Signed-off-by` line is welcome and not required.

## Behaviour

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies everywhere in this project.
