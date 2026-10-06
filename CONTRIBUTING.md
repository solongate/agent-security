# Contributing to SolonGate

Thanks for being here. This is a security control: when it works, nothing
happens, and a change that quietly weakens it looks exactly like a change that
does nothing. Most of what follows exists to keep that from happening.

Read this once before your first pull request. After that,
[ENGINEERING.md](ENGINEERING.md) is the document you will want open.

## The short version

1. Open an issue before writing anything non trivial, so nobody duplicates work.
2. Go 1.25 and Node 20+. `pnpm install`, then `pnpm build`.
3. Run the conformance suite against **both** implementations. A change is
   correct exactly when it passes against each.
4. Behaviour changes need a case in the conformance suite that fails before your
   change and passes after it.
5. `gofmt`, `go vet`, `go test -count=1 ./...` in every Go module you touched.

## Setting up

```bash
git clone https://github.com/codeyevsky/solongate-oss.git
cd solongate-oss
pnpm install
pnpm build
```

`pnpm install` warns four times that it could not create a bin: `solongate`,
`solongate-proxy`, `proxy`, `solongate-audit`. It is linking commands at files
that the build has not produced yet, and the next command produces them. Nothing
is wrong and nothing needs rerunning.

If you want the tool actually installed on your machine while you work on it,
`./install.sh` does that from the checkout, and
[docs/install.md](docs/install.md) explains what it writes. You do not need it
installed to run the tests.

### What lives where

| Package | What it is |
| --- | --- |
| `packages/guard-go` | The guard. Runs on every tool call and decides. |
| `packages/proxy` | The CLI, the TUI and the hooks in TypeScript, published as `@solongate/proxy`. |
| `packages/proxy-go` | The same CLI in Go, which is what ships as the binary. |
| `packages/sgpolicy` | The policy engine: JSON rules compiled to Rego, evaluated in process. |
| `packages/sgshared` | Shapes more than one program has to agree about. |

[docs/architecture.md](docs/architecture.md) is the map, including which process
runs when.

## The rule that shapes everything

**There are two implementations of the guard, and they have to be
indistinguishable.** A machine with the Go binary is decided by Go. A machine
without it is decided by the bundled Node hook. Nothing else chooses, so a
behaviour that exists in one of them and not the other is a policy that applies
to some of your machines.

So: a change to the decision path lands in both, in the same pull request, or it
does not land. If you can only do one half, say so in the pull request and open
an issue for the other, and expect the review to focus on whether the gap is
safe in the meantime.

## Testing

### The conformance suite is the contract

`packages/proxy/test` runs the guard as a subprocess, feeds it a client payload,
and asserts on the exit code, the files touched and what a stub server does NOT
receive. Nothing in it imports any implementation's internals, which is why the
same suite can judge both.

```bash
cd packages/proxy
pnpm build                    # the suite imports dist/, and drives the bundled hook

node test/run-all.mjs                                   # the Node hook
SG_HOOK=$PWD/../guard-go/solongate-guard \
  node test/run-all.mjs                                 # and the Go binary
```

Two things about `SG_HOOK`:

- **It has to be absolute.** The suite spawns the guard with `cwd` set to a
  sandbox, so a relative path resolves against that and fails with ENOENT on
  every case, which reads as a total failure rather than a bad invocation.
- **Give it explicitly.** Otherwise the suite judges whatever is installed in
  your home directory, which passes on a machine that has SolonGate installed
  and fails on one that does not, including every CI runner.

Build the Go guard first if you have not:

```bash
cd packages/guard-go && go build -o solongate-guard .
```

### Use the real build, not `tsc`

`pnpm build` rather than `npx tsc`. `tsc` emits one JavaScript file per source
file, which resolves every import the suite has and is **not what ships**: the
package ships the bundler's output. A module the suite imports has to be an entry
point to survive the real build. Two were not, and only a machine that had run
`pnpm build` noticed.

### The Go side

```bash
for m in guard-go proxy-go sgpolicy sgshared; do
  (cd packages/$m && gofmt -l . && go vet ./... && go test -count=1 ./...)
done
```

`-count=1` is not a habit, it is a fix. Go serves a cached PASS for a test whose
subject was deleted elsewhere in the repo, and one sat green that way for a
while. CI is the place that should never read a cache, and so is your last run
before pushing.

### What you cannot automate

Some of this product can only be tested by a person, and that is by design:

- **The CLI** refuses to run without a terminal on both stdin and stdout, so no
  script and no agent can drive it.
- **Enforcement** only happens on a real tool call, so triggering it means asking
  an agent to do something.

[TESTING.md](TESTING.md) is the run sheet for both, including the matrix of every
constraint type against every client. If your change touches the CLI surface or
a client adapter, run the relevant rows and say in the pull request which ones
you ran.

## Adding a test

Every case in the conformance suite exists because the behaviour it pins was once
wrong, and the comment on it says which. Keep that property:

- Name the behaviour, not the function. `a denial is answered without waiting for
  anything` beats `test deny path`.
- Write the comment that explains **why the case is there**, in terms of what
  went wrong or could go wrong. A reader six months from now has to be able to
  tell whether your assertion is still the thing worth asserting.
- A pass and a failure must look different. "Nothing was blocked" is never
  evidence on its own, so assert on the exit code, the recorded entry, or the
  file that should not have changed.

## Code style

- **Go**: `gofmt`, and `go vet` clean. No lint config beyond that.
- **TypeScript**: `npx tsc --noEmit -p tsconfig.json` in `packages/proxy` has to
  pass. Formatting follows what is already in the file.
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
- Say what you ran. "Both implementations, full suite, plus rows 3 and 7 of the
  run sheet on Claude Code and Codex" is a complete answer.
- CI runs the Go matrix, the TypeScript typecheck, the conformance suite twice,
  the release build, and a secret scan. All of it has to be green.
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

This project is MIT licensed. By submitting a pull request you agree that your
contribution is licensed under the same terms. There is no CLA and no copyright
assignment.

A `Signed-off-by` line is welcome and not required.

## Behaviour

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies everywhere in this project.
