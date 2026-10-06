<!--
Thanks for sending this. Delete any section that does not apply.

If this fixes a vulnerability that was reported privately, say so without the
details, and link the advisory rather than describing the bypass here.
-->

## What changes for somebody running this

<!-- One or two sentences, in terms of behaviour rather than files. -->

## Why

<!-- What was wrong, or what could not be expressed before. Link the issue. -->

Closes #

## Does this change what gets blocked?

- [ ] No. Nothing a policy decides behaves differently.
- [ ] Yes, and the hook version is bumped in this pull request
      (`hookVersion` in `packages/guard-go/main.go` and `HOOK_VERSION` in the
      Node guard hook, which a test keeps equal).

If yes, say in one line what a user will notice after updating. That line
becomes a changelog entry marked **behaviour**.

## Both implementations

There are two guards, and which one decides a call depends only on whether a
machine has the Go binary. A change to the decision path lands in both or it
does not land.

- [ ] This does not touch the decision path.
- [ ] It touches the decision path, and both implementations are changed here.
- [ ] Only one half is changed, and the pull request explains why that is safe,
      with an issue open for the other.

## What you ran

```
# the conformance suite, against the Node hook
cd packages/proxy && pnpm build && node test/run-all.mjs

# and against the Go binary
cd packages/guard-go && go build -o solongate-guard .
cd ../proxy && SG_HOOK=$PWD/../guard-go/solongate-guard node test/run-all.mjs

# every Go module you touched
gofmt -l . && go vet ./... && go test -count=1 ./...
```

- [ ] Suite passes against the Node hook
- [ ] Suite passes against the Go binary
- [ ] `gofmt`, `go vet` and `go test -count=1` are clean in every module touched
- [ ] `npx tsc --noEmit -p tsconfig.json` passes in `packages/proxy`, if TypeScript changed

Manual rows from [TESTING.md](../TESTING.md), if the CLI surface or a client
adapter changed:

<!-- e.g. "rows 3 and 7 on Claude Code and Codex, Linux" -->

## New or changed tests

<!--
A behaviour change needs a conformance case that fails before and passes after.
Say which file, and what the case pins. If you changed an existing case, explain
why the behaviour it pinned was wrong: every case in there exists because
something was once broken.
-->

## Anything a reviewer should look at closely

<!-- A decision you are unsure about, a tradeoff, a comment you removed. -->
