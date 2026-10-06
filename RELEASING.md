# Releasing

How a version becomes something people can install, and the checks that stop a
release from lying about what it contains.

Only maintainers can cut a release. Everything here runs from a clean checkout
of `main`.

## What a version is

One number, in one place: the `version` field of
`packages/proxy/package.json`.

It is stamped into the Go binaries at build time with
`-ldflags "-X main.buildVersion=<version>"`, which is what `solongate --version`
and `solongate doctor` print. That was the whole of it for a long time: nothing
on GitHub showed the number, there were no tags, and the only way to learn what a
version meant was to read the commit that typed it. Twice in one day the manifest
and the commit message disagreed, because nothing compared them.

So now **a tag is the thing that makes a version visible**, and the release
workflow refuses a tag that does not match the manifest.

Two other numbers exist and are not the release version:

- **The hook version** (`hookVersion` in `packages/guard-go/main.go`, and
  `HOOK_VERSION` in the Node guard hook). It says which decision contract a
  guard implements. The hook compares it before delegating to the binary, so a
  binary that reports an older number is not used. A test reads the number out of
  the Node hook and asserts the Go constant equals it, so the two cannot drift.
  **Bump it when you change what gets blocked**, not when you change how
  something is phrased.
- **`optionalDependencies`** in `packages/proxy/package.json`: six entries, one
  per platform guard package, whose only correct value is this package's own
  version. `pnpm build:go` writes them.

## How it is distributed

Over git. `solongate update` pulls the newest source into the checkout it was
installed from and runs the install, which builds from source. The archives
attached to a GitHub release are a record of what a tag produced, never the
install path.

The npm package `@solongate/proxy` exists and carries the same version. It is not
what this repository's release workflow publishes.

## Cutting a release

### 1. Decide the version

Patch steps, pre 1.0. A release happens when there is something worth
installing, not on a schedule.

If anything in the release changes what gets blocked, say so in the changelog
entry and bump the hook version in the same pull request as the behaviour change,
not here.

### 2. Make sure main is green and clean

```bash
git checkout main && git pull
git status                    # has to be clean

pnpm install
pnpm build
cd packages/proxy && pnpm build && node test/run-all.mjs && cd ../..

cd packages/guard-go && go build -o solongate-guard . && cd ../..
cd packages/proxy && SG_HOOK=$PWD/../guard-go/solongate-guard node test/run-all.mjs && cd ../..

for m in guard-go proxy-go sgpolicy sgshared; do
  (cd packages/$m && gofmt -l . && go vet ./... && go test -count=1 ./...)
done
```

The conformance suite against both implementations is not optional here. CI runs
the same thing, and a release is the one moment where "CI was green on an older
commit" is not an answer.

### 3. Bump the version and the dependent files

Three files move together, and the second and third are the ones that get
forgotten:

```bash
# 1. the manifest
#    packages/proxy/package.json  ->  "version": "0.0.7"

# 2. the six optionalDependencies entries, written for you
cd packages/proxy && pnpm build:go linux-x64 && cd ../..
git diff --stat packages/proxy/package.json      # should show the six entries

# 3. the lockfile, which tracks the workspace version
pnpm install --lockfile-only
```

Why each one matters:

- **`optionalDependencies`**: a version bumped without those entries following it
  publishes new JavaScript beside the previous release's binaries. npm installs
  cleanly, `update` prints the new version, and the launcher runs the old binary.
  Nothing in that chain reports a failure from the outside, which is why CI
  checks it (`git diff --exit-code` on the manifest after running the build) and
  why `test/release-shape.mjs` asserts it.
- **The lockfile**: a bump that leaves it behind breaks `solongate update`, which
  installs with a frozen lockfile.

One target is enough for `build:go` at this step. The script rewrites all six
entries whichever platform was built.

### 4. Update the changelog

Move the Unreleased section to the new version in
[CHANGELOG.md](CHANGELOG.md). Mark anything that changes what gets blocked as
**behaviour**, because somebody's live policy will behave differently after the
update.

### 5. Commit, tag, push

```bash
git add -A
git commit                    # subject: what changed, and the version on its own line in the body
git push origin main

git tag v0.0.7
git push origin v0.0.7
```

The tag must be `v` plus exactly the manifest version. The workflow's first step
compares them and fails the release if they disagree, with the reason: binaries
that report a different version than the tag that produced them would mean
`doctor` and the download page are each telling the truth about a different
build.

### 6. Watch the workflow

`.github/workflows/release.yml` runs on the tag and does this:

1. Checks the tag against `packages/proxy/package.json`.
2. `pnpm install --frozen-lockfile`, then `pnpm build`.
3. `pnpm build:go` with no target, which cross compiles all six platforms. CGO
   is off, so there is no per platform toolchain to install.
4. One `tar.gz` per platform, named
   `solongate-<tag>-<platform>.tar.gz`.
5. Creates the GitHub release, with notes assembled from
   `git log --no-merges` over the range since the previous tag, plus the install
   instructions.

If it fails, fix forward: delete the tag, push the fix, tag again. A tag that
produced no release is confusing but harmless. A release whose archives do not
match its tag is not.

```bash
git tag -d v0.0.7
git push origin :refs/tags/v0.0.7
```

### 7. Check the result

On a machine that has an older version installed:

```bash
solongate update
solongate --version          # the new number
solongate doctor             # guard, hooks and local logs all healthy
```

Then open a new terminal and ask an agent to do something your policy refuses.
Hooks load at session start, so the terminal you ran the update in is still
running the previous registration.

## There is no release script, and that is on purpose

`packages/proxy` used to carry `scripts/release.mjs` behind a `pnpm release`
entry. Both are gone.

It came from the repository this code was carved out of: it built and signed a
browser extension from a `packages/shadowdom` that does not exist in this tree,
then published to a registry this repository does not publish to. It could not
have succeeded, it needed credentials nobody here has, and the one thing worse
than no release command is one that looks like the release command.

The release path is the git tag and the workflow above. Nothing else.

## Release notes

The workflow builds them from the commit subjects, which is why the subject line
convention matters: it should say what changed in the product. Anything that
needs more than a line belongs in the changelog, and the changelog is what a
person reads before updating.

For a release that changes what gets blocked, edit the published release notes
afterwards to lead with that, in one sentence, above the generated list.
