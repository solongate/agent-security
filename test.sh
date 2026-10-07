#!/usr/bin/env sh
#
# Run everything CI runs, in the order that fails fastest.
#
#   ./test.sh              all of it
#   ./test.sh suite        the conformance suite only, against both guards
#   ./test.sh go           the Go modules only
#
# WHY A SCRIPT RATHER THAN FOUR COMMANDS IN CONTRIBUTING.md. The four were: build
# the TypeScript, run the suite, build the Go guard and run the suite again
# against it, then loop gofmt, vet and test over four modules. Every one of them
# has a detail that is wrong in a way that does not look wrong: SG_HOOK has to be
# absolute or every case fails with ENOENT and reads as a broken guard, the build
# has to be the bundler's and not tsc's or the suite tests a layout nobody ships,
# and `go test` without -count=1 will serve a cached PASS for a test whose subject
# was deleted.
#
# Somebody who has to remember four commands and three footnotes runs the first
# one and assumes the rest.
#
# IT RUNS BOTH GUARDS, EVERY TIME. There are two implementations and which one
# decides a call depends only on whether a machine has the Go binary, so a suite
# run against one of them certifies half the machines. That is the whole reason
# this file exists rather than an alias for `pnpm test`.

set -eu

cd "$(dirname "$0")"
ROOT=$(pwd)

# ── output ────────────────────────────────────────────────────────────

if [ -t 1 ]; then
	B=$(printf '\033[1m') DIM=$(printf '\033[2m') OFF=$(printf '\033[0m')
	GREEN=$(printf '\033[32m') RED=$(printf '\033[31m')
else
	B='' DIM='' OFF='' GREEN='' RED=''
fi

step() { printf '\n%s▸ %s%s\n' "$B" "$1" "$OFF"; }
note() { printf '  %s%s%s\n' "$DIM" "$1" "$OFF"; }

# Every failure says what broke AND what it means, because the three failures
# this script is most likely to hit all read as something else.
die() {
	printf '\n%s✗ %s%s\n' "$RED" "$1" "$OFF"
	shift
	for line in "$@"; do printf '  %s\n' "$line"; done
	printf '\n'
	exit 1
}

WHAT=${1:-all}

# ── the typescript build, which the suite reads ───────────────────────
#
# pnpm build and not `npx tsc`. tsc emits one JavaScript file per source file,
# which resolves every import the suite has and is NOT what ships: the package
# ships the bundler's output, so a module the suite imports has to be an entry
# point to survive the real build. Two were not, and only a machine that had run
# the real build noticed.
build_ts() {
	step "Building the CLI, the TUI and the hooks"
	cd "$ROOT/packages/proxy"
	pnpm build >/dev/null 2>&1 || die "the build failed." \
		"Run it on its own to see why:" \
		"    cd packages/proxy && pnpm build"
	note "dist/ and the bundled hook are current"
}

# ── the conformance suite, against both guards ────────────────────────
run_suite() {
	build_ts

	step "Conformance suite: the bundled JavaScript hook"
	cd "$ROOT/packages/proxy"
	node test/run-all.mjs || die "the suite failed against the Node hook." \
		"This is the contract. A red suite means the change is wrong, not the test."

	step "Conformance suite: the Go guard"
	# Built into a temp directory rather than into the tree: an executable sitting
	# in packages/guard-go looks like an install, and a stale one is worse than
	# none. SG_HOOK must be ABSOLUTE because the suite spawns the guard with cwd
	# set to a sandbox, so a relative path resolves against that and fails with
	# ENOENT on every single case, which reads as the guard being broken.
	GUARD_DIR=$(mktemp -d)
	trap 'rm -rf "$GUARD_DIR"' EXIT
	cd "$ROOT/packages/guard-go"
	go build -o "$GUARD_DIR/guard" . || die "the Go guard did not build." \
		"Run it on its own to see why:" \
		"    cd packages/guard-go && go build ."
	cd "$ROOT/packages/proxy"
	SG_HOOK="$GUARD_DIR/guard" node test/run-all.mjs || die \
		"the suite failed against the Go guard but passed against the Node hook." \
		"That is a DIVERGENCE: the two are meant to be indistinguishable, and" \
		"which one decides a call depends only on whether a machine has the binary." \
		"Every divergence found so far was found exactly this way."
}

# ── the go modules ────────────────────────────────────────────────────
run_go() {
	for m in guard-go proxy-go sgpolicy sgshared; do
		step "Go: $m"
		cd "$ROOT/packages/$m"

		unformatted=$(gofmt -l .)
		if [ -n "$unformatted" ]; then
			printf '%s\n' "$unformatted"
			die "those files are not gofmt'd." "    cd packages/$m && gofmt -w ."
		fi

		go vet ./... || die "go vet found something in $m."

		# -count=1 is not a habit, it is a fix. Go serves a cached PASS for a test
		# whose subject was deleted elsewhere in the repo, and one sat green that
		# way for a while. The run before you push is the other place that should
		# never read a cache.
		go test -count=1 ./... || die "tests failed in $m."
	done
}

# ── the typescript types ──────────────────────────────────────────────
run_types() {
	step "TypeScript types"
	cd "$ROOT/packages/proxy"
	npx --no-install tsc --noEmit -p tsconfig.json || die "typecheck failed."
	note "no type errors"
}

case "$WHAT" in
suite) run_suite ;;
go) run_go ;;
all)
	run_go
	run_types
	run_suite
	;;
*)
	printf 'unknown argument: %s\n\n' "$WHAT" >&2
	printf '  ./test.sh         everything\n' >&2
	printf '  ./test.sh suite   the conformance suite, against both guards\n' >&2
	printf '  ./test.sh go      the Go modules\n\n' >&2
	exit 1
	;;
esac

printf '\n%s✓ green%s\n' "$GREEN" "$OFF"
case "$WHAT" in
all) note "four Go modules, the types, and the suite against both guards" ;;
esac
printf '\n'
