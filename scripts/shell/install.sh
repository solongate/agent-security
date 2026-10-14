#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
#
# Install SolonGate from this checkout: install the workspace, bundle the
# hooks, build this host's binaries, then run the freshly built binary to
# register the guard. Afterwards `solongate` is a command.
#
# This is the one path through those steps that ends by running the binary
# BY PATH rather than by a `solongate` that might still point at an older
# install, which is why it exists instead of four lines in the README.
#
# An agent cannot use this: the install step runs the CLI's `repair`, and
# every CLI command changes a security posture, so it refuses to run without
# a terminal on both stdin and stdout, which an agent tool call never has.
# The build steps still succeed; only that last step is refused, and it says
# so rather than looking like a bug.

set -eu

# ── arguments ────────────────────────────────────────

AUTO=0
for arg in "$@"; do
	case $arg in
	-y | --yes) AUTO=1 ;;
	-h | --help)
		cat <<'USAGE'
Install SolonGate from this checkout.

  ./scripts/shell/install.sh         walk through it, pausing between steps
  ./scripts/shell/install.sh --yes   assume yes; there is nothing to prompt for today

Afterwards "solongate" is a command. Open a new terminal before testing it:
hooks load when a session starts, so sessions already open are not guarded.
USAGE
		exit 0
		;;
	*)
		printf 'unknown argument: %s (try --help)\n' "$arg" >&2
		exit 1
		;;
	esac
done

# ── output ────────────────────────────────────────────────────────────

# Colour only on a real terminal; a pipe or CI log gets plain text.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
	# The same green/red packages/core/term uses, so this script and the Go CLI
	# read as one program when a run crosses from one into the other.
	B='\033[1m'; DIM='\033[2m'
	RED='\033[38;2;220;80;80m'; GREEN='\033[38;2;80;200;120m'; OFF='\033[0m'
else
	B=''; DIM=''; RED=''; GREEN=''; OFF=''
fi

# Each step prints one line when it's done, not a package manager's raw
# output: [  OK  ] Installed workspace dependencies. On failure the captured
# output is printed underneath a [FAILED] line instead of being thrown away.
#
# Everything below goes to stderr: it's the only stream sh can rely on being
# unbuffered, which is what lets a partial line (the typewriter effect, the
# spinner) reach the screen before a command finishes. It also puts this
# script on the same stream `solongate update` and the Go CLI print their own
# marks to, so a run that crosses between them reads as one.
TYPE_DELAY=0.002
[ -t 2 ] || TYPE_DELAY=''
sleep "$TYPE_DELAY" 2>/dev/null || TYPE_DELAY=''

type_out() {
	if [ -z "$TYPE_DELAY" ]; then
		printf '%s' "$1" >&2
		return 0
	fi
	# ${rest#?} drops the first character; ${rest%"${rest#?}"} is that character.
	# Shell builtins only: a `cut` per character triples the cost of the line.
	_rest=$1
	while [ -n "$_rest" ]; do
		printf '%s' "${_rest%"${_rest#?}"}" >&2
		_rest=${_rest#?}
		sleep "$TYPE_DELAY"
	done
}

say() { printf '         %b' "$DIM" >&2; type_out "$1"; printf '%b\n' "$OFF" >&2; }
mark_ok() { printf '%b[  OK  ]%b ' "$GREEN" "$OFF" >&2; type_out "$1"; printf '\n' >&2; }
mark_no() { printf '%b[FAILED]%b ' "$RED" "$OFF" >&2; type_out "$1"; printf '\n' >&2; }

# A file, not a variable: `pnpm install` emits more than a shell should hold
# in a command substitution, and a substitution would miss anything the
# child writes straight to the terminal.
RUNLOG=$(mktemp 2>/dev/null || echo /tmp/solongate-install.log)

trap 'rm -f "$RUNLOG"' EXIT

if sleep 0.35 2>/dev/null; then SPIN_DELAY=0.35; else SPIN_DELAY=1; fi

# run: announce a step, capture its output, and say one line about how it
# went. The dots keep the screen moving while output is captured and the
# step takes tens of seconds; only on a terminal, since a \r into a log file
# would just repeat the same line.
run() {
	_doing=$1
	_done=$2
	shift 2

	if [ -t 2 ]; then
		# set +e around wait: the whole point is to read the exit status, and
		# set -e would take the script out before the [FAILED] line could print.
		"$@" >"$RUNLOG" 2>&1 </dev/null &
		_pid=$!
		_d=''
		while kill -0 "$_pid" 2>/dev/null; do
			case $_d in
				'.') _d='..' ;;
				'..') _d='...' ;;
				*) _d='.' ;;
			esac
			printf '\r\033[2K         %b%s%s%b' "$DIM" "$_doing" "$_d" "$OFF" >&2
			sleep "$SPIN_DELAY"
		done
		set +e
		wait "$_pid"
		_rc=$?
		set -e
		printf '\r\033[2K' >&2
	else
		say "$_doing..."
		set +e
		"$@" >"$RUNLOG" 2>&1
		_rc=$?
		set -e
	fi

	if [ "$_rc" -eq 0 ]; then
		mark_ok "$_done"
		return 0
	fi
	mark_no "$_doing"
	printf '\n' >&2
	sed 's/^/         /' "$RUNLOG" >&2
	printf '\n' >&2
	exit 1
}

# die prints the problem and what to do about it, so a failure doesn't leave
# somebody searching.
die() {
	printf '\n%berror:%b %s\n' "$RED" "$OFF" "$1" >&2
	shift
	for line in "$@"; do printf '       %s\n' "$line" >&2; done
	exit 1
}

cd "$(dirname "$0")/../.."
repo=$(pwd)

# Every line starts in the same column: a mark is "[  OK  ] ", nine
# characters, so everything else is indented nine. This script can run in
# the middle of `solongate update`, and a header flush against the margin
# would read as a separate program's banner.
printf '         %bSolonGate%b  ' "$B" "$OFF" >&2
type_out "installing from $repo"
printf '\n' >&2

# ── which host is this ────────────────────────────────────────────────

# The npm spelling of the platform, which names the directory the binaries
# land in. Go spells two of these differently; scripts/build-go-binaries.mjs
# holds the same mapping.
case $(uname -s) in
Linux) os=linux ;;
Darwin) os=darwin ;;
*)
	die "this script covers Linux and macOS; found $(uname -s)." \
		"On Windows, build with: pnpm install && cd packages/hooks && pnpm build && pnpm build:go win32-x64" \
		"then run platforms\\win32-x64\\solongate.exe repair from a terminal."
	;;
esac

case $(uname -m) in
x86_64 | amd64) cpu=x64 ;;
arm64 | aarch64) cpu=arm64 ;;
*) die "unsupported CPU $(uname -m); SolonGate ships x64 and arm64 builds." ;;
esac

tag="$os-$cpu"
bin="$repo/packages/hooks/platforms/$tag/solongate"

# ── 1. the tools this needs ───────────────────────────────────────────

command -v node >/dev/null 2>&1 || die "node was not found on PATH." \
	"SolonGate's hooks are .mjs programs and run under node. Install Node 22 or newer."

node_major=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)
if [ "$node_major" -lt 22 ]; then
	die "node $(node -v) is too old; SolonGate needs 22 or newer." \
		"Node 20 reached end of life in April 2026 and no longer receives security" \
		"patches, which is not a runtime to put a security tool on."
fi

command -v pnpm >/dev/null 2>&1 || die "pnpm was not found on PATH." \
	"This repository is a pnpm workspace: npm and yarn cannot resolve the" \
	"workspace links between its packages. Install it with:" \
	"    corepack enable pnpm" \
	"  or" \
	"    npm install -g pnpm"

# Go is found the way scripts/gobin.mjs finds it, not just PATH: a toolchain
# fetched by `go` itself for a newer go.mod lives in the module cache with no
# symlink anywhere.
go_bin=$(node -e 'import("./scripts/gobin.mjs").then(m => console.log(m.goBin()))' 2>/dev/null || echo go)
if ! "$go_bin" version >/dev/null 2>&1; then
	die "no Go toolchain was found." \
		"The guard and the CLI are Go programs. Install Go 1.26 or newer, or set" \
		"GO_BIN to the binary if it is somewhere this did not look."
fi

mark_ok "Toolchain: node $(node -v), pnpm $(pnpm --version), $("$go_bin" version | cut -d' ' -f3 | sed 's/^go/go /')."

# ── 2. the workspace ──────────────────────────────────────────────────

# Not pnpm's own upgrade ad, which it would otherwise draw in a box in the
# middle of this run and which reads as the next thing gone wrong in the
# install of a security tool.
export npm_config_update_notifier=false

run "Installing workspace dependencies" "Installed workspace dependencies." \
	pnpm install

# ── 3. the hooks ──────────────────────────────────────────────────────

cd "$repo/packages/hooks"
run "Bundling the hooks" "Bundled the hooks that watch your agents." \
	pnpm build

# ── 4. this host's binaries ───────────────────────────────────────────

# One target, not all six: six is what a release needs; this is the machine
# in front of us.
GO_BIN="$go_bin" run "Building the guard and CLI for $tag" "Built the guard and the CLI." \
	pnpm build:go "$tag"
[ -x "$bin" ] || die "the build reported success but $bin is not there." \
	"Run \`pnpm build:go $tag\` in packages/hooks and read what it says."

# ── 5. the install ────────────────────────────────────────────────────

# The binary is run by path here, not through whatever `solongate` is
# already on PATH: that could be an older install, and asking it to install
# itself would install the old version over the new one.
if [ ! -t 0 ] || [ ! -t 1 ]; then
	die "no interactive terminal (stdin and stdout are not both a tty)." \
		"Everything above this point succeeded: the build is done." \
		"" \
		"The install step is refused because every command in the SolonGate CLI" \
		"changes a security posture, so the CLI requires a terminal, which an AI" \
		"agent's tool call does not have. This is deliberate." \
		"" \
		"Run ./scripts/shell/install.sh yourself, in your own terminal."
fi

# Not through run(): repair refuses to work unless stdout AND stdin are both
# a terminal, for the same reason above, and capturing its output would take
# the terminal away from the one step that needs it.
if "$bin" repair; then
	mark_ok "SolonGate is installed. Your agents ask it before they act."
else
	mark_no "Registering the guard with your agents"
	exit 1
fi

# ── and a command called solongate ────────────────────────────────────

# An install puts the binaries in the store, where the guard hook looks for
# them; putting `solongate` on PATH is a separate step, since somebody who
# cloned this repository never ran npm.
store_bin="$HOME/.solongate/bin/solongate"
[ -x "$store_bin" ] || die "the install finished but $store_bin is not there." \
	"Nothing was added to your PATH. Run ./scripts/shell/install.sh again and read the last lines."

linked=''
for dir in "$HOME/.local/bin" "$HOME/bin" /usr/local/bin; do
	case ":$PATH:" in *":$dir:"*) ;; *) continue ;; esac
	[ -d "$dir" ] && [ -w "$dir" ] || continue

	# A real file is somebody else's install, not a link this script can
	# replace. Keep it, renamed, so the change can be undone by hand.
	if [ -e "$dir/solongate" ] && [ ! -L "$dir/solongate" ]; then
		mv "$dir/solongate" "$dir/solongate.before-solongate-install" || continue
		say "moved an existing $dir/solongate aside as solongate.before-solongate-install"
	fi

	if ln -sf "$store_bin" "$dir/solongate" 2>/dev/null; then
		linked="$dir/solongate"
		break
	fi
done

if [ -n "$linked" ]; then
	mark_ok "solongate is on your PATH: $linked"
else
	mark_ok "Installed, but not on your PATH yet."
	say 'add to your shell profile:'
	printf '\n    export PATH="$HOME/.solongate/bin:$PATH"\n\n' >&2
fi

say "solongate              the TUI"
say "solongate policy       what is enforced here"
say "solongate doctor       whether it is working"
say "solongate update       pull the newest version and reinstall"