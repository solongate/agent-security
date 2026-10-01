#!/usr/bin/env sh
#
# Install SolonGate from this checkout.
#
#   ./install.sh
#
# Afterwards `solongate` is a command, and the long path this script exists to
# replace is never typed again.
#
# WHY A SCRIPT RATHER THAN FOUR COMMANDS IN THE README. The four were: install the
# workspace, build the TypeScript, build this host's binaries, then run the freshly
# built binary BY PATH — `./packages/proxy/platforms/linux-x64/solongate repair` —
# because the `solongate` on PATH still pointed at an older install. That last one
# is not a command anybody should have to know, it names a directory that depends
# on the machine, and getting it wrong looks like the product being broken rather
# than a path being mistyped.
#
# Everything here is a step somebody would otherwise do by hand, in the same order,
# with the failures named.
#
# IT CANNOT BE USED BY AN AGENT, and that is not this script's doing. Every command
# in the CLI changes a security posture — policies, rate limits, DLP, the guard
# itself — so the CLI refuses to run without a terminal on both stdin and stdout,
# which an agent tool call never has. Run from an agent, the build steps here
# succeed and the install step is refused, which is the correct outcome and is
# reported as such rather than left to look like a bug.

set -eu

# ── arguments ────────────────────────────────────────

AUTO=0
for arg in "$@"; do
	case $arg in
	-y | --yes) AUTO=1 ;;
	-h | --help)
		cat <<'USAGE'
Install SolonGate from this checkout.

  ./install.sh         walk through it, pausing between steps
  ./install.sh --yes   run it straight through, no pauses

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

# Colour only when something is there to read it. A pipe or a CI log gets plain
# text; escape codes in a captured log are noise that outlives the terminal.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
	B='\033[1m'; DIM='\033[2m'; RED='\033[31m'; GREEN='\033[32m'; OFF='\033[0m'
else
	B=''; DIM=''; RED=''; GREEN=''; OFF=''
fi

# WHY THIS STOPS BETWEEN STEPS. Five steps produce several hundred lines — two of
# them are a package manager and a bundler reporting at their own volume — and the
# few lines this script prints itself are the ones worth reading. Run straight
# through, all of it arrives at once and the only thing a person can do afterwards
# is scroll back and hope the terminal kept enough.
#
# So each step stops at its end, with what it did still on screen.
#
# ONLY WHEN SOMEBODY IS THERE TO PRESS A KEY. A pipe, a CI job and an agent have no
# tty, and a prompt there is not a pause but a hang with nothing explaining it.
# --yes is for the person who wants it straight through anyway.
pause() {
	[ "$AUTO" = 1 ] && return 0
	[ -t 0 ] && [ -t 1 ] || return 0
	printf '\n      %bEnter to continue · Ctrl+C to stop%b ' "$DIM" "$OFF"
	# `|| true` because EOF on stdin is not a failure, and set -e would treat it as
	# one — ending the install at a prompt rather than at a problem.
	read -r _ || true
}

step=0
step() {
	# Before the header rather than after the work: the pause belongs at the end of
	# the step that just finished, while its output is still what you are looking at.
	[ "$step" -gt 0 ] && pause
	step=$((step + 1))
	printf '\n%b[%d/%d]%b %s\n' "$B" "$step" "$TOTAL" "$OFF" "$1"
}
note() { printf '      %b%s%b\n' "$DIM" "$1" "$OFF"; }
ok() { printf '      %b%s%b\n' "$GREEN" "$1" "$OFF"; }

# die prints the problem AND what to do about it. A one-line failure that leaves
# somebody searching is the thing this script is meant to stop producing.
die() {
	printf '\n%berror:%b %s\n' "$RED" "$OFF" "$1" >&2
	shift
	for line in "$@"; do printf '       %s\n' "$line" >&2; done
	exit 1
}

TOTAL=5

cd "$(dirname "$0")"
repo=$(pwd)

printf '%bSolonGate%b — installing from %s\n' "$B" "$OFF" "$repo"

# ── which host is this ────────────────────────────────────────────────

# The npm spelling of the platform, which is what the platform packages are named
# after and therefore which directory the binaries land in. Go spells two of these
# differently; scripts/build-go-binaries.mjs holds the same mapping.
case $(uname -s) in
Linux) os=linux ;;
Darwin) os=darwin ;;
*)
	die "this script covers Linux and macOS; found $(uname -s)." \
		"On Windows, build with: pnpm install && cd packages/proxy && pnpm build && pnpm build:go win32-x64" \
		"then run platforms\\win32-x64\\solongate.exe repair from a terminal."
	;;
esac

case $(uname -m) in
x86_64 | amd64) cpu=x64 ;;
arm64 | aarch64) cpu=arm64 ;;
*) die "unsupported CPU $(uname -m); SolonGate ships x64 and arm64 builds." ;;
esac

tag="$os-$cpu"
bin="$repo/packages/proxy/platforms/$tag/solongate"

# ── 1. the tools this needs ───────────────────────────────────────────

step "Checking the toolchain"

command -v node >/dev/null 2>&1 || die "node was not found on PATH." \
	"SolonGate's hooks are .mjs programs and run under node. Install Node 20 or newer."

# The major version, from `v22.4.0`. Checked because the failure otherwise arrives
# much later as a syntax error inside a bundled hook, which reads as the product
# being broken rather than the runtime being old.
node_major=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)
if [ "$node_major" -lt 20 ]; then
	die "node $(node -v) is too old; SolonGate needs 20 or newer." \
		"The hooks use syntax that older versions cannot parse, and the error they" \
		"produce names a bundled file rather than the version."
fi
note "node $(node -v)"

command -v pnpm >/dev/null 2>&1 || die "pnpm was not found on PATH." \
	"This repository is a pnpm workspace — npm and yarn cannot resolve the" \
	"workspace links between its packages. Install it with:" \
	"    corepack enable pnpm" \
	"  or" \
	"    npm install -g pnpm"
note "pnpm $(pnpm --version)"

# Go is found the same way the build script finds it, which is not just PATH: a
# toolchain fetched by `go` itself for a newer go.mod lives in the module cache,
# with no symlink anywhere. scripts/gobin.mjs exists for that case, so it answers
# here too rather than this script keeping a second, worse copy of the search.
go_bin=$(node -e 'import("./scripts/gobin.mjs").then(m => console.log(m.goBin()))' 2>/dev/null || echo go)
if ! "$go_bin" version >/dev/null 2>&1; then
	die "no Go toolchain was found." \
		"The guard and the CLI are Go programs. Install Go 1.25 or newer, or set" \
		"GO_BIN to the binary if it is somewhere this did not look."
fi
note "$("$go_bin" version | cut -d' ' -f3) at $go_bin"

# ── 2. the workspace ──────────────────────────────────────────────────

step "Installing workspace dependencies"
note "pnpm warns here that it could not create a bin — it is linking commands at"
note "files the next step has not produced yet. Nothing is wrong."
pnpm install

# ── 3. the TypeScript half ────────────────────────────────────────────

step "Building the CLI, the TUI and the hooks"
cd "$repo/packages/proxy"
pnpm build

# ── 4. this host's binaries ───────────────────────────────────────────

# One target, not all six. Six is what a release needs and takes minutes; this is
# the machine in front of us.
step "Building the Go guard and CLI for $tag"
GO_BIN="$go_bin" pnpm build:go "$tag"
[ -x "$bin" ] || die "the build reported success but $bin is not there." \
	"Run \`pnpm build:go $tag\` in packages/proxy and read what it says."

# ── 5. the install ────────────────────────────────────────────────────

# WHY THE BINARY IS RUN BY PATH HERE, which is the thing this script exists to
# stop a person doing: the `solongate` on PATH, if there is one, is whatever was
# installed before — an older release, or nothing. Asking it to install itself
# would install the old version over the new one. So the freshly built binary is
# the one that arranges the machine, exactly once, and every run after this is
# plain `solongate`.
step "Installing the guard, the hooks and the client registrations"

if [ ! -t 0 ] || [ ! -t 1 ]; then
	die "no interactive terminal (stdin and stdout are not both a tty)." \
		"Everything above this point succeeded: the build is done." \
		"" \
		"The install step is refused because every command in the SolonGate CLI" \
		"changes a security posture, so the CLI requires a terminal — which an AI" \
		"agent's tool call does not have. This is deliberate." \
		"" \
		"Run ./install.sh yourself, in your own terminal."
fi

"$bin" repair

# ── and a command called solongate ────────────────────────────────────

# An install puts the binaries in the store, which is where the guard hook looks
# for them. It does NOT put anything on PATH: that is normally npm's job, done by
# `npm i -g @solongate/proxy`, and somebody who cloned this repository never ran
# it. Without this, `repair` succeeds and `solongate` is still not a command —
# which is the exact complaint this script was written for.
store_bin="$HOME/.solongate/bin/solongate"

if existing=$(command -v solongate 2>/dev/null); then
	# Something already answers to the name. Leave it: the npm launcher's last
	# candidate is the store, so it finds the binary that was just installed.
	printf '\n%b✓%b solongate is ready\n' "$GREEN" "$OFF"
	note "via $existing"
else
	linked=''
	for dir in "$HOME/.local/bin" "$HOME/bin" /usr/local/bin; do
		# On PATH and writable, or it is not a candidate. A link into a directory
		# nothing searches is indistinguishable from doing nothing.
		case ":$PATH:" in *":$dir:"*) ;; *) continue ;; esac
		[ -d "$dir" ] && [ -w "$dir" ] || continue
		if ln -sf "$store_bin" "$dir/solongate" 2>/dev/null; then
			linked="$dir/solongate"
			break
		fi
	done

	if [ -n "$linked" ]; then
		printf '\n%b✓%b solongate is ready\n' "$GREEN" "$OFF"
		note "linked at $linked"
	else
		printf '\n%b✓%b installed, but not on your PATH yet\n' "$GREEN" "$OFF"
		note "Add this to your shell profile:"
		printf '\n    export PATH="$HOME/.solongate/bin:$PATH"\n'
	fi
fi

# Hooks are read when a client starts, so a session that is already open is still
# running under whatever was registered when it launched — including none.
printf '\n%bOpen a new terminal before you test it.%b\n' "$B" "$OFF"
note "Hooks load when a session starts, so sessions already open are not guarded."
printf '\n'
ok "solongate              the dataroom"
ok "solongate policy       what is enforced here"
ok "solongate doctor       whether it is working"
printf '\n'
