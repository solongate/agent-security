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
# workspace, bundle the hooks, build this host's binaries, then run the freshly
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

# WHAT JUST HAPPENED, IN WORDS SOMEBODY CAN USE.
#
# Four of these five steps print output this script does not control — a package
# manager, a bundler and a Go build, each reporting at its own volume and in its own
# vocabulary. A person installing a security tool for the first time reads a few
# hundred lines of that and has no way to tell a warning from a failure, or to answer
# the only question they actually have: did that work, and what was it for.
#
# So every step ends with one sentence, in plain language, after the noise and before
# the pause. It is the last thing on screen while they decide whether to continue.
plain() { printf '\n      %b✓%b %s\n' "$GREEN" "$OFF" "$1"; }
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
	"SolonGate's hooks are .mjs programs and run under node. Install Node 22 or newer."

# The major version, from `v22.4.0`. Checked here because every failure further
# down is worse to read: a dependency that refuses to install, or a syntax error
# inside a bundled hook, both of which look like the product being broken rather
# than the runtime being old.
node_major=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)
if [ "$node_major" -lt 22 ]; then
	die "node $(node -v) is too old; SolonGate needs 22 or newer." \
		"Node 20 reached end of life in April 2026 and no longer receives security" \
		"patches, which is not a runtime to put a security tool on."
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

plain "Your machine has the three tools needed to build SolonGate."

# ── 2. the workspace ──────────────────────────────────────────────────

step "Installing workspace dependencies"
note "pnpm warns here that it could not create a bin — it is linking commands at"
note "files the next step has not produced yet. Nothing is wrong."

# AND NOT pnpm's OWN UPGRADE AD, which it draws in a box in the middle of this:
#
#     ╭──────────────────────────────────────────╮
#     │     Update available! 9.15.0 → 12.8.1.   │
#     │     Run "pnpm add -g pnpm" to update.    │
#     ╰──────────────────────────────────────────╯
#
# It is about pnpm, it is not a problem, and it lands directly under a line saying
# the warnings above are expected — so it reads as the next thing that went wrong,
# in the install of a security tool, where somebody is already watching for trouble.
# It was reported as an error the first time anybody saw it.
#
# An installer's output should be about the thing being installed. The variable is
# npm's, which pnpm honours.
export npm_config_update_notifier=false

pnpm install

plain "Downloaded the code libraries the build needs. The warnings above are expected."

# ── 3. the hooks ──────────────────────────────────────────────────────

step "Bundling the hooks"
cd "$repo/packages/proxy"
pnpm build

plain "Bundled the hooks that watch what your AI agents do."

# ── 4. this host's binaries ───────────────────────────────────────────

# One target, not all six. Six is what a release needs and takes minutes; this is
# the machine in front of us.
step "Building the Go guard and CLI for $tag"
GO_BIN="$go_bin" pnpm build:go "$tag"
[ -x "$bin" ] || die "the build reported success but $bin is not there." \
	"Run \`pnpm build:go $tag\` in packages/proxy and read what it says."

plain "Built the guard: the program that checks every action an AI agent takes."

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

plain "SolonGate is installed. Your AI agents now have to ask it before they act."

# ── and a command called solongate ────────────────────────────────────

# AN INSTALL DOES NOT MAKE A COMMAND. It puts the binaries in the store, which is
# where the guard hook looks for them; putting `solongate` on PATH is npm's job, and
# somebody who cloned this repository never ran npm.
#
# AND IF SOMETHING IS ALREADY THERE, IT MAY NOT BE THIS. That was the first version
# of this block: it found a `solongate` on PATH, reported success and stopped. What
# it found was an npm install from months earlier, whose launcher resolves the
# platform package shipped BESIDE IT before it ever looks in the store — so the
# command kept running a binary from a different build entirely, while the guard
# enforcing every tool call was the new one. Two versions, one name, and the only
# visible symptom was a screen that looked unfamiliar.
#
# So the link is pointed at the binary this run installed, every time. It is one
# symlink, it is reversible, and anything that was not a symlink is kept.
store_bin="$HOME/.solongate/bin/solongate"
[ -x "$store_bin" ] || die "the install finished but $store_bin is not there." \
	"Nothing was added to your PATH. Run ./install.sh again and read step 5."

linked=''
for dir in "$HOME/.local/bin" "$HOME/bin" /usr/local/bin; do
	# On PATH and writable, or it is not a candidate: a link into a directory nothing
	# searches is indistinguishable from doing nothing.
	case ":$PATH:" in *":$dir:"*) ;; *) continue ;; esac
	[ -d "$dir" ] && [ -w "$dir" ] || continue

	# A real file is somebody else's install, not a link this script can replace. Keep
	# it — renamed, not deleted — so the change can be undone by hand.
	if [ -e "$dir/solongate" ] && [ ! -L "$dir/solongate" ]; then
		mv "$dir/solongate" "$dir/solongate.before-solongate-install" || continue
		note "moved an existing $dir/solongate aside (renamed to solongate.before-solongate-install)"
	fi

	if ln -sf "$store_bin" "$dir/solongate" 2>/dev/null; then
		linked="$dir/solongate"
		break
	fi
done

if [ -n "$linked" ]; then
	printf '\n%b✓%b solongate is ready\n' "$GREEN" "$OFF"
	note "$linked → $store_bin"
else
	printf '\n%b✓%b installed, but not on your PATH yet\n' "$GREEN" "$OFF"
	note "Add this to your shell profile:"
	printf '\n    export PATH="$HOME/.solongate/bin:$PATH"\n'
fi

# Hooks are read when a client starts, so a session that is already open is still
# running under whatever was registered when it launched — including none.
printf '\n%bOpen a new terminal before you test it.%b\n' "$B" "$OFF"
note "Hooks load when a session starts, so sessions already open are not guarded."
printf '\n'
ok "solongate              the dataroom"
ok "solongate policy       what is enforced here"
ok "solongate doctor       whether it is working"
ok "solongate update       pull the newest version and reinstall"
printf '\n'
