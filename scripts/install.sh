#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 the SolonGate contributors

# Installs SolonGate from this checkout.
set -eu

AUTO=0
for arg in "$@"; do
	case $arg in
	-y | --yes) AUTO=1 ;;
	-h | --help)
		cat <<'USAGE'
Install SolonGate from this checkout.

  ./scripts/install.sh         walk through it, pausing between steps
  ./scripts/install.sh --yes   assume yes; there is nothing to prompt for today

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

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
	B='\033[1m'; DIM='\033[2m'
	RED='\033[38;2;220;80;80m'; GREEN='\033[38;2;80;200;120m'; OFF='\033[0m'
else
	B=''; DIM=''; RED=''; GREEN=''; OFF=''
fi

TYPE_DELAY=0.002
[ -t 2 ] || TYPE_DELAY=''
sleep "$TYPE_DELAY" 2>/dev/null || TYPE_DELAY=''

type_out() {
	if [ -z "$TYPE_DELAY" ]; then
		printf '%s' "$1" >&2
		return 0
	fi
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

RUNLOG=$(mktemp 2>/dev/null || echo /tmp/solongate-install.log)

trap 'rm -f "$RUNLOG"' EXIT

if sleep 0.35 2>/dev/null; then SPIN_DELAY=0.35; else SPIN_DELAY=1; fi

run() {
	_doing=$1
	_done=$2
	shift 2

	if [ -t 2 ]; then
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

die() {
	printf '\n%berror:%b %s\n' "$RED" "$OFF" "$1" >&2
	shift
	for line in "$@"; do printf '       %s\n' "$line" >&2; done
	exit 1
}

cd "$(dirname "$0")/.."
repo=$(pwd)

printf '         %bSolonGate%b  ' "$B" "$OFF" >&2
type_out "installing from $repo"
printf '\n' >&2

case $(uname -s) in
Linux) os=linux ;;
Darwin) os=darwin ;;
*)
	die "this script covers Linux and macOS; found $(uname -s)." \
		"On Windows, build with: packages\\hooks\\scripts\\build-platforms.sh win32-x64" \
		"(Git Bash or WSL, with Go on PATH), then run" \
		"platforms\\win32-x64\\solongate.exe repair from a terminal."
	;;
esac

case $(uname -m) in
x86_64 | amd64) cpu=x64 ;;
arm64 | aarch64) cpu=arm64 ;;
*) die "unsupported CPU $(uname -m); SolonGate ships x64 and arm64 builds." ;;
esac

tag="$os-$cpu"
bin="$repo/packages/hooks/platforms/$tag/solongate"

go_bin=go
for p in "$HOME/go/bin/go" /usr/local/go/bin/go /usr/lib/go/bin/go /opt/homebrew/bin/go /usr/local/bin/go; do
	[ -x "$p" ] && { go_bin=$p; break; }
done
if [ "$go_bin" = go ]; then
	cache="$HOME/go/pkg/mod/golang.org"
	if [ -d "$cache" ]; then
		found=$(find "$cache" -maxdepth 1 -type d -name 'toolchain@*' 2>/dev/null | sort -r | while read -r d; do
			[ -x "$d/bin/go" ] && { printf '%s\n' "$d/bin/go"; break; }
		done)
		[ -n "$found" ] && go_bin=$found
	fi
fi

if ! "$go_bin" version >/dev/null 2>&1; then
	die "no Go toolchain was found." \
		"The guard and the CLI are Go programs. Install Go 1.26 or newer, or set" \
		"GO_BIN to the binary if it is somewhere this did not look."
fi

mark_ok "Toolchain: $("$go_bin" version | cut -d' ' -f3 | sed 's/^go/go /')."

GO_BIN="$go_bin" run "Building the guard and CLI for $tag" "Built the guard and the CLI." \
	"$repo/packages/hooks/scripts/build-platforms.sh" "$tag"
[ -x "$bin" ] || die "the build reported success but $bin is not there." \
	"Run \`packages/hooks/scripts/build-platforms.sh $tag\` and read what it says."

if [ ! -t 0 ] || [ ! -t 1 ]; then
	die "no interactive terminal (stdin and stdout are not both a tty)." \
		"Everything above this point succeeded. The build is done." \
		"" \
		"The install step is refused because every command in the SolonGate CLI" \
		"changes a security posture, so the CLI requires a terminal, which an AI" \
		"agent's tool call does not have. This is deliberate." \
		"" \
		"Run ./scripts/install.sh yourself, in your own terminal."
fi

if "$bin" repair; then
	mark_ok "SolonGate is installed. Your agents ask it before they act."
else
	mark_no "Registering the guard with your agents"
	exit 1
fi

store_bin="$HOME/.solongate/bin/solongate"
[ -x "$store_bin" ] || die "the install finished but $store_bin is not there." \
	"Nothing was added to your PATH. Run ./scripts/install.sh again and read the last lines."

linked=''
for dir in "$HOME/.local/bin" "$HOME/bin" /usr/local/bin; do
	case ":$PATH:" in *":$dir:"*) ;; *) continue ;; esac
	[ -d "$dir" ] && [ -w "$dir" ] || continue

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