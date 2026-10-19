#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 the SolonGate contributors
#
# Cross-compiles the guard and CLI binaries for every shipped platform (or
# one, given its tag) and lays them out under packages/hooks/platforms/<tag>,
# exactly what install.sh and a release archive copy from.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
hooks_dir=$(cd "$here/.." && pwd)
repo=$(cd "$hooks_dir/../.." && pwd)
out_root="$hooks_dir/platforms"
version=$(cat "$hooks_dir/VERSION")

# Same lookup packages/app and the CLI's own update path use: a toolchain
# `go` itself fetched for a newer go.mod lives in the module cache with no
# symlink anywhere, so PATH alone is not enough.
go_bin() {
	if [ -n "${GO_BIN:-}" ]; then
		printf '%s' "$GO_BIN"
		return
	fi
	for p in "$HOME/go/bin/go" /usr/local/go/bin/go /usr/lib/go/bin/go /opt/homebrew/bin/go /usr/local/bin/go; do
		if [ -x "$p" ]; then
			printf '%s' "$p"
			return
		fi
	done
	cache="$HOME/go/pkg/mod/golang.org"
	if [ -d "$cache" ]; then
		found=$(find "$cache" -maxdepth 1 -type d -name 'toolchain@*' 2>/dev/null | sort -r | while read -r d; do
			if [ -x "$d/bin/go" ]; then
				printf '%s\n' "$d/bin/go"
				break
			fi
		done)
		if [ -n "$found" ]; then
			printf '%s' "$found"
			return
		fi
	fi
	printf 'go'
}

go=$(go_bin)
if ! "$go" version >/dev/null 2>&1; then
	echo "no Go toolchain on PATH (looked for \`$go\`). Set GO_BIN, or add it:" >&2
	echo "  export PATH=\"\$HOME/.local/opt/go/bin:\$PATH\"" >&2
	exit 1
fi

# tag GOOS GOARCH exe-suffix
all_targets='
linux-x64 linux amd64
linux-arm64 linux arm64
darwin-x64 darwin amd64
darwin-arm64 darwin arm64
win32-x64 windows amd64
win32-arm64 windows arm64
'

only=${1:-}
targets=$(printf '%s' "$all_targets" | grep -v '^$' || true)
if [ -n "$only" ]; then
	targets=$(printf '%s' "$targets" | awk -v t="$only" '$1 == t')
	if [ -z "$targets" ]; then
		echo "unknown target $only; known:" >&2
		printf '%s' "$all_targets" | awk '{print "  " $1}' >&2
		exit 1
	fi
fi

echo "building at version $version" >&2
echo >&2

printf '%s\n' "$targets" | while IFS=' ' read -r tag goos goarch; do
	[ -n "$tag" ] || continue

	dir="$out_root/$tag"
	rm -rf "$dir"
	mkdir -p "$dir"

	suffix=''
	[ "$goos" = windows ] && suffix='.exe'

	for pair in "solongate-guard:$repo/packages/guard" "solongate:$repo/packages/app"; do
		bin=${pair%%:*}
		module=${pair#*:}
		exe="$bin$suffix"
		dest="$dir/$exe"

		GOOS=$goos GOARCH=$goarch CGO_ENABLED=0 "$go" build \
			-C "$module" \
			-trimpath \
			-ldflags "-s -w -X main.buildVersion=$version" \
			-o "$dest" .

		[ "$goos" = windows ] || chmod 755 "$dest"
	done

	size=$(du -ch "$dir"/* 2>/dev/null | tail -1 | cut -f1)
	printf '  %-14s %s\n' "$tag" "$size" >&2
done

echo >&2
echo "laid out under $out_root" >&2
echo "these are what install.sh and \`repair\` copy from; nothing here is published." >&2