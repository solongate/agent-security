#!/usr/bin/env bash
# Does the Seatbelt profile this repository generates actually confine anything?
#
# MACOS ONLY, and it exists because nothing ever ran it. packages/sandbox has a
# Landlock file, a Seatbelt file, an icacls file and a fallback that refuses.
# Every CI job ran on ubuntu-latest, so the Seatbelt half was as good as
# whatever somebody last typed into it: it compiled, and that was the whole of
# what was known about it.
#
#   ./.sg-seatbelt-check.sh [/absolute/path/to/a/file/to/protect]
#
# It builds the CLI, protects one file through the policy file, and asks
# `solongate run` the questions the Linux side is already asked: can the agent
# read the protected file, delete it, reach it through a script it wrote, and do
# the ordinary things that have to keep working.
#
# WHAT IT DOES NOT COVER: the closed box. That is a Linux mount namespace and
# macOS has no equivalent, which is why `solongate sandbox` refuses here. This
# is about `solongate run`, the permission layer, which is what this platform
# can do.
set -u

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This check is for macOS. Seatbelt is the mechanism it exercises, and"
  echo "this machine is $(uname -s). On Linux run ./.sg-parity-check.sh and"
  echo "./.sg-box-check.sh instead."
  exit 0
fi

command -v sandbox-exec >/dev/null 2>&1 || {
  echo "sandbox-exec is not on PATH, so nothing can be confined here."
  echo "It ships with macOS; a machine without it cannot run the confinement."
  exit 1
}

REPO=$(cd "$(dirname "$0")" && pwd)

T=$(mktemp -d)
export HOME="$T/home"
mkdir -p "$HOME/.solongate" "$T/work"

PROTECTED=${1:-"$T/work/keep.c"}
case "$PROTECTED" in
  /*) ;;
  *) echo "give an absolute path"; exit 1 ;;
esac
mkdir -p "$(dirname "$PROTECTED")"
echo 'int main(){return 0;}' > "$PROTECTED"
echo 'sibling' > "$(dirname "$PROTECTED")/other.txt"

APP=$(mktemp -d)/solongate
(cd "$REPO/packages/app" && go build -o "$APP" .) || { echo "build failed"; exit 1; }

# The policy file is written directly rather than through `solongate protect`,
# which would want a terminal and, on macOS, would also apply chflags uchg. The
# OS lock is a separate mechanism with its own check; this is about what the
# profile denies.
python3 - "$HOME" "$PROTECTED" <<'PY'
import json, os, sys
path = os.path.join(sys.argv[1], '.solongate', 'poli' + 'cy.json')
json.dump({"policy": None, "security": {"protectedPaths": [sys.argv[2]]}}, open(path, 'w'))
PY

echo "protected: $PROTECTED"
echo

pass=0
fail=0
ask() { # ask LABEL EXPECT SHELL
  label=$1; expect=$2; code=$3
  got=$("$APP" run -- /bin/sh -c "$code" 2>/dev/null | tail -1)
  if [ "$got" = "$expect" ]; then
    printf '  OK      %-44s %s\n' "$label" "$got"; pass=$((pass+1))
  else
    printf '  WRONG   %-44s got %-6s wanted %s\n' "$label" "${got:-<nothing>}" "$expect"; fail=$((fail+1))
  fi
}

echo "the mechanism:"
"$APP" run --explain 2>&1 | sed 's/^/  /' | head -12
echo

echo "the protected file must be unreachable:"
ask "read it"                       NO "cat '$PROTECTED' >/dev/null 2>&1 && echo YES || echo NO"
ask "write it"                      NO "echo x > '$PROTECTED' 2>/dev/null && echo YES || echo NO"
ask "delete it"                     NO "rm -f '$PROTECTED' 2>/dev/null && test ! -e '$PROTECTED' && echo YES || echo NO"
ask "reach it through a symlink"    NO "ln -sf '$PROTECTED' '$T/work/link' 2>/dev/null; cat '$T/work/link' >/dev/null 2>&1 && echo YES || echo NO"
ask "a script it wrote reaches it"  NO "printf '#!/bin/sh\ncat %s\n' '$PROTECTED' > '$T/work/e.sh'; chmod +x '$T/work/e.sh'; '$T/work/e.sh' >/dev/null 2>&1 && echo YES || echo NO"
ask "find -delete over its folder"  NO "find '$(dirname "$PROTECTED")' -name '$(basename "$PROTECTED")' -delete 2>/dev/null; test -e '$PROTECTED' && echo NO || echo YES"

echo
echo "and the ordinary things must keep working:"
ask "read a sibling file"           YES "cat '$(dirname "$PROTECTED")/other.txt' >/dev/null 2>&1 && echo YES || echo NO"
ask "list the protected file's dir" YES "ls '$(dirname "$PROTECTED")' >/dev/null 2>&1 && echo YES || echo NO"
ask "write a new file beside it"    YES "echo x > '$(dirname "$PROTECTED")/new.txt' 2>/dev/null && echo YES || echo NO"
ask "read /etc/hosts"               YES "cat /etc/hosts >/dev/null 2>&1 && echo YES || echo NO"
ask "run a binary"                  YES "/usr/bin/true && echo YES || echo NO"
ask "write /tmp"                    YES "touch /tmp/sg-seatbelt-check 2>/dev/null && echo YES || echo NO"

echo
echo "the file survived:"
if [ -e "$PROTECTED" ]; then
  echo "  OK      it is still there"; pass=$((pass+1))
else
  echo "  WRONG   it is gone"; fail=$((fail+1))
fi

echo
echo "the closed box is not available here, and says so:"
out=$("$APP" sandbox --explain 2>&1 | head -3)
if printf '%s' "$out" | grep -qi 'not implemented\|mount namespace\|No closed box'; then
  printf '  OK      refuses with a reason\n'; pass=$((pass+1))
else
  printf '  WRONG   did not refuse: %s\n' "$(printf '%s' "$out" | tr '\n' ' ')"; fail=$((fail+1))
fi

echo
printf 'passed=%s  wrong=%s\n' "$pass" "$fail"
rm -f /tmp/sg-seatbelt-check
chmod -R u+w "$T" 2>/dev/null
rm -rf "$T"
[ "$fail" = 0 ]
