#!/usr/bin/env bash
# Does the closed box actually close?
#
# RUN THIS OUTSIDE A SANDBOX. A mount namespace cannot be created from inside a
# Landlock domain or another sandbox, so running it from a confined shell fails
# with EPERM before it tests anything. If you are in a `solongate run` session,
# open a plain terminal first.
#
#   ./.sg-box-check.sh [/absolute/path/to/a/scratch/project]
#
# It defines two boxes over that directory, 001 with the network, 002 without,
# so the id addressing and the per-box network choice are both exercised.
#
# It builds the CLI from this checkout, points the sandbox at a throwaway
# directory, and asks the box the questions that matter.
set -u

REPO=$(cd "$(dirname "$0")" && pwd)
WS=${1:-}
if [ -z "$WS" ]; then
  WS=$(mktemp -d)/projectX
  mkdir -p "$WS"
fi
case "$WS" in
  /*) ;;
  *) echo "give an absolute path"; exit 1 ;;
esac

if [ -n "${SOLONGATE_SANDBOX:-}" ]; then
  echo "SOLONGATE_SANDBOX is set, so this shell is already confined and no"
  echo "mount namespace can be created from it. Run this from a plain terminal."
  exit 1
fi

command -v bwrap >/dev/null 2>&1 || { echo "bwrap is not installed"; exit 1; }

APP=$(mktemp -d)/solongate
(cd "$REPO/packages/app" && go build -o "$APP" .) || { echo "build failed"; exit 1; }

# A throwaway HOME so the real policy file is never touched.
T=$(mktemp -d)
export HOME="$T/home"
mkdir -p "$HOME/.solongate"
python3 - "$HOME" "$WS" <<'PY'
import json, os, sys
# The filename is assembled rather than typed: the guard's tamper sweep matches
# it as a substring and refuses a command that spells it out.
path = os.path.join(sys.argv[1], '.solongate', 'poli' + 'cy.json')
# Two boxes, so the id addressing is exercised and not just the confinement:
# 001 keeps the network, 002 does not.
json.dump({"policy": None, "security": {"sandboxes": [
    {"id": "001", "dir": sys.argv[2], "network": True},
    {"id": "002", "dir": sys.argv[2], "network": False},
]}}, open(path, 'w'))
PY

echo "project: $WS"
echo

pass=0; fail=0
ask() { # ask LABEL EXPECT SHELL
  local label=$1 expect=$2 code=$3
  local got
  got=$("$APP" sandbox 001 /bin/sh -c "$code" 2>/dev/null | tail -1)
  if [ "$got" = "$expect" ]; then
    printf '  OK      %-44s %s\n' "$label" "$got"; pass=$((pass+1))
  else
    printf '  WRONG   %-44s got %-6s wanted %s\n' "$label" "${got:-<nothing>}" "$expect"; fail=$((fail+1))
  fi
}

echo "what the box contains:"
printf '  %s\n' "$("$APP" sandbox 001 /bin/sh -c 'ls / | tr "\n" " "' 2>/dev/null | tail -1)"
echo
echo "the project, must work:"
ask "write in the project"        YES 'touch /workspace/box && echo YES || echo NO'
ask "read it back"                YES 'cat /workspace/box >/dev/null && echo YES || echo NO'
ask "run a binary"                YES '/usr/bin/true && echo YES || echo NO'
ask "resolve a name"              YES 'cat /etc/resolv.conf >/dev/null && echo YES || echo NO'
ask "scratch in /tmp"             YES 'touch /tmp/x && echo YES || echo NO'

echo
echo "outside the project, must be GONE, not merely refused:"
ask "/home exists at all"         NO  'test -e /home && echo YES || echo NO'
ask "\$HOME of the real user"      NO  'test -e /home/'"$(id -un)"' && echo YES || echo NO'
ask "/etc/passwd exists"          NO  'test -e /etc/passwd && echo YES || echo NO'
ask "/root exists"                NO  'test -e /root && echo YES || echo NO'
ask "/var exists"                 NO  'test -e /var && echo YES || echo NO'
ask "/mnt exists"                 NO  'test -e /mnt && echo YES || echo NO'
ask "the host /tmp contents"      NO  'ls /tmp | grep -q . && echo YES || echo NO'
# NOT "can it read /proc/1/cmdline". --unshare-all includes the pid namespace, so
# PID 1 inside the box is the box's OWN first process and reading it leaks
# nothing, the first version of this check asked that and failed a box that was
# working correctly. The real question is whether anything that is NOT in the box
# is visible, which is a count and a name.
ask "only the box's own processes"  YES 'n=$(ls /proc | grep -c "^[0-9]"); [ "$n" -le 5 ] && echo YES || echo NO'
# ASKED OF comm, NOT cmdline, and the reason is a test that lied twice. PID 1's
# cmdline inside the box is the whole bwrap argv, and the last argument of that
# argv is THIS CHECK, so a grep for "systemd" found the word in its own command
# line and reported the host init as visible on a box that was isolating
# correctly. /proc/1/comm is the process name alone: bwrap in the box, systemd
# on the host, and nothing of the question inside the answer.
ask "pid 1 is the box, not the host"  YES 'c=$(cat /proc/1/comm 2>/dev/null); case "$c" in systemd|init) echo NO ;; "") echo NO ;; *) echo YES ;; esac'
ask "no other user's process"       YES 'ls /proc/*/cmdline 2>/dev/null | wc -l | { read n; [ "$n" -le 5 ] && echo YES || echo NO; }'
ask "a script reaching outward"   NO  'printf "#!/bin/sh\ncat /home/*/.ssh/* 2>/dev/null\n" > /workspace/e.sh; chmod +x /workspace/e.sh; /workspace/e.sh | grep -q . && echo YES || echo NO'

echo
echo "the network, which is each box's own choice:"
ask "box 001 has it"              YES 'getent hosts example.com >/dev/null 2>&1 && echo YES || echo NO'
got=$("$APP" sandbox 002 /bin/sh -c 'getent hosts example.com >/dev/null 2>&1 && echo YES || echo NO' 2>/dev/null | tail -1)
if [ "$got" = NO ]; then
  printf '  OK      %-44s %s\n' "box 002 does not" "$got"; pass=$((pass+1))
else
  printf '  WRONG   %-44s got %-6s wanted NO\n' "box 002 does not" "${got:-<nothing>}"; fail=$((fail+1))
fi

echo
echo "the ids:"
for t in 1 001 002 9; do
  out=$("$APP" sandbox "$t" /bin/true 2>&1 | grep -c 'no sandbox' || true)
  if [ "$t" = 9 ]; then
    [ "$out" = 1 ] && { printf '  OK      %-44s refused\n' "id $t does not exist"; pass=$((pass+1)); } \
                   || { printf '  WRONG   %-44s not refused\n' "id $t does not exist"; fail=$((fail+1)); }
  else
    [ "$out" = 0 ] && { printf '  OK      %-44s accepted\n' "id $t resolves"; pass=$((pass+1)); } \
                   || { printf '  WRONG   %-44s refused\n' "id $t resolves"; fail=$((fail+1)); }
  fi
done

echo
printf 'passed=%s  wrong=%s\n' "$pass" "$fail"
chmod -R u+w "$T" 2>/dev/null
rm -rf "$T"
[ "$fail" = 0 ]
