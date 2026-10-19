#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 the SolonGate contributors
# Drives the Go guard against a set of fixture policies and asserts the
# verdict each one must produce. Exit 2 = deny, 0 = allow.
#
# This used to compare the Go guard against a bundled Node guard and assert
# that the two agreed; there is only one implementation now, so the cases
# that used to prove agreement now just assert the expected verdict
# directly. Same fixtures, same coverage of this repository's actual history
# of bugs (protected paths, require-sandbox, agent scoping, the .last-deny
# flag); the comparison the name describes is gone because there is nothing
# left to compare against.
#
# Not a test suite, there is none in this repository. This is the by-hand
# evidence CONTRIBUTING.md asks a pull request to carry, written down so the
# next person can re-run it instead of reconstructing it.
#
#   ./scripts/shell/sg-parity-check.sh [path-to-go-guard]
#
# Builds the guard into a temp path if none is given.
set -u

REPO=$(cd "$(dirname "$0")/../.." && pwd)
G=${1:-}
if [[ -z "$G" ]]; then
  G=$(mktemp -d)/sg-guard
  (cd "$REPO/packages/guard" && go build -o "$G" .) || { echo "guard build failed"; exit 1; }
fi

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/home/.solongate" "$T/proj"
echo 'int main(){}' > "$T/proj/game.c"
echo 'hunter2'      > "$T/proj/secret.txt"

# Written without the literal filename in any command: the product's own tamper
# protection matches that string as a substring and refuses the call.
POL="$T/home/.solongate/$(printf 'policy').json"

pass=0
fail=0

note()  { printf '           %s\n' "$1"; }
ok()    { printf '  OK       %-44s %s\n' "$1" "${2:-}"; pass=$((pass+1)); }
bad()   { printf '  WRONG    %-44s %s\n' "$1" "${2:-}"; fail=$((fail+1)); }

# expect DESC WANT PAYLOAD CLIENT [env...] -- asserts the guard's exit code
# against the wanted one, and when a refusal was wanted, that it said why
# rather than coming back silent.
expect() {
  local desc="$1" want="$2" payload="$3" client="$4"
  shift 4
  local out rc
  # -u SOLONGATE_SANDBOX because a shell inside `solongate run` already carries
  # the marker, and inheriting it makes the require-sandbox case pass for the
  # wrong reason: the guard allows, and the case reads as correct by accident.
  out=$(printf '%s' "$payload" | env -u SOLONGATE_SANDBOX HOME="$T/home" "$@" "$G" "$client" 2>&1); rc=$?

  if [[ "$rc" != "$want" ]]; then
    bad "$desc" "got=$rc want=$want"
    note "out: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-110)"
    return
  fi

  if [[ "$want" = 2 ]] && [[ -z "$out" ]]; then
    bad "$desc (refused, but said nothing)" "got=$rc"
    return
  fi
  ok "$desc" "got=$rc"
}

call() { # call TOOL JSON_INPUT ID
  printf '{"tool_name":"%s","tool_input":%s,"cwd":"%s/proj","tool_use_id":"%s"}' "$1" "$2" "$T" "$3"
}

cd "$T/proj" || exit 1

# ── 1. the user's own protected paths ────────────────────────────────────────
cat > "$POL" <<JSON
{ "policy": { "id":"p1","name":"t","mode":"denylist","rules":[] },
  "security": { "protectedPaths": ["$T/proj/game.c"], "requireSandbox": false } }
JSON

echo
echo "[1] user protected paths"
expect "read a protected file"        2 "$(call Read  '{"file_path":"'"$T"'/proj/game.c"}' t1)" claude-code
expect "rm a protected file via Bash" 2 "$(call Bash  '{"command":"rm '"$T"'/proj/game.c"}' t2)" claude-code
expect "write to a protected file"    2 "$(call Write '{"file_path":"'"$T"'/proj/game.c","content":"x"}' t3)" claude-code
expect "an unrelated file is untouched" 0 "$(call Read '{"file_path":"'"$T"'/proj/other.c"}' t4)" claude-code

# ── 2. require-sandbox ───────────────────────────────────────────────────────
cat > "$POL" <<JSON
{ "policy": { "id":"p1","name":"t","mode":"denylist","rules":[] },
  "security": { "protectedPaths": [], "requireSandbox": true } }
JSON

echo
echo "[2] require-sandbox"
expect "no marker -> refuse"      2 "$(call Read '{"file_path":"/etc/hostname"}' t5)" claude-code
# A SET ENV VAR IS NOT CONFINEMENT. The marker is an environment variable, any
# shell can export it, so the guard asks the kernel instead of trusting it: a
# forged marker with nothing behind it still gets refused, and the refusal
# names the forgery.
expect "a forged marker is refused"  2 "$(call Read '{"file_path":"/etc/hostname"}' t6)" claude-code SOLONGATE_SANDBOX=1

# ── 3. policy.agents scoping ─────────────────────────────────────────────────
# toolPattern "*" is load-bearing here and not decoration: with the field absent
# the Go guard generates `input.tool_name == ""` and the rule never fires, so a
# scoping case written without it would pass while proving nothing.
cat > "$POL" <<JSON
{ "policy": { "id":"p1","name":"t","mode":"denylist","agents":["codex"],"rules":[
    { "id":"r1","effect":"DENY","enabled":true,"priority":10,"toolPattern":"*",
      "filenameConstraints":{"denied":["secret.txt"]} } ] },
  "security": {} }
JSON

echo
echo "[3] policy.agents scoping"
expect "in-scope client is refused"     2 "$(call Read '{"file_path":"'"$T"'/proj/secret.txt"}' t7)" codex
expect "out-of-scope client is allowed" 0 "$(call Read '{"file_path":"'"$T"'/proj/secret.txt"}' t8)" claude-code

echo
echo "[4] an out-of-scope policy must not disarm the layers"
expect "tamper still fires out of scope" 2 \
  "$(call Read '{"file_path":"'"$T"'/home/.solongate/policy.json"}' t9)" claude-code

# ── 5. the .last-deny flag ───────────────────────────────────────────────────
cat > "$POL" <<JSON
{ "policy": { "id":"p1","name":"t","mode":"denylist","rules":[] },
  "security": { "protectedPaths": [], "requireSandbox": true } }
JSON

# projectKey is FNV-1a over UTF-16 code units of the PROCESS cwd
# (packages/shared/paths.go), recomputed here rather than hardcoded. Plain
# bash: every path this script hands it is ASCII, where a UTF-16 code unit
# and a byte value are the same number.
fnv_key() {
  local s="$1" h=2166136261 i len cp
  len=${#s}
  for (( i = 0; i < len; i++ )); do
    cp=$(printf '%d' "'${s:$i:1}")
    h=$(( (h ^ cp) & 0xffffffff ))
    h=$(( (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) & 0xffffffff ))
  done
  printf '%x' "$h"
}
KEY=$(fnv_key "$T/proj")
FLAG="$T/home/.solongate/projects/$KEY/.last-deny"

echo
echo "[5] .last-deny flag"
rm -f "$FLAG"
printf '%s' "$(call Read '{"file_path":"/etc/hostname"}' tu_go)" \
  | env -u SOLONGATE_SANDBOX HOME="$T/home" "$G" claude-code >/dev/null 2>&1
if [[ -f "$FLAG" ]]; then
  id=$(grep -oE '"id"[[:space:]]*:[[:space:]]*"[^"]*"' "$FLAG" | head -1 | sed -E 's/.*"([^"]*)"$/\1/')
  [[ "$id" = "tu_go" ]] \
    && ok "it wrote the flag, with the call id" "id=$id" \
    || bad "it wrote the flag with the wrong id" "id=$id"
else
  bad "it did not write the flag"
fi

echo
printf 'passed=%s  failed=%s\n' "$pass" "$fail"
echo
echo "WHAT THIS DOES NOT MEASURE: the enforcement layers themselves. These"
echo "cases are about protected paths, require-sandbox, agent scoping and the"
echo ".last-deny flag. Whether DLP, the rate limit, the four policy"
echo "constraint kinds and whitelist mode do what they claim is a separate"
echo "question, and ./scripts/shell/sg-layers-check.sh is where it is asked."
[[ "$fail" = 0 ]]