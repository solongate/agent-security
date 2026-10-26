#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 the SolonGate contributors

# Runs the Go guard against fixture policies and checks the verdict each one produces. 
# Exit 2 means deny, 0 means allow. Builds the guard into a temp path if none is given.
set -u

REPO=$(cd "$(dirname "$0")/.." && pwd)
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

POL="$T/home/.solongate/$(printf 'policy').json"

pass=0
fail=0

note()  { printf '           %s\n' "$1"; }
ok()    { printf '  OK       %-44s %s\n' "$1" "${2:-}"; pass=$((pass+1)); }
bad()   { printf '  WRONG    %-44s %s\n' "$1" "${2:-}"; fail=$((fail+1)); }

expect() {
  local desc="$1" want="$2" payload="$3" client="$4"
  shift 4
  local out rc
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

call() {
  printf '{"tool_name":"%s","tool_input":%s,"cwd":"%s/proj","tool_use_id":"%s"}' "$1" "$2" "$T" "$3"
}

cd "$T/proj" || exit 1

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

cat > "$POL" <<JSON
{ "policy": { "id":"p1","name":"t","mode":"denylist","rules":[] },
  "security": { "protectedPaths": [], "requireSandbox": true } }
JSON

echo
echo "[2] require-sandbox"
expect "no marker -> refuse"      2 "$(call Read '{"file_path":"/etc/hostname"}' t5)" claude-code
expect "a forged marker is refused"  2 "$(call Read '{"file_path":"/etc/hostname"}' t6)" claude-code SOLONGATE_SANDBOX=1

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

cat > "$POL" <<JSON
{ "policy": { "id":"p1","name":"t","mode":"denylist","rules":[] },
  "security": { "protectedPaths": [], "requireSandbox": true } }
JSON

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
echo "This does not cover DLP, the rate limit, or the other policy constraint"
echo "kinds. See ./scripts/sg-layers-check.sh for those."
[[ "$fail" = 0 ]]