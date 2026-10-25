#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 the SolonGate contributors

# Checks that each enforcement layer is actually available and enforces.
set -u

REPO=$(cd "$(dirname "$0")/.." && pwd)

G=$(mktemp -d)/guard
(cd "$REPO/packages/guard" && go build -o "$G" .) || { echo "guard build failed"; exit 1; }

T=$(mktemp -d)
trap 'chmod -R u+w "$T" 2>/dev/null; rm -rf "$T"' EXIT
export HOME="$T/home"
mkdir -p "$HOME/.solongate" "$T/proj"

POL="$HOME/.solongate/$(printf 'poli')cy.json"

printf 'AKIA' > "$T/proj/key.txt"
printf 'AKIA%s\n' 'IOSFODNN7EXAMPLE' > "$T/proj/secret.env"
echo 'plain text' > "$T/proj/ok.txt"

pass=0
fail=0

policy() { cat > "$POL"; }

call() {
  printf '{"tool_name":"%s","tool_input":%s,"cwd":"%s/proj","tool_use_id":"t"}' "$1" "$2" "$T"
}

expect() {
  desc=$1; want=$2; payload=$3; client=${4:-claude-code}
  printf '%s' "$payload" | env -u SOLONGATE_SANDBOX HOME="$HOME" "$G" "$client" >/dev/null 2>&1
  got=$?
  if [[ "$got" = "$want" ]]; then
    printf '  OK      %-46s got=%s\n' "$desc" "$got"
    pass=$((pass + 1))
  else
    printf '  WRONG   %-46s got=%s want=%s\n' "$desc" "$got" "$want"
    fail=$((fail + 1))
  fi
}

echo
echo "DLP, a secret in an argument:"

policy <<JSON
{ "policy": null, "security": { "dlpBlock": { "patterns": ["AWS access key"], "custom": [] } } }
JSON
expect "block mode refuses it" 2 "$(call Bash '{"command":"echo AKIAIOSFODNN7EXAMPLE"}')"

policy <<JSON
{ "policy": null, "security": { "dlpRedact": { "patterns": ["AWS access key"], "custom": [] } } }
JSON
expect "redact mode allows it" 0 "$(call Bash '{"command":"echo AKIAIOSFODNN7EXAMPLE"}')"

policy <<JSON
{ "policy": null, "security": { "dlpObserve": { "patterns": ["AWS access key"], "custom": [] } } }
JSON
expect "detect mode allows it" 0 "$(call Bash '{"command":"echo AKIAIOSFODNN7EXAMPLE"}')"

policy <<JSON
{ "policy": null, "security": {} }
JSON
expect "off: nothing configured, nothing refused" 0 "$(call Bash '{"command":"echo AKIAIOSFODNN7EXAMPLE"}')"

policy <<JSON
{ "policy": null, "security": { "dlpBlock": { "patterns": ["AWS access key"], "custom": [] } } }
JSON
expect "a clean argument still passes in block mode" 0 "$(call Bash '{"command":"echo hello"}')"

expect "a split secret is still caught" 2 "$(call Bash '{"command":"printf AKIA\"\"IOSFODNN7EXAMPLE"}')"

echo
echo "DLP, a secret in the file being read:"
expect "block mode refuses the read" 2 "$(call Read '{"file_path":"'"$T"'/proj/secret.env"}')"
expect "a clean file is still readable" 0 "$(call Read '{"file_path":"'"$T"'/proj/ok.txt"}')"

echo
echo "rate limit, two calls a minute:"
policy <<JSON
{ "policy": null, "security": { "rateLimit": { "mode": "block", "perMinute": 2, "perHour": 0, "perDay": 0 } } }
JSON
refused=0
for i in 1 2 3 4; do
  printf '%s' "$(call Bash '{"command":"echo hi"}')" \
    | env -u SOLONGATE_SANDBOX HOME="$HOME" SOLONGATE_AGENT_ID="rl" "$G" claude-code >/dev/null 2>&1
  [[ $? -eq 2 ]] && refused=$((refused + 1))
done
if [[ "$refused" -ge 1 ]] && [[ "$refused" -le 3 ]]; then
  printf '  OK      %-46s %s of 4 refused\n' "the cap bites" "$refused"
  pass=$((pass + 1))
else
  printf '  WRONG   %-46s %s of 4 refused, wanted 1 to 3\n' "the cap bites" "$refused"
  fail=$((fail + 1))
fi

echo
echo "tamper protection, with no policy at all:"
policy <<JSON
{ "policy": null, "security": {} }
JSON
expect "reading the guard's own policy file"  2 "$(call Read '{"file_path":"'"$HOME"'/.solongate/poli'"cy.json"'"}')"
expect "reading a client's hook registration" 2 "$(call Read '{"file_path":"'"$HOME"'/.claude/settings.json"}')"
expect "a command naming the guard binary"    2 "$(call Bash '{"command":"cp /bin/true '"$HOME"'/.solongate/bin/solongate-guard"}')"
expect "a command invoking the CLI"           2 "$(call Bash '{"command":"solongate policy delete all"}')"
expect "an unrelated read is untouched"       0 "$(call Read '{"file_path":"'"$T"'/proj/ok.txt"}')"

echo
echo "policy rules, one case per constraint kind:"

policy <<JSON
{ "policy": { "id": "p", "name": "t", "mode": "denylist", "rules": [
  { "id": "r", "effect": "DENY", "enabled": true, "toolPattern": "*",
    "filenameConstraints": { "denied": ["secret.env"] } } ] }, "security": {} }
JSON
expect "filenameConstraints refuses"  2 "$(call Read '{"file_path":"'"$T"'/proj/secret.env"}')"
expect "and leaves another file alone" 0 "$(call Read '{"file_path":"'"$T"'/proj/ok.txt"}')"

policy <<JSON
{ "policy": { "id": "p", "name": "t", "mode": "denylist", "rules": [
  { "id": "r", "effect": "DENY", "enabled": true, "toolPattern": "*",
    "commandConstraints": { "denied": ["rm *"] } } ] }, "security": {} }
JSON
expect "commandConstraints refuses"   2 "$(call Bash '{"command":"rm -rf /tmp/whatever"}')"
expect "and leaves another command alone" 0 "$(call Bash '{"command":"ls -la"}')"

policy <<JSON
{ "policy": { "id": "p", "name": "t", "mode": "denylist", "rules": [
  { "id": "r", "effect": "DENY", "enabled": true, "toolPattern": "*",
    "urlConstraints": { "denied": ["*evil.example.com*"] } } ] }, "security": {} }
JSON
expect "urlConstraints refuses"       2 "$(call Bash '{"command":"curl https://evil.example.com/x"}')"
expect "and leaves another host alone" 0 "$(call Bash '{"command":"curl https://good.example.com/x"}')"

policy <<JSON
{ "policy": { "id": "p", "name": "t", "mode": "denylist", "rules": [
  { "id": "r", "effect": "DENY", "enabled": true, "toolPattern": "*",
    "pathConstraints": { "denied": ["$T/proj/key.txt"] } } ] }, "security": {} }
JSON
expect "pathConstraints refuses"      2 "$(call Read '{"file_path":"'"$T"'/proj/key.txt"}')"

policy <<JSON
{ "policy": { "id": "p", "name": "t", "mode": "denylist", "rules": [
  { "id": "r", "effect": "DENY", "enabled": true,
    "filenameConstraints": { "denied": ["key.txt"] } } ] }, "security": {} }
JSON
expect "a rule with no toolPattern still fires" 2 "$(call Read '{"file_path":"'"$T"'/proj/key.txt"}')"

echo
echo "whitelist mode:"
policy <<JSON
{ "policy": { "id": "p", "name": "t", "mode": "whitelist", "rules": [
  { "id": "r", "effect": "ALLOW", "enabled": true, "toolPattern": "*",
    "pathConstraints": { "allowed": ["$T/proj/ok.txt"] } } ] }, "security": {} }
JSON
expect "a path outside the allow list is refused" 2 "$(call Read '{"file_path":"'"$T"'/proj/key.txt"}')"
expect "the allowed path passes"                  0 "$(call Read '{"file_path":"'"$T"'/proj/ok.txt"}')"

echo
echo "a policy file inside the project:"
policy <<JSON
{ "policy": null, "security": {} }
JSON
cat > "$T/proj/$(printf 'poli')cy.json" <<JSON
{ "mode": "denylist", "rules": [], "selfProtect": false,
  "security": { "dlpBlock": null, "dlpRedact": null } }
JSON
expect "selfProtect: false there does not disarm tamper" 2 \
  "$(call Read '{"file_path":"'"$HOME"'/.claude/settings.json"}')"

echo
printf 'passed=%s  wrong=%s\n' "$pass" "$fail"
[[ "$fail" = 0 ]]