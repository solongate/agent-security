// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"strings"
	"testing"
)

func TestLauncherScriptEmbedsTheGuardBinary(t *testing.T) {
	s := launcherScript("/opt/solongate/bin/solongate-guard")
	if !strings.HasPrefix(s, "#!/bin/sh\n") {
		t.Fatalf("launcherScript() does not start with a shebang: %q", s[:40])
	}
	if !strings.Contains(s, `gobin='/opt/solongate/bin/solongate-guard'`) {
		t.Errorf("launcherScript() does not embed the guard binary path: %s", s)
	}
}

func TestLauncherScriptEscapesSingleQuotesInPath(t *testing.T) {
	s := launcherScript(`/opt/it's/guard`)
	if !strings.Contains(s, `gobin='/opt/it'\''s/guard'`) {
		t.Errorf("launcherScript() did not escape the single quote in the binary path: %s", s)
	}
}

func TestLauncherScriptHandlesEachHookKind(t *testing.T) {
	s := launcherScript("/bin/guard")
	for _, want := range []string{
		`kind="${1:-}"`,
		`--sg-doctor`,
		`case "$kind" in`,
		`guard) echo "solongate: this tool call is REFUSED, the guard is fail-closed." >&2; exit 2 ;;`,
		`exec "$gobin" "$@"`,
		`exec "$gobin" "$kind" "$@"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("launcherScript() is missing expected fragment %q", want)
		}
	}
}

func TestLauncherScriptIsValidPOSIXShellShape(t *testing.T) {
	s := launcherScript("/bin/guard")
	if strings.Count(s, "if [") != strings.Count(s, "fi\n") {
		t.Errorf("launcherScript() has mismatched if/fi: %d if vs %d fi", strings.Count(s, "if ["), strings.Count(s, "fi\n"))
	}
	if !strings.HasSuffix(s, "\n") {
		t.Error("launcherScript() should end with a trailing newline (it is a shell script written to disk)")
	}
}