package commands

import (
	"os"
	"strings"
	"testing"
)

// `repair` reports what it FOUND before it reports what it did, AND IT REPAIRS.
//
// This used to be TestRepairPrintsWhatItFoundEvenWhenItCannotRun, and it required
// exit code 1 plus the line "no login on this device" on a machine with no account:
// there was no key to arm the guard with, so the listing was the whole value of the
// run. Every machine has no account now. The test passed, and what it was pinning
// was a `repair` command that could not repair anything on any machine.
//
// The listing is still the first thing checked, because it is still the part that
// says which client was unguarded — and it is what a person reads to find out that
// the thing they thought was installed was not.
func TestRepairReportsWhatItFoundAndThenFixesIt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("SOLONGATE_API_KEY", "")
	t.Setenv("SOLONGATE_NO_OS_LOCK", "1")
	t.Setenv("SOLONGATE_INTERNAL", "1") // this test is not the sudo check

	var code int
	_, e := capture(t, func() { code = RunRepair(nil) })
	if code != 0 {
		t.Fatalf("repair failed on a machine with no account: exit %d\n%s", code, e)
	}

	plain := ansi.ReplaceAllString(e, "")
	for _, want := range []string{
		"SolonGate repair",
		"before:",
		"guard hook file      MISSING",
		"Claude hooks         guard NOT registered",
		// What it did, which is the half that used to be unreachable.
		"restored:",
		"Claude hooks         guard registered",
		"guard repaired",
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("missing %q from the report:\n%s", want, plain)
		}
	}
	// NO ROW MAY MENTION AN ACCOUNT. The report carried a `cloud credential` row
	// that read MISSING on every machine, and a permanent red line in a report is
	// how a report stops being read.
	for _, gone := range []string{"credential", "login", "account"} {
		if strings.Contains(plain, gone) {
			t.Errorf("the report still talks about %q:\n%s", gone, plain)
		}
	}
	// And it really did arm the client, not just say so.
	if _, err := os.Stat(home + "/.claude/settings.json"); err != nil {
		t.Errorf("no Claude settings after a successful repair: %v", err)
	}
}
