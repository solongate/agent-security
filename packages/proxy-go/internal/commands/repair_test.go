package commands

import (
	"os"
	"strings"
	"testing"
)

// `repair` reports what it FOUND before it reports what it did. A device with no
// account cannot be repaired — there is no key to arm the guard with — and the
// listing is the whole value of the run: it says which client was unguarded.
func TestRepairPrintsWhatItFoundEvenWhenItCannotRun(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("SOLONGATE_API_KEY", "")
	t.Setenv("SOLONGATE_API_URL", "http://127.0.0.1:1")
	t.Setenv("SOLONGATE_NO_OS_LOCK", "1")
	t.Setenv("SOLONGATE_INTERNAL", "1") // this test is not the sudo check

	var code int
	_, e := capture(t, func() { code = RunRepair(nil) })
	if code != 1 {
		t.Fatalf("a repair that could not run must exit non-zero, got %d", code)
	}

	plain := ansi.ReplaceAllString(e, "")
	for _, want := range []string{
		"SolonGate repair",
		"before:",
		"guard hook file      MISSING",
		"Claude hooks         guard NOT registered",
		"no login on this device",
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("missing %q from the report:\n%s", want, plain)
		}
	}
	if strings.Contains(plain, "restored:") {
		t.Errorf("nothing was restored, so nothing may claim it was:\n%s", plain)
	}
	if _, err := os.Stat(home + "/.claude"); err == nil {
		t.Error("a repair that could not run still touched the client configuration")
	}
}
