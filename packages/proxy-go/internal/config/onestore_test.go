package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ONE STORE PER DEVICE, whatever directory you are standing in and whichever copy
// of the program you ran.
//
// This is the property somebody asks about the moment they have the product in two
// places — a checkout they are developing in and the install on their PATH, or two
// clones side by side. If the policy, the audit trail and the per-project flags
// followed the working directory or the binary, those two copies would enforce
// different rules on the same machine and each would look correct from the inside.
//
// IT WAS NOT ALWAYS TRUE. An older guard kept its per-call flags in `./.solongate/`,
// beside whatever the agent happened to be working on, which scattered a dot-folder
// through every directory an agent had ever touched. sweepLegacyScratch in
// packages/guard-go still goes and removes what is left of it. That is what this
// test exists to stop coming back: it is cheap to reintroduce — one os.Getwd() in a
// path helper — and it would be invisible until two copies disagreed.
//
// So the claim is narrow and checked directly: every path this package hands out
// depends on the HOME directory and on nothing else.
func TestTheStoreIsPerDeviceAndNotPerCheckout(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Each entry is a path the program reads or writes. Anything that holds state and
	// is not in here is not covered, so a new store belongs in this list.
	paths := func() map[string]string {
		return map[string]string{
			"the store itself": Dir(),
			"hooks":            HooksDir(),
			"policy":           PolicyFilePath(),
			"credential":       CredentialPath(),
		}
	}

	// From one directory.
	first := paths()

	// And from a completely different one. os.UserHomeDir reads $HOME on this
	// platform, so the cd is the only thing that changes between the two calls.
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if err := os.Chdir(elsewhere); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	second := paths()

	for label, want := range first {
		if got := second[label]; got != want {
			t.Errorf("%s moved when the working directory did:\n  in %s: %s\n  in %s: %s\n"+
				"Two copies of SolonGate on one machine would now enforce different rules.",
				label, prev, want, elsewhere, got)
		}
	}

	// AND NONE OF THEM IS INSIDE A WORKING DIRECTORY. Equality above would also hold
	// if every path were hardcoded to the same wrong place, so this checks the shape:
	// the store lives under HOME, and nowhere near where anybody ran the program.
	for label, p := range second {
		if !strings.HasPrefix(p, home+string(filepath.Separator)) && p != home {
			t.Errorf("%s is %q, which is not under the home directory %q", label, p, home)
		}
		if strings.HasPrefix(p, elsewhere) || strings.HasPrefix(p, prev) {
			t.Errorf("%s is %q, which is inside a working directory", label, p)
		}
	}

	// ONE PATH IS DELIBERATELY NOT IN THE LIST ABOVE, and the distinction is the whole
	// design rather than an exception to it: WHICH project's flags you get depends on the
	// project you are standing in, WHERE they are kept does not.
	//
	// So ProjectFlagDir moves with the working directory — it has to, or two projects
	// would share one set of flags — but it never leaves the store.
	inElsewhere := ProjectFlagDir()
	if err := os.Chdir(prev); err != nil {
		t.Fatal(err)
	}
	inPrev := ProjectFlagDir()

	if inElsewhere == inPrev {
		t.Errorf("two different projects share one flag folder (%s), so per-project policy cannot work", inPrev)
	}
	for _, p := range []string{inElsewhere, inPrev} {
		if !strings.HasPrefix(p, Dir()+string(filepath.Separator)) {
			t.Errorf("a project's flag folder is outside the store:\n  %s\n  store: %s", p, Dir())
		}
	}
}
