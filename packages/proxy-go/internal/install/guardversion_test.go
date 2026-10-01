package install

import (
	"os"
	"path/filepath"
	"testing"
)

// THE GUARD'S VERSION NUMBERS HAVE TO COME FROM SOMEWHERE.
//
// internal/api declares GuardVersions as a function variable whose comment says the
// install layer fills it in. Nothing did. It kept its default of (0, nil) on every
// machine, so everything reading it believed the installed guard was unknown and the
// newest available was zero — which the live view renders literally as `hooks v? → v0`:
// a permanent warning that the guard is out of date, naming a version that cannot
// exist, on an install made seconds earlier.
//
// It survived because `solongate doctor` reads the local file itself rather than
// trusting that variable. The command whose whole job is to say whether the guard is
// healthy had its own copy of the answer, so the broken path had no visible symptom
// anywhere a test was looking.
//
// This checks the two readers the wiring is built from, against files on disk.
func TestTheGuardVersionsAreReadableFromDisk(t *testing.T) {
	home := sandbox(t)
	haveHookSources(t)

	// NOTHING INSTALLED YET. Nil, not zero: the difference is "no guard here" versus
	// "a guard at version zero", and treating the first as the second is what produced
	// the upgrade prompt that started this.
	if v := InstalledGuardVersion(); v != nil {
		t.Errorf("with no guard installed, InstalledGuardVersion() = %d, want nil", *v)
	}

	// The version this build would install, read from the packaged source.
	shipped := ShippedGuardVersion()
	if shipped == nil {
		t.Fatal("ShippedGuardVersion() is nil even though the hook sources are present, " +
			"so nothing can ever report a newest version")
	}
	if *shipped <= 0 {
		t.Fatalf("ShippedGuardVersion() = %d; a hook version is a positive number", *shipped)
	}

	if r := Install(); !r.OK {
		t.Fatalf("install failed: %+v", r)
	}

	// AND AFTER AN INSTALL THE TWO AGREE, because the installer writes the shipped
	// file. A machine that just installed is by definition current, and any difference
	// here means the installed guard is not the one this build ships.
	installed := InstalledGuardVersion()
	if installed == nil {
		t.Fatalf("after installing, the guard at %s has no readable HOOK_VERSION",
			filepath.Join(home, ".solongate", "hooks"))
	}
	if *installed != *shipped {
		t.Errorf("installed v%d but this build ships v%d — an install should leave them equal,\n"+
			"and anything comparing them will report a fresh install as out of date",
			*installed, *shipped)
	}
}

// A guard file with no version in it reads as "cannot tell", not as version zero.
//
// Same distinction as above, from the other side: a truncated or half-written hook
// must not report a number, because a number is something the rest of the product
// compares against.
func TestAnUnreadableGuardHasNoVersionRatherThanZero(t *testing.T) {
	home := sandbox(t)
	hooks := filepath.Join(home, ".solongate", "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(GlobalPaths().GuardPath(), []byte("// truncated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v := InstalledGuardVersion(); v != nil {
		t.Errorf("a guard file with no HOOK_VERSION reported v%d, want nil", *v)
	}
}
