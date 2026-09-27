package store

import (
	"os"
	"regexp"
	"testing"
)

// THE FENCE BETWEEN THIS LIST AND THE GUARD'S.
//
// packages/guard-go/dlp.go carries the patterns a guarded machine actually
// scans with, and it gates every one of them on enabled[p.Name]. The enabled
// set comes from here: DLPPatternNames() is what a fresh project is given, what
// a stored subset is filtered through, and what the settings endpoint publishes
// as availablePatterns for a person to tick. So the two lists are one contract
// written in two files, and every way of breaking it is silent.
//
//	a name only the guard has     nobody can ever switch it on, because no
//	                              screen offers it and no stored subset can
//	                              legally contain it.
//	a name only this service has   a project enables it, this service publishes
//	                              it, and the guard finds nothing by that name
//	                              to turn on.
//	a name spelled differently    both of the above at once.
//
// That is exactly how fifty-six detectors came to ship on every machine in the
// fleet and be dead on all of them, for as long as this list stood at fourteen.
// Nothing errored, because nothing compares them at runtime. This does.
//
// THE ORDER IS PINNED TOO, and not for tidiness. Both scanners return the FIRST
// pattern that matches, so the order decides which name a piece of text is
// reported under when two patterns can both claim it. Two lists in different
// orders would report the same secret under two different names depending on
// which half of the product saw it.
//
// It reads the guard's source rather than importing it because guard-go is
// package main in another module. The same trick deploy_test.go uses on the
// Dockerfile, and it fails rather than skips when the file is missing: a sync
// test that quietly skips is the hole it was written to close.
//
// WHERE IT LOOKS, AND WHY THERE IS MORE THAN ONE PLACE. This runs in two very
// different trees. In a checkout the file is four directories up. In the api
// image it is at /packages/guard-go/dlp.go, because Dockerfile.system copies
// the module directories to the absolute path go.mod's relative replaces
// resolve to from /src. Hard-coding the checkout path made the first Railway
// build after this test was written fail on a missing file, which stops a
// deploy and leaves the last image that built still being served: the exact
// failure deploy_test.go exists to prevent, caused by its own neighbour.
func TestTheGuardsDLPPatternsAreThisList(t *testing.T) {
	var src []byte
	var err error
	for _, candidate := range []string{
		"../../../../packages/guard-go/dlp.go", // a checkout
		"/packages/guard-go/dlp.go",            // inside the api image
	} {
		if src, err = os.ReadFile(candidate); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("cannot read the guard's pattern list in any of the places it lives, so nothing is checking that it matches this one: %v", err)
	}

	// Each entry is `{"Name", regexp.MustCompile(...)}` on its own line. Only
	// the name is taken: the expressions are compiled separately on each side
	// and this service's copies carry (?i) in the CI field rather than inline.
	entry := regexp.MustCompile(`\{"([^"]+)", regexp\.MustCompile\(`)
	var want []string
	for _, m := range entry.FindAllStringSubmatch(string(src), -1) {
		want = append(want, m[1])
	}
	if len(want) == 0 {
		t.Fatal("no patterns were found in guard-go/dlp.go, so the shape this test parses has changed and it is now checking nothing")
	}

	got := DLPPatternNames()
	if len(got) != len(want) {
		t.Fatalf("the guard carries %d patterns and this service publishes %d, so %d of them can never be switched on",
			len(want), len(got), abs(len(want)-len(got)))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pattern %d is %q here and %q in guard-go/dlp.go", i, got[i], want[i])
		}
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// Every expression this service publishes has to compile, because two readers
// in this module compile them at request time and skip the ones that fail. A
// built-in that never compiles is a detector a person can tick and enable
// nothing with.
func TestEveryBuiltinDLPPatternCompiles(t *testing.T) {
	for _, p := range DLPPatterns {
		expr := p.Re
		if p.CI {
			expr = "(?i)" + expr
		}
		if _, err := regexp.Compile(expr); err != nil {
			t.Errorf("%q does not compile, so it silently matches nothing: %v", p.Name, err)
		}
	}
}
