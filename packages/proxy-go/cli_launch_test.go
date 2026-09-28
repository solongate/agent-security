package main

// The npm wrapper's list of commands it hands to this binary, and this binary's
// own table, have to be the same list.
//
// WHEN THEY ARE NOT, THE COMMAND EXISTS AND NOBODY CAN RUN IT. `browser` was in
// the table here, dispatched correctly, and worked when the binary was invoked
// directly - and `solongate browser launch`, which is what a person actually
// types, printed "Unknown command: browser", because the wrapper did not
// delegate it and the TypeScript CLI behind it has never heard of it.
//
// The comment above that list already claimed the two match. Nothing checked,
// so the claim was true on the day it was written and false a release later.

import (
	"os"
	"regexp"
	"testing"
)

func TestTheWrapperHandsOverEveryCommandThisBinaryOwns(t *testing.T) {
	// The wrapper lives in the sibling npm package, which is not there when
	// this test runs inside a built image. That is the one place the check
	// cannot help and also the one place the mismatch cannot be introduced.
	src, err := os.ReadFile("../proxy/src/cli-launch.ts")
	if err != nil {
		t.Skip("not run from a checkout")
	}

	block := regexp.MustCompile(`(?s)GO_SUBCOMMANDS = new Set\(\[(.*?)\]\)`).FindSubmatch(src)
	if block == nil {
		t.Fatal("the wrapper's command list could not be found, so nothing here is being checked")
	}
	delegated := map[string]bool{}
	for _, m := range regexp.MustCompile(`'([a-z-]+)'`).FindAllSubmatch(block[1], -1) {
		delegated[string(m[1])] = true
	}
	if len(delegated) == 0 {
		t.Fatal("the wrapper delegates nothing, which cannot be right")
	}

	// The TypeScript CLI's own dispatcher. A command it implements is REACHABLE
	// whether or not the wrapper delegates it - `trace` lives in
	// both and runs on the TypeScript path on purpose - so the invariant is not
	// "everything is delegated". It is that a command which exists ONLY in Go
	// must be, or nothing can run it.
	ts, err := os.ReadFile("../proxy/src/commands/index.ts")
	if err != nil {
		t.Skip("not run from a checkout")
	}
	inTS := map[string]bool{}
	for _, m := range regexp.MustCompile(`case '([a-z-]+)':`).FindAllSubmatch(ts, -1) {
		inTS[string(m[1])] = true
	}

	for _, c := range table() {
		// login is a pointer to a removed command; the wrapper carries it in
		// GO_INFO_ARGS rather than the subcommand set.
		if c.name == "login" {
			continue
		}
		if !delegated[c.name] && !inTS[c.name] {
			t.Errorf("`solongate %s` exists only in Go and is not delegated, so it reaches the "+
				"TypeScript CLI and answers \"Unknown command\": add %q to GO_SUBCOMMANDS in "+
				"packages/proxy/src/cli-launch.ts", c.name, c.name)
		}
	}

	// And the other way, because a name the wrapper hands over that this binary
	// does not have is the same failure with the error printed by the other
	// half: the Go CLI's own "Unknown command".
	own := map[string]bool{}
	for _, c := range table() {
		own[c.name] = true
	}
	for name := range delegated {
		// dataroom is the bare invocation, which the wrapper names explicitly
		// and the table reaches through no entry of its own.
		if name == "dataroom" {
			continue
		}
		if !own[name] {
			t.Errorf("the wrapper hands `%s` to this binary, which has no such command", name)
		}
	}
}
