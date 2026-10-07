// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// THE HELP MUST NOT NAME A COMMAND THIS BINARY DOES NOT HAVE.
//
// `solongate --help` listed, among others:
//
//	update auto on|off          background auto-update
//	browser status              the Shadow AI agent, and which browsers ask it
//	policy dry-run <id|file>    replay recent traffic against rules
//	audit whitelist <logId>     turn a denial into an ALLOW rule
//	sessions [--all]            live agent-session feed
//	session <id>                one session's detail
//
// None of them existed. Typing any one produced "Unknown command", from a list the
// program had just printed as its own. A footer underneath went further and said
// sessions, alerts and webhooks "run here".
//
// Help text is the one piece of documentation that ships INSIDE the thing it describes,
// so it is the one that has no excuse for being wrong. This reads the help the binary
// actually prints and checks every command in it against the table that dispatches them.
func TestEveryCommandInTheHelpExists(t *testing.T) {
	known := map[string]bool{}
	for _, c := range table() {
		known[c.name] = true
	}
	// Printed as the first line of the Setup section, meaning "run it with no command".
	known["solongate"] = true

	for _, name := range helpCommandNames(t) {
		if !known[name] {
			t.Errorf("the help offers %q, which is not a command — typing it answers "+
				"\"Unknown command\" from a list the program just printed", name)
		}
	}
}

// AND THE OTHER DIRECTION: a command nobody can find is nearly as bad as one that does
// not exist. `update` was added to the table and not to the help, so the command the
// health check tells people to run was absent from the list of commands.
func TestEveryCommandIsInTheHelp(t *testing.T) {
	listed := map[string]bool{}
	for _, name := range helpCommandNames(t) {
		listed[name] = true
	}

	for _, c := range table() {
		// `dataroom` is what running with no command does, and the help says so on its
		// own line rather than naming the subcommand.
		if c.name == "dataroom" {
			continue
		}
		if !listed[c.name] {
			t.Errorf("%q is a command and is not in the help, so the only way to find it "+
				"is to already know it is there", c.name)
		}
	}
}

// helpCommandNames is the first word of every cmd(...) line in the help source.
//
// Read from the source rather than by running printHelp: the output is coloured, wrapped
// and interleaved with headings, and a test that parsed it would be testing the
// formatting. The call sites are what has to stay true.
func helpCommandNames(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	start := strings.Index(src, "func printHelp()")
	if start < 0 {
		t.Fatal("printHelp is gone; this test and the help have to move together")
	}
	end := strings.Index(src[start:], "\n}\n")
	if end < 0 {
		t.Fatal("could not find the end of printHelp")
	}

	re := regexp.MustCompile(`cmd\("([^"]+)"`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(src[start:start+end], -1) {
		first := strings.Fields(m[1])
		if len(first) == 0 {
			continue
		}
		// Continuation lines describe a flag of the command above them.
		if strings.HasPrefix(first[0], "-") {
			continue
		}
		out = append(out, first[0])
	}
	if len(out) == 0 {
		t.Fatal("no commands found in the help; the parse is wrong, not the help")
	}
	return out
}
