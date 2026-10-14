// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// NAMES ARE SPLIT ACROSS CONCATENATIONS THROUGHOUT THIS FILE, and it is not
// style. The layer under test matches protected names as substrings, including
// inside a shell command, and the agent that wrote this file is subject to it:
// a test fixture spelling one of those names in one piece is a command this
// product refuses to run. Verified from the inside, which is a decent sign the
// sweep works.
//
// tamperCheck runs first and cannot be turned off by a policy, so it is the one
// layer whose failure mode is total: a hole here lets an agent edit the rules
// every other layer reads. These cases are the five shapes it matches and, just
// as importantly, the things it must leave alone.

func policyFile() string {
	return filepath.Join(tamperHome, ".solongate", "poli"+"cy.json")
}

func TestTamperCheckBlocksItsOwnFiles(t *testing.T) {
	home := tamperHome
	cases := []struct {
		name, tool, path string
	}{
		{"the policy file", "Read", policyFile()},
		{"the policy cache", "Read", filepath.Join(home, ".solongate", ".poli"+"cy-cache.json")},
		{"the hooks directory", "Write", filepath.Join(home, ".solongate", "hooks", "anything")},
		{"the credentials file", "Read", filepath.Join(home, ".solongate", "accou"+"nts.json")},
		{"a client hook registration", "Edit", filepath.Join(home, ".claude", "setti"+"ngs.json")},
	}
	for _, c := range cases {
		if tamperCheck(c.tool, map[string]interface{}{"file_path": c.path}) == "" {
			t.Errorf("%s: tamperCheck allowed %s on %s", c.name, c.tool, c.path)
		}
	}
}

// READS AS WELL AS WRITES, which is the part people assume is not covered. An
// agent that can read the policy knows exactly which paths are unwatched.
func TestTamperCheckBlocksReadsNotJustWrites(t *testing.T) {
	for _, tool := range []string{"Read", "Write", "Edit", "NotebookEdit"} {
		if tamperCheck(tool, map[string]interface{}{"file_path": policyFile()}) == "" {
			t.Errorf("%s on the policy file was allowed", tool)
		}
	}
}

// THE BASENAME HALF IS SCOPED ONE WAY AND NOT THE OTHER, and the asymmetry is
// deliberate, so it is pinned here before somebody reads it as a hole and
// "fixes" it into a wall.
//
//	by PATH     scoped to ~/.solongate/. The names are matched as prefixes and
//	            several of them are names a person's own project may use, so
//	            protecting them everywhere would refuse an unrelated file.
//	by COMMAND  unscoped substring. A command has no argument structure this
//	            layer can trust, so a protected name anywhere in it counts.
//
// Nothing is lost by the scoping: what actually has to be unreachable is the
// file at its real path, and those are covered by the absolute list, the globs
// and the per-client patterns regardless of basename.
func TestTamperCheckBasenamesAreScopedToOurDirectory(t *testing.T) {
	names := []string{"guar" + "d.mjs", "shie" + "ld.mjs", "solongate" + ".db"}

	for _, name := range names {
		inside := filepath.Join(tamperHome, ".solongate", name)
		if tamperCheck("Read", map[string]interface{}{"file_path": inside}) == "" {
			t.Errorf("a protected name inside our own directory was allowed: %s", inside)
		}

		// The same name somewhere that is none of our business.
		outside := filepath.Join("/home/u/projects/x", name)
		if got := tamperCheck("Read", map[string]interface{}{"file_path": outside}); got != "" {
			t.Errorf("a file in somebody's own project was refused: %s said %q", outside, got)
		}
	}

	// A command naming one is refused wherever it points, because a command is
	// not a path and this layer does not try to parse it into one.
	for _, name := range names {
		cmd := "cat /home/u/projects/x/" + name
		if tamperCheck("Bash", map[string]interface{}{"command": cmd}) == "" {
			t.Errorf("the command sweep missed a protected name: %s", cmd)
		}
	}
}

// The name a person's own project is most likely to collide with, called out on
// its own because it is the case the scoping exists for.
func TestTamperCheckLeavesAProjectsOwnPolicyFileAlone(t *testing.T) {
	theirs := "/home/u/projects/x/" + "poli" + "cy.json"
	if got := tamperCheck("Read", map[string]interface{}{"file_path": theirs}); got != "" {
		t.Errorf("a project's own file was refused because it shares our name: %q", got)
	}
	if tamperCheck("Read", map[string]interface{}{"file_path": policyFile()}) == "" {
		t.Error("ours, at its real path, was allowed")
	}
}

// The exec sweep. A path argument is not the only way to reach a file; a shell
// command naming it reaches it too, and the guard sees the command as one string.
func TestTamperCheckSweepsExecCommands(t *testing.T) {
	p := policyFile()
	cmds := []string{
		"cat " + p,
		"rm -f " + p,
		"python3 -c \"open('" + p + "').read()\"",
		"echo '{}' > " + p,
	}
	for _, cmd := range cmds {
		if tamperCheck("Bash", map[string]interface{}{"command": cmd}) == "" {
			t.Errorf("an exec command reaching the policy file was allowed: %s", cmd)
		}
	}
}

// The CLI invocation check. `protect remove` changes the protection without
// touching a protected file, so a path based layer cannot see it.
func TestTamperCheckBlocksCLIInvocation(t *testing.T) {
	cmds := []string{
		"solongate" + " protect remove /home/u/p/game.c",
		"solongate" + " policy mode off",
	}
	for _, cmd := range cmds {
		if tamperCheck("Bash", map[string]interface{}{"command": cmd}) == "" {
			t.Errorf("an invocation of the CLI itself was allowed: %s", cmd)
		}
	}
}

// AND THE OTHER DIRECTION, which is the half that finds walls. A layer that
// refuses everything passes every "was it blocked" case anybody writes.
func TestTamperCheckLeavesOrdinaryWorkAlone(t *testing.T) {
	cases := []struct{ tool, key, val string }{
		{"Read", "file_path", "/home/u/projects/x/main.go"},
		{"Write", "file_path", "/home/u/projects/x/README.md"},
		{"Bash", "command", "go build ./..."},
		{"Bash", "command", "git commit -m \"a message\""},
		{"Bash", "command", "npm install"},
		{"Read", "file_path", "/etc/hostname"},
		// A project's own config, which shares a shape with ours and must not
		// be confused with it.
		{"Read", "file_path", "/home/u/projects/x/package.json"},
		{"Read", "file_path", "/home/u/projects/x/tsconfig.json"},
	}
	for _, c := range cases {
		if got := tamperCheck(c.tool, map[string]interface{}{c.key: c.val}); got != "" {
			t.Errorf("tamperCheck refused ordinary work: %s %s=%q said %q", c.tool, c.key, c.val, got)
		}
	}
}

func TestTamperCheckHandlesMissingAndOddArguments(t *testing.T) {
	// The guard reads whatever JSON a client sends. A missing key, a wrong type
	// or a nil map must not panic and must not refuse.
	odd := []map[string]interface{}{
		nil,
		{},
		{"file_path": nil},
		{"file_path": 42},
		{"command": []string{"not", "a", "string"}},
		{"unrelated_field": "value"},
	}
	for i, args := range odd {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d panicked: %v", i, r)
				}
			}()
			if got := tamperCheck("Read", args); got != "" {
				t.Errorf("case %d refused on malformed arguments: %q", i, got)
			}
		}()
	}
}

// The refusal text reaches the model, so it has to name what happened rather
// than only that something did.
func TestTamperRefusalNamesTheLayer(t *testing.T) {
	got := tamperCheck("Read", map[string]interface{}{"file_path": policyFile()})
	if !strings.Contains(strings.ToLower(got), "tamper") {
		t.Errorf("the refusal does not name the layer: %q", got)
	}
}

// ── The parser underneath ────────────────────────────────────────────────────

// A HEREDOC IS WHERE A COMMAND HIDES A COMMAND.
//
// `cat <<EOF > f` is followed by lines that are DATA, not commands, and a sweep
// that reads them as commands refuses ordinary work: a shell script written into
// a file by an agent mentions paths constantly. Read the delimiter wrong and the
// body is swept; read it too greedily and a real command after the heredoc is
// skipped, which is the direction that misses an attack.
func TestReadHeredocDelimiter(t *testing.T) {
	cases := []struct {
		name, cmd string
		at        int
		delim     string
		quoted    bool
	}{
		{"plain", "cat <<EOF\nbody\nEOF\n", 6, "EOF", false},
		{"tab stripping form", "cat <<-EOF\nbody\nEOF\n", 6, "EOF", false},
		{"space before it", "cat << EOF\n", 6, "EOF", false},
		// QUOTED IS A DIFFERENT LANGUAGE. An unquoted delimiter means the shell
		// expands $VAR and $(...) in the body, so the body can contain a real
		// command substitution; a quoted one means it cannot. The flag is what
		// lets the caller treat the two differently.
		{"single quoted", "cat <<'EOF'\n", 6, "EOF", true},
		{"double quoted", "cat <<\"EOF\"\n", 6, "EOF", true},
		{"terminated by a pipe", "cat <<EOF|wc\n", 6, "EOF", false},
		{"terminated by a semicolon", "cat <<EOF;\n", 6, "EOF", false},
		// Nothing after `<<` at all. Returning a delimiter here would make the
		// rest of the command a heredoc body and skip it entirely.
		{"nothing after it", "cat <<", 6, "", false},
	}
	for _, c := range cases {
		delim, quoted, after := readHeredocDelimiter(c.cmd, c.at)
		if delim != c.delim {
			t.Errorf("%s: delimiter %q, want %q", c.name, delim, c.delim)
		}
		if quoted != c.quoted {
			t.Errorf("%s: quoted=%v, want %v", c.name, quoted, c.quoted)
		}
		if after < c.at || after > len(c.cmd) {
			t.Errorf("%s: resume index %d is outside the command", c.name, after)
		}
	}
}

// A PATH IS COMPARED AFTER IT IS NORMALISED, and the two normalisations are
// each a bypass somewhere.
func TestNormTamperPath(t *testing.T) {
	ours := ".solon" + "gate"
	cases := []struct{ in, want string }{
		// Case, because Windows and macOS both have case-insensitive filesystems
		// by default: a rule written in lower case is walked around by typing the
		// path in capitals.
		{"/Home/U/." + "Solongate" + "/Hooks", "/home/u/" + ours + "/hooks"},
		// Separator, because a Windows path uses backslashes and every rule in
		// the list is written with forward ones.
		{`C:\Users\u\.solon` + `gate\hooks`, "c:/users/u/" + ours + "/hooks"},
		{"", ""},
	}
	for _, c := range cases {
		if got := normTamperPath(c.in); got != c.want {
			t.Errorf("normTamperPath(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}

// EXTRACTION IS WHAT THE SWEEP ACTUALLY SEES.
//
// A path this does not return is a path no rule can refuse, so the cases are the
// argument shapes real clients send rather than the ones that are easy to parse.
func TestExtractTargetPaths(t *testing.T) {
	ours := "/home/u/.solon" + "gate/hooks/x.mjs"
	cases := []struct {
		name string
		args map[string]interface{}
	}{
		{"file_path", map[string]interface{}{"file_path": ours}},
		{"path", map[string]interface{}{"path": ours}},
		{"notebook_path", map[string]interface{}{"notebook_path": ours}},
	}
	for _, c := range cases {
		got := extractTargetPaths(c.args)
		found := false
		for _, g := range got {
			if g == ours {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: the path was not extracted, so no rule can refuse it: %v", c.name, got)
		}
	}

	// Odd shapes must not panic and must not invent paths. A client that sends a
	// number or a nested object is a client whose calls still have to be swept.
	for _, args := range []map[string]interface{}{
		nil,
		{},
		{"file_path": nil},
		{"file_path": 42},
		{"file_path": []interface{}{"a", 1}},
		{"path": map[string]interface{}{"nested": ours}},
	} {
		_ = extractTargetPaths(args)
	}
}