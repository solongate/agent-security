// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

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

func TestTamperCheckBlocksReadsNotJustWrites(t *testing.T) {
	for _, tool := range []string{"Read", "Write", "Edit", "NotebookEdit"} {
		if tamperCheck(tool, map[string]interface{}{"file_path": policyFile()}) == "" {
			t.Errorf("%s on the policy file was allowed", tool)
		}
	}
}

func TestTamperCheckBasenamesAreScopedToOurDirectory(t *testing.T) {
	names := []string{"guar" + "d.mjs", "shie" + "ld.mjs", "solongate" + ".db"}

	for _, name := range names {
		inside := filepath.Join(tamperHome, ".solongate", name)
		if tamperCheck("Read", map[string]interface{}{"file_path": inside}) == "" {
			t.Errorf("a protected name inside our own directory was allowed: %s", inside)
		}

		outside := filepath.Join("/home/u/projects/x", name)
		if got := tamperCheck("Read", map[string]interface{}{"file_path": outside}); got != "" {
			t.Errorf("a file in somebody's own project was refused: %s said %q", outside, got)
		}
	}

	for _, name := range names {
		cmd := "cat /home/u/projects/x/" + name
		if tamperCheck("Bash", map[string]interface{}{"command": cmd}) == "" {
			t.Errorf("the command sweep missed a protected name: %s", cmd)
		}
	}
}

func TestTamperCheckLeavesAProjectsOwnPolicyFileAlone(t *testing.T) {
	theirs := "/home/u/projects/x/" + "poli" + "cy.json"
	if got := tamperCheck("Read", map[string]interface{}{"file_path": theirs}); got != "" {
		t.Errorf("a project's own file was refused because it shares our name: %q", got)
	}
	if tamperCheck("Read", map[string]interface{}{"file_path": policyFile()}) == "" {
		t.Error("ours, at its real path, was allowed")
	}
}

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

func TestTamperCheckLeavesOrdinaryWorkAlone(t *testing.T) {
	cases := []struct{ tool, key, val string }{
		{"Read", "file_path", "/home/u/projects/x/main.go"},
		{"Write", "file_path", "/home/u/projects/x/README.md"},
		{"Bash", "command", "go build ./..."},
		{"Bash", "command", "git commit -m \"a message\""},
		{"Bash", "command", "npm install"},
		{"Read", "file_path", "/etc/hostname"},

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

func TestTamperRefusalNamesTheLayer(t *testing.T) {
	got := tamperCheck("Read", map[string]interface{}{"file_path": policyFile()})
	if !strings.Contains(strings.ToLower(got), "tamper") {
		t.Errorf("the refusal does not name the layer: %q", got)
	}
}

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

		{"single quoted", "cat <<'EOF'\n", 6, "EOF", true},
		{"double quoted", "cat <<\"EOF\"\n", 6, "EOF", true},
		{"terminated by a pipe", "cat <<EOF|wc\n", 6, "EOF", false},
		{"terminated by a semicolon", "cat <<EOF;\n", 6, "EOF", false},

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

func TestNormTamperPath(t *testing.T) {
	ours := ".solon" + "gate"
	cases := []struct{ in, want string }{

		{"/Home/U/." + "Solongate" + "/Hooks", "/home/u/" + ours + "/hooks"},

		{`C:\Users\u\.solon` + `gate\hooks`, "c:/users/u/" + ours + "/hooks"},
		{"", ""},
	}
	for _, c := range cases {
		if got := normTamperPath(c.in); got != c.want {
			t.Errorf("normTamperPath(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}

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