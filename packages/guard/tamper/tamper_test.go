// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tamper

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
		{"the policy signing key", "Read", filepath.Join(home, ".solongate", "crypto", "machine"+".key")},
		{"the policy verification key", "Write", filepath.Join(home, ".solongate", "crypto", "machine"+".pub")},
		{"the key directory", "Read", filepath.Join(home, ".solongate", "crypto")},
	}
	for _, c := range cases {
		if Check(c.tool, map[string]interface{}{"file_path": c.path}) == "" {
			t.Errorf("%s: Check allowed %s on %s", c.name, c.tool, c.path)
		}
	}
}

func TestTamperCheckBlocksReadsNotJustWrites(t *testing.T) {
	for _, tool := range []string{"Read", "Write", "Edit", "NotebookEdit"} {
		if Check(tool, map[string]interface{}{"file_path": policyFile()}) == "" {
			t.Errorf("%s on the policy file was allowed", tool)
		}
	}
}

func TestTamperCheckBasenamesAreScopedToOurDirectory(t *testing.T) {
	names := []string{"solongate" + "-guard", "solongate" + ".exe", "solongate" + ".db"}

	for _, name := range names {
		inside := filepath.Join(tamperHome, ".solongate", name)
		if Check("Read", map[string]interface{}{"file_path": inside}) == "" {
			t.Errorf("a protected name inside our own directory was allowed: %s", inside)
		}

		outside := filepath.Join("/home/u/projects/x", name)
		if got := Check("Read", map[string]interface{}{"file_path": outside}); got != "" {
			t.Errorf("a file in somebody's own project was refused: %s said %q", outside, got)
		}
	}

	for _, name := range names {
		cmd := "cat /home/u/projects/x/" + name
		if Check("Bash", map[string]interface{}{"command": cmd}) == "" {
			t.Errorf("the command sweep missed a protected name: %s", cmd)
		}
	}
}

func TestTamperCheckLeavesAProjectsOwnPolicyFileAlone(t *testing.T) {
	theirs := "/home/u/projects/x/" + "poli" + "cy.json"
	if got := Check("Read", map[string]interface{}{"file_path": theirs}); got != "" {
		t.Errorf("a project's own file was refused because it shares our name: %q", got)
	}
	if Check("Read", map[string]interface{}{"file_path": policyFile()}) == "" {
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
		if Check("Bash", map[string]interface{}{"command": cmd}) == "" {
			t.Errorf("an exec command reaching the policy file was allowed: %s", cmd)
		}
	}
}

// Issue #216: machine.key signs policy.json, so reading it out lets an agent
// sign a forged policy that passes verification.
func TestTamperCheckBlocksTheSigningKeys(t *testing.T) {
	keyDir := "/home/u/.solon" + "gate/crypto"
	paths := []string{keyDir, keyDir + "/machine" + ".key", keyDir + "/machine" + ".pub"}
	for _, p := range paths {
		if Check("Read", map[string]interface{}{"file_path": p}) == "" {
			t.Errorf("Check allowed reading %s", p)
		}
	}

	cmds := []string{
		"cat ~/.solon" + "gate/crypto/machine" + ".key",
		"cp /tmp/forged ~/.solon" + "gate/crypto/machine" + ".pub",
		"rm -rf ~/.solon" + "gate/crypto",
		"tar czf /tmp/k.tgz ~/.solon" + "gate/crypto",
		"cat ~/.solon" + "gate/*/machine" + ".key",
	}
	for _, cmd := range cmds {
		if Check("Bash", map[string]interface{}{"command": cmd}) == "" {
			t.Errorf("an exec command reaching the signing keys was allowed: %s", cmd)
		}
	}

	if got := Check("Read", map[string]interface{}{"file_path": "/home/u/projects/x/crypto/keys.go"}); got != "" {
		t.Errorf("a project's own crypto directory was refused: %q", got)
	}
}

func TestTamperCheckBlocksCLIInvocation(t *testing.T) {
	cmds := []string{
		"solongate" + " protect remove /home/u/p/game.c",
		"solongate" + " policy mode off",
	}
	for _, cmd := range cmds {
		if Check("Bash", map[string]interface{}{"command": cmd}) == "" {
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
		if got := Check(c.tool, map[string]interface{}{c.key: c.val}); got != "" {
			t.Errorf("Check refused ordinary work: %s %s=%q said %q", c.tool, c.key, c.val, got)
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
			if got := Check("Read", args); got != "" {
				t.Errorf("case %d refused on malformed arguments: %q", i, got)
			}
		}()
	}
}

func TestTamperRefusalNamesTheLayer(t *testing.T) {
	got := Check("Read", map[string]interface{}{"file_path": policyFile()})
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
		{"", "."},

		// Dot-segment paths must be cleaned (vulnerability fix).
		{"/home/u/." + "claude/./setti" + "ngs.json", "/home/u/.claude/settings.json"},
		{"/home/u/." + "claude/foo/../setti" + "ngs.json", "/home/u/.claude/settings.json"},
		{"/home/u/." + "solon" + "gate/./hooks/guard.mjs", "/home/u/" + ours + "/hooks/guard.mjs"},
	}
	for _, c := range cases {
		if got := NormPath(c.in); got != c.want {
			t.Errorf("NormPath(%q)=%q, want %q", c.in, got, c.want)
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
		got := ExtractTargetPaths(c.args)
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
		_ = ExtractTargetPaths(args)
	}
}

// --- Regression tests for the 8 tamper guard security fixes ---

func TestTamperCheckBlocksDotSegmentBypass(t *testing.T) {
	// Fix 1: NormPath must clean dot-segments so /./  and /../
	// do not evade the protected path lists.
	cases := []struct {
		name, path string
	}{
		{"dot-segment on Claude settings",
			tamperHome + "/.claude/./setti" + "ngs.json"},
		{"parent-segment on Claude settings",
			tamperHome + "/.claude/x/../setti" + "ngs.json"},
		{"dot-segment on SolonGate hook",
			tamperHome + "/.solon" + "gate/./hooks/guard.mjs"},
		{"dot-segment on Antigravity hooks",
			tamperHome + "/.gemini/config/./hooks.json"},
		{"dot-segment on Codex hooks",
			tamperHome + "/.codex/./hooks.json"},
	}
	for _, c := range cases {
		if got := Check("Write", map[string]interface{}{"file_path": c.path}); got == "" {
			t.Errorf("%s: Check allowed dot-segment bypass on %s", c.name, c.path)
		}
	}
}

func TestTamperCheckBlocksOpenCodePlugin(t *testing.T) {
	// Fix 2: OpenCode's SolonGate plugin must be protected.
	plugin := tamperHome + "/.config/opencode/plugins/solon" + "gate.js"

	if Check("Write", map[string]interface{}{"file_path": plugin}) == "" {
		t.Error("Check allowed writing to the OpenCode plugin file")
	}
	if Check("Bash", map[string]interface{}{"command": "rm " + plugin}) == "" {
		t.Error("Check allowed shell deletion of the OpenCode plugin file")
	}
}

func TestTamperCheckBlocksRelativePathWithCwd(t *testing.T) {
	// Fix 3: relative paths must be resolved against cwd.
	cwd := tamperHome + "/.claude"
	if Check("Write", map[string]interface{}{"file_path": "setti" + "ngs.json"}, cwd) == "" {
		t.Error("Check allowed relative path settings.json with cwd=~/.claude")
	}
	// Absolute paths should not be affected by cwd.
	if Check("Write", map[string]interface{}{"file_path": "/home/u/projects/readme.md"}, cwd) != "" {
		t.Error("Check refused an absolute path to an unprotected file")
	}
}

func TestTamperCheckBlocksCdSplitEvasion(t *testing.T) {
	// Fix 4: cd into a protected directory followed by file operations
	// must be blocked even when the path regex does not join them.
	cmds := []string{
		"cd ~/.claude && rm setti" + "ngs.json",
		"cd ~/.solon" + "gate && rm -rf hooks/",
		"cd ~/.codex && cat hooks.json",
		"cd ~/.gemini/config && rm hooks.json",
	}
	for _, cmd := range cmds {
		if Check("Bash", map[string]interface{}{"command": cmd}) == "" {
			t.Errorf("Check allowed cd-split evasion: %s", cmd)
		}
	}
}

func TestTamperCheckExtractsStringArrayPaths(t *testing.T) {
	// Fix 5: string items in []interface{} arrays must be extracted.
	args := map[string]interface{}{
		"file_path": []interface{}{tamperHome + "/.solon" + "gate/poli" + "cy.json"},
	}
	if Check("Write", args) == "" {
		t.Error("Check allowed a string array containing a protected path")
	}
}

func TestTamperCheckRecognizesAdditionalPathFields(t *testing.T) {
	// Fix 6: DirectoryPath, SearchPath, and file must be recognized.
	fields := []struct{ key, path string }{
		{"DirectoryPath", tamperHome + "/.solon" + "gate/hooks"},
		{"SearchPath", tamperHome + "/.solon" + "gate/bin"},
		{"file", tamperHome + "/.claude/setti" + "ngs.json"},
	}
	for _, f := range fields {
		if Check("list_dir", map[string]interface{}{f.key: f.path}) == "" {
			t.Errorf("Check allowed %s=%s", f.key, f.path)
		}
	}
}

func TestTamperCheckRecognizesShTool(t *testing.T) {
	// Fix 7: tool names sh, zsh, terminal must be classified as exec tools.
	for _, tool := range []string{"sh", "zsh", "dash", "terminal"} {
		if Check(tool, map[string]interface{}{"command": "rm " + policyFile()}) == "" {
			t.Errorf("Check allowed exec command via tool %q", tool)
		}
	}
}

func TestTamperCheckExtractsNestedMapPaths(t *testing.T) {
	// Fix 5b: paths nested one level deep in map arguments must be extracted.
	args := map[string]interface{}{
		"params": map[string]interface{}{
			"file_path": tamperHome + "/.claude/setti" + "ngs.json",
		},
	}
	if Check("custom_tool", args) == "" {
		t.Error("Check allowed a nested map containing a protected path")
	}
}

func TestTamperCheckExtractsBatchPaths(t *testing.T) {
	// Paths in 'paths' array must be extracted and blocked.
	args := map[string]interface{}{
		"paths": []interface{}{tamperHome + "/.solon" + "gate/poli" + "cy.json"},
	}
	if Check("batch_write", args) == "" {
		t.Error("Check allowed batch_write with protected paths array")
	}
}
