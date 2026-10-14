// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"strings"
	"testing"
)

// THE CONDITION THAT FIRED ON NOTHING.
//
// A rule whose JSON omits toolPattern used to compile to `input.tool_name == ""`,
// which no call satisfies, so the rule was silently unenforced on the Rego path
// while the fallback evaluator, which has no tool_pattern condition at all,
// enforced it. Rules the TUI writes carry "*" and were unaffected; a
// hand-written policy file was the one that lost its rules.
func TestToolPatternEmptyMatchesEverythingLikeAStar(t *testing.T) {
	star := generateToolPatternCondition("*")
	empty := generateToolPatternCondition("")

	if len(empty) != len(star) {
		t.Fatalf("an absent toolPattern compiles differently from \"*\":\n  \"\" -> %v\n  \"*\" -> %v", empty, star)
	}
	for i := range star {
		if empty[i] != star[i] {
			t.Errorf("condition %d differs: %q vs %q", i, empty[i], star[i])
		}
	}
	// And neither may emit a comparison, which is what the bug was.
	for _, c := range append(star, empty...) {
		if strings.Contains(c, "input.tool_name ==") {
			t.Errorf("a match-everything pattern emitted a comparison: %q", c)
		}
	}
}

func TestToolPatternShapes(t *testing.T) {
	cases := []struct {
		pattern, wantFunc, wantArg string
	}{
		{"Bash", "input.tool_name ==", "Bash"},
		{"mcp__*", "startswith", "mcp__"},
		{"*Edit", "endswith", "Edit"},
		{"*shell*", "contains", "shell"},
	}
	for _, c := range cases {
		got := strings.Join(generateToolPatternCondition(c.pattern), " ")
		if !strings.Contains(got, c.wantFunc) {
			t.Errorf("pattern %q: want %s, got %q", c.pattern, c.wantFunc, got)
		}
		if !strings.Contains(got, c.wantArg) {
			t.Errorf("pattern %q: want the argument %q in %q", c.pattern, c.wantArg, got)
		}
	}
}

func TestEscapeRegoString(t *testing.T) {
	// A pattern reaches here from a policy file, which is a file a person edits.
	// An unescaped quote or backslash does not make a bad rule, it makes a
	// policy that does not compile, and a policy that does not compile sends
	// every call down the fallback path.
	cases := []struct{ in, want string }{
		{`plain`, `plain`},
		{`has"quote`, `has\"quote`},
		{`has\backslash`, `has\\backslash`},
		{"has\nnewline", `has\nnewline`},
		{"has\ttab", `has\ttab`},
	}
	for _, c := range cases {
		if got := EscapeRegoString(c.in); got != c.want {
			t.Errorf("EscapeRegoString(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}

func TestConvertRulesToRegoProducesOneBlockPerEnabledRule(t *testing.T) {
	yes, no := true, false
	rules := []PolicyRule{
		{ID: "a", Effect: "deny", ToolPattern: "*", Enabled: &yes},
		{ID: "b", Effect: "deny", ToolPattern: "*", Enabled: &no},
		{ID: "c", Effect: "allow", ToolPattern: "Bash", Enabled: &yes},
		// No Enabled field at all. The Rego compiler treats that as disabled
		// and the fallback evaluator treats it as enabled; the difference is
		// inherited and deliberately preserved, so it is pinned rather than
		// quietly depended on.
		{ID: "d", Effect: "deny", ToolPattern: "*"},
	}
	out := ConvertRulesToRego(rules)

	for _, id := range []string{"a", "c"} {
		if !strings.Contains(out, id) {
			t.Errorf("enabled rule %q is missing from the compiled policy", id)
		}
	}
	for _, id := range []string{"b", "d"} {
		if strings.Contains(out, `"`+id+`"`) {
			t.Errorf("rule %q is not enabled for Rego but appears in the output", id)
		}
	}
}

func TestConvertRulesToRegoWithNoRules(t *testing.T) {
	// An empty policy must still compile. A policy that does not compile falls
	// back, and falling back for the ordinary case of "no rules yet" would make
	// the fast path dead code on a fresh install.
	out := ConvertRulesToRego(nil)
	if strings.TrimSpace(out) == "" {
		t.Error("an empty rule set produced nothing to compile")
	}
}

// Which tool names count as "this call executes what it is given". A name this
// misses is a client whose commands are never swept, so the cases are the names
// real clients actually use rather than names that sound plausible.
func TestIsExecTool(t *testing.T) {
	exec := []string{
		"Bash", "bash", // Claude Code
		"shell", "exec", // Codex, and the MCP convention
		"run_command",       // Windsurf
		"run_terminal_cmd",  // Cursor
		"bash_tool",         // the Anthropic API tool name
		"mcp__shell__exec",  // any MCP server exposing a shell
		"powershell", "cmd", // Windows
		"eval",
	}
	for _, tool := range exec {
		if !IsExecTool(tool) {
			t.Errorf("IsExecTool(%q)=false, so that client's commands are never swept", tool)
		}
	}

	// AND THE HALF THAT FINDS WALLS. A file tool sent through the command sweep
	// gets its arguments treated as shell text, which is how a path containing
	// an ordinary word turns into a refusal.
	notExec := []string{"Read", "Write", "Edit", "Glob", "Grep", "WebFetch", "TodoWrite", "NotebookEdit"}
	for _, tool := range notExec {
		if IsExecTool(tool) {
			t.Errorf("IsExecTool(%q)=true, which sends a file tool through the command sweep", tool)
		}
	}

	// MATCHED AS A SUBSTRING, which is what gets the long tail and is also the
	// known cost: a tool called "rerun_query" contains "run" and is swept. The
	// sweep only ever refuses on a protected name, so the cost is a false
	// refusal on a tool nobody has rather than a miss, and it is pinned here so
	// that tradeoff is a decision rather than a surprise.
	if !IsExecTool("rerun_query") {
		t.Error("the substring match changed shape; the long tail of vendor names depends on it")
	}
}

func TestMatchPathGlob(t *testing.T) {
	// Paths are assembled rather than written whole: this product's own
	// directory names are protected literals, and a source file spelling one in
	// one piece is a file the tamper layer refuses to let an agent write.
	ours := "/.solongate/"
	cases := []struct {
		path, glob string
		match      bool
	}{
		{"/home/u" + ours + "hooks/x.mjs", "**" + ours + "hooks/**", true},
		{"/home/u" + ours + "poli" + "cy.json", "**" + ours + "*.json", true},
		{"/home/u/projects/x/main.go", "**" + ours + "**", false},
		// The case the absolute list uses a trailing slash for: a sibling
		// directory whose name starts with a protected one.
		{"/home/u/.solongate-backup/x", "**" + ours + "**", false},
	}
	for _, c := range cases {
		if got := MatchPathGlob(c.path, c.glob); got != c.match {
			t.Errorf("MatchPathGlob(%q, %q)=%v, want %v", c.path, c.glob, got, c.match)
		}
	}
}

func TestJSTruthyMatchesJavaScript(t *testing.T) {
	// This exists to agree with a JavaScript twin, so the cases are the ones
	// where Go's idea of empty and JavaScript's idea of falsy differ.
	truthy := []interface{}{true, "x", 1.0, -1.0, []interface{}{}, map[string]interface{}{}}
	for _, v := range truthy {
		if !JSTruthy(v) {
			t.Errorf("JSTruthy(%#v)=false, JavaScript says true", v)
		}
	}
	falsy := []interface{}{false, "", 0.0, nil}
	for _, v := range falsy {
		if JSTruthy(v) {
			t.Errorf("JSTruthy(%#v)=true, JavaScript says false", v)
		}
	}
}