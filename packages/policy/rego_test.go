// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package policy

import (
	"strings"
	"testing"
)

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

	out := ConvertRulesToRego(nil)
	if strings.TrimSpace(out) == "" {
		t.Error("an empty rule set produced nothing to compile")
	}
}

func TestIsExecTool(t *testing.T) {
	exec := []string{
		"Bash", "bash",
		"shell", "exec",
		"run_command",
		"run_terminal_cmd",
		"bash_tool",
		"mcp__shell__exec",
		"powershell", "cmd",
		"eval",
	}
	for _, tool := range exec {
		if !IsExecTool(tool) {
			t.Errorf("IsExecTool(%q)=false, so that client's commands are never swept", tool)
		}
	}

	notExec := []string{"Read", "Write", "Edit", "Glob", "Grep", "WebFetch", "TodoWrite", "NotebookEdit"}
	for _, tool := range notExec {
		if IsExecTool(tool) {
			t.Errorf("IsExecTool(%q)=true, which sends a file tool through the command sweep", tool)
		}
	}

	if !IsExecTool("rerun_query") {
		t.Error("the substring match changed shape; the long tail of vendor names depends on it")
	}
}

func TestMatchPathGlob(t *testing.T) {

	ours := "/.solongate/"
	cases := []struct {
		path, glob string
		match      bool
	}{
		{"/home/u" + ours + "hooks/x.mjs", "**" + ours + "hooks/**", true},
		{"/home/u" + ours + "poli" + "cy.json", "**" + ours + "*.json", true},
		{"/home/u/projects/x/main.go", "**" + ours + "**", false},

		{"/home/u/.solongate-backup/x", "**" + ours + "**", false},
	}
	for _, c := range cases {
		if got := MatchPathGlob(c.path, c.glob); got != c.match {
			t.Errorf("MatchPathGlob(%q, %q)=%v, want %v", c.path, c.glob, got, c.match)
		}
	}
}

func TestJSTruthyMatchesJavaScript(t *testing.T) {

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
