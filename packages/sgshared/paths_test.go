package sgshared

import "testing"

// These values come from running the JavaScript, not from running this package.
// That direction is the whole point: the Node guard, the audit hook and the
// dataroom write these files today, so where the two disagree the JavaScript is
// right and this is the bug.
//
//	node -e 'function k(d){let h=0x811c9dc5;const s=String(d||"");
//	  for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);
//	  h=(h+((h<<1)+(h<<4)+(h<<7)+(h<<8)+(h<<24)))>>>0}return h.toString(16)}
//	  console.log(k("/home/müşteri/proj"))'
func TestProjectKeyMatchesJavaScript(t *testing.T) {
	for dir, want := range map[string]string{
		"/home/user/proj":    "52e82b15",
		"/home/müşteri/proj": "98d8e9fc",
		"/home/坂本/proj":      "596d4ea2",
	} {
		if got := ProjectKey(dir); got != want {
			t.Errorf("ProjectKey(%q) = %s, JavaScript computes %s.\n"+
				"This names a DIRECTORY: the guard would write its flags where nothing "+
				"else looks, and nothing would report an error.", dir, got, want)
		}
	}
}

// node -e 'console.log(String("ünlü").replace(/[^a-zA-Z0-9_-]/g,"_"))'
func TestAgentKeyMatchesJavaScript(t *testing.T) {
	for agent, want := range map[string]string{
		"claude-code": "claude-code",
		"my agent":    "my_agent",
		"ünlü":        "_nl_",
		// Outside the basic plane: the JavaScript regex works on UTF-16 units, so
		// a surrogate pair is two replacements. Ranging over runes gives one.
		"a😀b": "a__b",
		"":    "default",
	} {
		if got := AgentKey(agent); got != want {
			t.Errorf("AgentKey(%q) = %q, JavaScript computes %q", agent, got, want)
		}
	}
}

func TestIsRealKeyRefusesPlaceholders(t *testing.T) {
	real := "sg_live_" + "abcdef0123456789abcdef0123456789"
	for k, want := range map[string]bool{
		real:                            true,
		"sg_test_" + "abcdef0123456789": true,
		"sg_live_your_key_here":         false,
		"sg_live_placeholder1234":       false,
		"sg_live_example00000000":       false,
		"sg_live_short":                 false,
		"not-a-key":                     false,
		"":                              false,
	} {
		if got := IsRealKey(k); got != want {
			t.Errorf("IsRealKey(%q) = %v, want %v — a key that fails this reads as "+
				"'no project selected', which means allow", k, got, want)
		}
	}
}

// The classifier decides input.permission, so a rule scoped to WRITE fires or
// does not fire on these answers.
func TestGuessPermission(t *testing.T) {
	for tool, want := range map[string]string{
		"bash":        "EXECUTE",
		"run_command": "EXECUTE",
		"apply_patch": "WRITE", // Codex sends every file edit under this one name
		"applypatch":  "WRITE",
		"Write":       "WRITE",
		"Edit":        "WRITE",
		"WebFetch":    "NETWORK",
		"websearch":   "NETWORK",
		"Read":        "READ",
		"Glob":        "READ",
	} {
		if got := GuessPermission(tool); got != want {
			t.Errorf("GuessPermission(%q) = %q, want %q", tool, got, want)
		}
	}
}

// The classifier reads a tool NAME, so a client that spells an edit differently
// gets a different permission class -- and one direction of that is a hole
// rather than an inconvenience.
//
// Antigravity's edit tool is `replace_file_content`. It matched none of the
// write words and fell through to READ, so a rule scoped to WRITE over a
// directory missed the tool the agent actually edits with: "deny writes under
// config/" left the agent free to rewrite config/. Found in a live run, from
// `solongate trace` reporting PERM=READ next to a successful edit.
func TestEditToolsClassifyAsWriteWhateverTheyAreCalled(t *testing.T) {
	for _, name := range []string{
		"replace_file_content", "write_to_file", "Write", "Edit", "MultiEdit",
		"apply_patch", "str_replace_editor", "modify_file", "append_to_file",
		"create_file", "delete_file", "rename_file", "move_file",
	} {
		if got := GuessPermission(name); got != "WRITE" {
			t.Errorf("GuessPermission(%q) = %q, want WRITE", name, got)
		}
	}
}

// The classes are ordered, and a name carrying two words takes the earlier
// branch. `run_command` is EXECUTE even though a command can write, because
// what the guard can see in it is a command line, not a path.
func TestPermissionOrderingSurvivesAmbiguousNames(t *testing.T) {
	for name, want := range map[string]string{
		"run_command":      "EXECUTE",
		"shell":            "EXECUTE",
		"bash":             "EXECUTE",
		"webfetch":         "NETWORK",
		"read_url_content": "READ", // no network word in it; measured, not desired
		"view_file":        "READ",
		"list_dir":         "READ",
		"grep_search":      "READ",
	} {
		if got := GuessPermission(name); got != want {
			t.Errorf("GuessPermission(%q) = %q, want %q", name, got, want)
		}
	}
}
