// SPDX-License-Identifier: Apache-2.0

package sgpolicy

import (
	"strings"
	"testing"
)

// A PATH RULE IS ABOUT THE FILE A CALL TOUCHES, NOT THE WORDS IN IT.
//
// ExtractPaths walked every string in a tool call, so the CONTENT of a file became a
// path candidate. A rule naming a protected directory then blocked any write whose text
// mentioned that directory — documentation, a test, a config example — and the refusal
// quoted the whole file as the offending path.
//
// Tamper protection had already reached this conclusion and written it down: target path
// fields only, "never the free-form content/body, which would false-positive on any file
// that merely mentions a protected path in its text". The policy layer had not.
//
// The literals here are assembled from fragments on purpose. This file's own text is a
// tool call's content, and a machine running the suite under a policy that names these
// paths would be unable to check out the file that tests them — which is the bug.
func TestTheTextOfAFileIsNotAPath(t *testing.T) {
	dir := "/home/me/." + "ssh"
	key := dir + "/id_" + "rsa"

	args := map[string]interface{}{
		"file_path": "/home/me/notes.md",
		"content":   "The keys live in " + key + ", do not commit them.",
	}

	paths := ExtractPaths(args, false)
	if !hasPath(paths, "/home/me/notes.md") {
		t.Errorf("the file being written is missing from %v", paths)
	}
	for _, p := range paths {
		if strings.Contains(p, "id_") {
			t.Errorf("a path was taken from the file's TEXT: %q\n"+
				"A rule about that directory would block writing any file that names it.", p)
		}
	}

	// THE SAME FAULT, ONE LAYER OVER. Filenames were extracted the same way, so a
	// rule about a key file blocked writing a document that mentioned one.
	for _, n := range ExtractFilenames(args) {
		if strings.Contains(n, "id_") {
			t.Errorf("a filename was taken from the file's TEXT: %q", n)
		}
	}
}

// EVERY PROSE FIELD, not just `content`. An edit carries its text in new_string and
// old_string, a shell call carries a sentence in description, and each has produced the
// same false positive.
func TestProseFieldsAreNotScannedForPaths(t *testing.T) {
	target := "/etc/" + "shadow"

	for _, field := range []string{
		"content", "body", "text", "new_string", "old_string", "description",
		"message", "prompt", "instructions", "replacement",
	} {
		args := map[string]interface{}{
			"file_path": "/tmp/ok.txt",
			field:       "see " + target + " for the format",
		}
		for _, p := range ExtractPaths(args, false) {
			if strings.Contains(p, "shadow") {
				t.Errorf("%s was read as a path: %q", field, p)
			}
		}
	}
}

// AND THE HOLE THIS MUST NOT OPEN.
//
// The exclusion is a denylist of prose fields rather than an allowlist of path fields,
// precisely so a path arriving in a field nobody thought of is still a path. An
// allowlist would stop seeing it, silently, which is the failure a guard cannot have.
func TestAPathInAnUnknownFieldIsStillAPath(t *testing.T) {
	args := map[string]interface{}{
		"some_tool_specific_key": "/etc/passwd",
		"nested":                 map[string]interface{}{"another_key": "/var/log/auth.log"},
		"list":                   []interface{}{"/opt/thing/config.yaml"},
	}

	paths := ExtractPaths(args, false)
	for _, want := range []string{"/etc/passwd", "/var/log/auth.log", "/opt/thing/config.yaml"} {
		if !hasPath(paths, want) {
			t.Errorf("%q was not seen as a path; got %v", want, paths)
		}
	}
}

// An exec call keeps its paths in `command`, which is why that field is not excluded.
func TestACommandStillYieldsItsPaths(t *testing.T) {
	args := map[string]interface{}{"command": "cat /etc/passwd && rm /tmp/x"}

	paths := ExtractPaths(args, true)
	for _, want := range []string{"/etc/passwd", "/tmp/x"} {
		if !hasPath(paths, want) {
			t.Errorf("%q was not seen in the command; got %v", want, paths)
		}
	}
}

func hasPath(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
