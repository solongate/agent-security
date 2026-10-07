// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

// A rewrite is shallow-merged into the call's OWN arguments by the client. Sent
// under the guard's neutral name it adds an argument beside the one the client
// is really going to use, the call runs against the original file, and nothing
// reports a problem.
//
// That is the whole of the DLP read-redaction path on the two clients that
// cannot mask tool output: Antigravity sends AbsolutePath, OpenCode sends
// filePath, and both were handed back `file_path`. The agent then read the
// unredacted file while the guard believed it had replaced it.
func TestRewritePatchUsesTheNameTheClientSent(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     map[string]interface{}
		order    []string
		patch    map[string]interface{}
		wantKey  string
		wantGone string
	}{
		{
			name:     "antigravity read",
			args:     map[string]interface{}{"AbsolutePath": "/p/secrets/a.txt"},
			order:    []string{"AbsolutePath"},
			patch:    map[string]interface{}{"file_path": "/tmp/redacted"},
			wantKey:  "AbsolutePath",
			wantGone: "file_path",
		},
		{
			name:     "opencode read",
			args:     map[string]interface{}{"filePath": "/p/secrets/a.txt"},
			order:    []string{"filePath"},
			patch:    map[string]interface{}{"file_path": "/tmp/redacted"},
			wantKey:  "filePath",
			wantGone: "file_path",
		},
		{
			name:     "antigravity shell",
			args:     map[string]interface{}{"CommandLine": "ls -la"},
			order:    []string{"CommandLine"},
			patch:    map[string]interface{}{"command": "ls -la | grep -v x"},
			wantKey:  "CommandLine",
			wantGone: "command",
		},
		{
			name:    "a client that already speaks the neutral name is left alone",
			args:    map[string]interface{}{"file_path": "/p/secrets/a.txt"},
			order:   []string{"file_path"},
			patch:   map[string]interface{}{"file_path": "/tmp/redacted"},
			wantKey: "file_path",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			argOriginals = map[string]string{}
			neutralizeArgs(tc.args, tc.order)

			got := clientArgNames(tc.patch)
			if _, ok := got[tc.wantKey]; !ok {
				t.Errorf("patch does not carry %q: %v", tc.wantKey, got)
			}
			if tc.wantGone != "" {
				if _, ok := got[tc.wantGone]; ok {
					t.Errorf("patch still carries the neutral name %q, which the client ignores: %v", tc.wantGone, got)
				}
			}
			if len(got) != len(tc.patch) {
				t.Errorf("a rename must not change how many arguments are patched: %v", got)
			}
		})
	}
}

// Codex sends a bare `command` and needs it back unchanged; nothing was renamed
// on the way in, so nothing may be renamed on the way out.
func TestRewritePatchIsUntouchedWhenNothingWasRenamed(t *testing.T) {
	argOriginals = map[string]string{}
	neutralizeArgs(map[string]interface{}{"command": "cat x"}, []string{"command"})

	patch := map[string]interface{}{"command": "cat /tmp/redacted"}
	got := clientArgNames(patch)

	if got["command"] != "cat /tmp/redacted" || len(got) != 1 {
		t.Fatalf("patch changed: %v", got)
	}
}

// The alias that LOST the collision must not be the one written back to, or the
// rewrite lands on an argument the client is not reading.
func TestRewritePatchFollowsTheArgumentThatWon(t *testing.T) {
	argOriginals = map[string]string{}
	// `command` wins over `cmd` because it comes first in the payload.
	neutralizeArgs(
		map[string]interface{}{"CommandLine": "first", "cmd": "second"},
		[]string{"CommandLine", "cmd"},
	)

	got := clientArgNames(map[string]interface{}{"command": "rewritten"})
	if _, ok := got["CommandLine"]; !ok {
		t.Fatalf("want the winning argument name, got %v", got)
	}
}
