// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build !windows

package observability

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/shared"
)

type rawTraceLine struct {
	TS   int64  `json:"ts"`
	Tool string `json:"tool"`
	Cwd  string `json:"cwd"`
}

// writeRing writes a .eval-ring.jsonl file under dir with one JSON line per
// record, creating dir if necessary.
func writeRing(t *testing.T, dir string, recs ...rawTraceLine) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, r := range recs {
		line, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, ".eval-ring.jsonl"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCountCell(t *testing.T) {
	zero := 0
	five := 5
	cases := []struct {
		name string
		n    *int
		want string
	}{
		{"nil", nil, "-"},
		{"pointer to zero", &zero, "0"},
		{"pointer to positive number", &five, "5"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCell(c.n); got != c.want {
				t.Errorf("countCell(...) = %q, want %q", got, c.want)
			}
		})
	}
}

func TestReadTraceRingMissingFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := readTraceRing(dir); err == nil {
		t.Fatal("expected an error for a directory with no .eval-ring.jsonl file")
	}
}

func TestReadTraceRingSortsAndSkipsMalformed(t *testing.T) {
	dir := t.TempDir()
	content := strings.Join([]string{
		`{"ts":1000,"tool":"Bash","cwd":"/a"}`,
		`not json`,
		`{"ts":3000,"tool":"Write","cwd":"/a"}`,
		``,
		`{"ts":2000,"tool":"Read","cwd":"/a"}`,
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, ".eval-ring.jsonl"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, err := readTraceRing(dir)
	if err != nil {
		t.Fatalf("readTraceRing: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3 (the malformed and blank lines skipped)", len(recs))
	}
	if recs[0].TS != 3000 || recs[1].TS != 2000 || recs[2].TS != 1000 {
		t.Errorf("records not sorted by TS descending: %+v", recs)
	}
}

func TestReadAllTraceRings(t *testing.T) {
	t.Run("no projects directory at all", func(t *testing.T) {
		newHome(t)
		recs := readAllTraceRings()
		if len(recs) != 0 {
			t.Errorf("got %d records, want 0 when projects/ does not exist", len(recs))
		}
	})

	t.Run("merges and sorts across projects", func(t *testing.T) {
		newHome(t)
		root := filepath.Join(shared.SGDir(), "projects")
		writeRing(t, filepath.Join(root, "proj-a"),
			rawTraceLine{TS: 1000, Tool: "Bash", Cwd: "/a"},
			rawTraceLine{TS: 3000, Tool: "Write", Cwd: "/a"},
		)
		writeRing(t, filepath.Join(root, "proj-b"),
			rawTraceLine{TS: 2000, Tool: "Read", Cwd: "/b"},
		)
		recs := readAllTraceRings()
		if len(recs) != 3 {
			t.Fatalf("got %d records, want 3", len(recs))
		}
		if recs[0].TS != 3000 || recs[1].TS != 2000 || recs[2].TS != 1000 {
			t.Errorf("records not merged and sorted by TS descending: %+v", recs)
		}
	})
}

func TestSameDir(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{"identical", "/home/user/project", "/home/user/project", true},
		{"trailing slash is ignored", "/home/user/project/", "/home/user/project", true},
		{"backslash normalized to forward slash", `C:\Users\me\project`, "C:/Users/me/project", true},
		{"different directories", "/home/user/a", "/home/user/b", false},
		{"both empty do not compare equal", "", "", false},
		{"one empty", "/home/user", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sameDir(c.a, c.b); got != c.want {
				t.Errorf("sameDir(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
			}
		})
	}
}

func TestRunTraceHelp(t *testing.T) {
	newHome(t)
	c := client.New()
	code, err := RunTrace(context.Background(), c, cliutil.Parse([]string{"help"}))
	if err != nil {
		t.Fatalf("RunTrace(help): %v", err)
	}
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
}

func TestRunTraceUnknownSub(t *testing.T) {
	newHome(t)
	c := client.New()
	var code int
	var err error
	out := captureFD(t, 2, func() {
		code, err = RunTrace(context.Background(), c, cliutil.Parse([]string{"bogus"}))
	})
	if err != nil {
		t.Fatalf("RunTrace(bogus): %v", err)
	}
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if !strings.Contains(out, "Unknown trace subcommand") {
		t.Errorf("output missing unknown-subcommand message:\n%s", out)
	}
}

func TestRunTraceNoRingsAtAll(t *testing.T) {
	newHome(t)
	c := client.New()
	var code int
	var err error
	out := captureFD(t, 2, func() {
		code, err = RunTrace(context.Background(), c, cliutil.Parse(nil))
	})
	if err != nil {
		t.Fatalf("RunTrace: %v", err)
	}
	if code != 1 {
		t.Errorf("code = %d, want 1 when there are no matching records", code)
	}
	if !strings.Contains(out, "No calls recorded for this directory.") {
		t.Errorf("output missing the no-calls message:\n%s", out)
	}
	if strings.Contains(out, "recorded calls in:") {
		t.Errorf("did not expect suggestions when no rings exist at all:\n%s", out)
	}
}

func TestRunTraceNoRecordsForCwdWithSuggestions(t *testing.T) {
	newHome(t)
	root := filepath.Join(shared.SGDir(), "projects", "other-project")
	writeRing(t, root, rawTraceLine{TS: 1000, Tool: "Bash", Cwd: "/some/other/dir"})

	c := client.New()
	var code int
	var err error
	out := captureFD(t, 2, func() {
		code, err = RunTrace(context.Background(), c, cliutil.Parse(nil))
	})
	if err != nil {
		t.Fatalf("RunTrace: %v", err)
	}
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if !strings.Contains(out, "No calls recorded for this directory.") {
		t.Errorf("output missing the no-calls message:\n%s", out)
	}
	if !strings.Contains(out, "recorded calls in:") || !strings.Contains(out, "/some/other/dir") {
		t.Errorf("output missing the suggestions block:\n%s", out)
	}
}

func TestRunTraceWithMatchingRecords(t *testing.T) {
	newHome(t)
	here, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(here)
	if err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(shared.SGDir(), "projects", "this-project")
	writeRing(t, dir,
		rawTraceLine{TS: 3000, Tool: "ToolA", Cwd: abs},
		rawTraceLine{TS: 1000, Tool: "ToolB", Cwd: abs},
		rawTraceLine{TS: 2000, Tool: "ToolC", Cwd: abs},
	)
	c := client.New()

	t.Run("json with limit", func(t *testing.T) {
		var code int
		var runErr error
		out := captureFD(t, 1, func() {
			code, runErr = RunTrace(context.Background(), c, cliutil.Parse([]string{"--json", "--limit", "2"}))
		})
		if runErr != nil {
			t.Fatalf("RunTrace: %v", runErr)
		}
		if code != 0 {
			t.Errorf("code = %d, want 0", code)
		}
		var recs []traceRecord
		if jerr := json.Unmarshal([]byte(out), &recs); jerr != nil {
			t.Fatalf("output is not valid JSON: %v\noutput: %s", jerr, out)
		}
		if len(recs) != 2 {
			t.Fatalf("got %d records, want 2 (limited)", len(recs))
		}
		if recs[0].Tool != "ToolA" || recs[1].Tool != "ToolC" {
			t.Errorf("records not sorted/limited correctly: %+v", recs)
		}
	})

	t.Run("text with limit", func(t *testing.T) {
		var code int
		var runErr error
		out := captureFD(t, 2, func() {
			code, runErr = RunTrace(context.Background(), c, cliutil.Parse([]string{"--limit", "2"}))
		})
		if runErr != nil {
			t.Fatalf("RunTrace: %v", runErr)
		}
		if code != 0 {
			t.Errorf("code = %d, want 0", code)
		}
		if !strings.Contains(out, "2 local evaluation(s)") {
			t.Errorf("output missing the count line:\n%s", out)
		}
		if !strings.Contains(out, "ToolA") || !strings.Contains(out, "ToolC") || strings.Contains(out, "ToolB") {
			t.Errorf("output does not reflect the top-2 limited, sorted records:\n%s", out)
		}
	})
}