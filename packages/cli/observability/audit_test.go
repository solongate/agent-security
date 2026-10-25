// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package observability

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
)

// newHome isolates the client's local file store (policy, audit log, stats)
// under a fresh temp dir for the duration of the test. This mirrors the
// two-line helper packages/core/client's own tests use to redirect the
// HOME-derived store.
func newHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

// captureFD redirects the real OS file descriptor fd (1 for stdout, 2 for
// stderr) to a pipe while fn runs, and returns everything written to it.
//
// cliutil.Out/Errln write through package-private io.Writer vars that are
// bound to os.Stdout/os.Stderr once, at cliutil's package-init time.
// Reassigning the exported os.Stdout/os.Stderr variables in a test (the
// usual trick, used e.g. in packages/guard/auditcmd where the code under
// test reads os.Stdout directly) does not change those already-captured
// copies here, so output would keep going to the real terminal. Only a
// descriptor-level dup2 redirects it, because the captured *os.File still
// refers to the same underlying fd number.
func captureFD(t *testing.T, fd int, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	saved, err := syscall.Dup(fd)
	if err != nil {
		t.Fatalf("syscall.Dup(%d): %v", fd, err)
	}
	if err := syscall.Dup2(int(w.Fd()), fd); err != nil {
		t.Fatalf("syscall.Dup2: %v", err)
	}
	w.Close()

	fn()

	if err := syscall.Dup2(saved, fd); err != nil {
		t.Fatalf("syscall.Dup2 restore: %v", err)
	}
	syscall.Close(saved)

	out, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	return string(out)
}

// seedAuditLog writes raw JSONL lines directly into the local audit log file
// that client.Audit/client.Stats read from, the same way a real guard
// process would append to it.
func seedAuditLog(t *testing.T, lines ...string) {
	t.Helper()
	file := config.LocalLogFile()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAuditUsage(t *testing.T) {
	u := auditUsage()
	for _, want := range []string{"solongate audit", "whitelist", "block"} {
		if !strings.Contains(u, want) {
			t.Errorf("auditUsage() missing %q, got: %s", want, u)
		}
	}
}

func TestDeref(t *testing.T) {
	nonEmpty := "hello"
	empty := ""
	cases := []struct {
		name     string
		s        *string
		fallback string
		want     string
	}{
		{"nil pointer", nil, "-", "-"},
		{"pointer to empty string", &empty, "-", "-"},
		{"pointer to non-empty string", &nonEmpty, "-", "hello"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := deref(c.s, c.fallback); got != c.want {
				t.Errorf("deref(...) = %q, want %q", got, c.want)
			}
		})
	}
}

func TestRunAuditHelp(t *testing.T) {
	newHome(t)
	c := client.New()
	code, err := RunAudit(context.Background(), c, cliutil.Parse([]string{"help"}))
	if err != nil {
		t.Fatalf("RunAudit(help): %v", err)
	}
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
}

func TestRunAuditWhitelistBlockMissingID(t *testing.T) {
	for _, sub := range []string{"whitelist", "block"} {
		t.Run(sub, func(t *testing.T) {
			newHome(t)
			c := client.New()
			code, err := RunAudit(context.Background(), c, cliutil.Parse([]string{sub}))
			if err != nil {
				t.Fatalf("RunAudit(%s): %v", sub, err)
			}
			if code != 1 {
				t.Errorf("code = %d, want 1 (cliutil.UsageErr)", code)
			}
		})
	}
}

func TestRunAuditWhitelistBlockAgainstEmptyLog(t *testing.T) {
	for _, sub := range []string{"whitelist", "block"} {
		t.Run(sub, func(t *testing.T) {
			newHome(t)
			c := client.New()
			code, err := RunAudit(context.Background(), c, cliutil.Parse([]string{sub, "1"}))
			if err == nil {
				t.Fatal("expected an error looking up a nonexistent audit log id, got nil")
			}
			if code != 1 {
				t.Errorf("code = %d, want 1", code)
			}
			if !strings.Contains(err.Error(), "no entry") {
				t.Errorf("err = %v, want it to mention the missing entry", err)
			}
		})
	}
}

func TestRunAuditDefaultListingEmptyJSON(t *testing.T) {
	newHome(t)
	c := client.New()
	var code int
	var err error
	out := captureFD(t, 1, func() {
		code, err = RunAudit(context.Background(), c, cliutil.Parse([]string{"--json"}))
	})
	if err != nil {
		t.Fatalf("RunAudit: %v", err)
	}
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	var res client.AuditList
	if jerr := json.Unmarshal([]byte(out), &res); jerr != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", jerr, out)
	}
	if res.Total != 0 || len(res.Entries) != 0 {
		t.Errorf("got Total=%d len(Entries)=%d, want 0 and 0", res.Total, len(res.Entries))
	}
}

func TestRunAuditDefaultListingEmptyText(t *testing.T) {
	newHome(t)
	c := client.New()
	var code int
	var err error
	out := captureFD(t, 2, func() {
		code, err = RunAudit(context.Background(), c, cliutil.Parse(nil))
	})
	if err != nil {
		t.Fatalf("RunAudit: %v", err)
	}
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(out, "0") || !strings.Contains(out, "matching entries") {
		t.Errorf("output = %q, want it to mention 0 matching entries", out)
	}
}

func TestRunAuditDefaultListingWithEntries(t *testing.T) {
	newHome(t)
	seedAuditLog(t,
		`{"ts":"2026-01-01T00:00:00Z","tool":"Bash","decision":"ALLOW","agent_name":"agent-a"}`,
		`{"ts":"2026-01-01T01:00:00Z","tool":"WebFetch","decision":"DENY","reason":"dlp pattern matched","dlp":["AWS access key"]}`,
	)
	c := client.New()

	var code int
	var err error
	out := captureFD(t, 2, func() {
		code, err = RunAudit(context.Background(), c, cliutil.Parse(nil))
	})
	if err != nil {
		t.Fatalf("RunAudit: %v", err)
	}
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	for _, want := range []string{"2", "matching entries", "WebFetch", "Bash", "DENY", "ALLOW"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}