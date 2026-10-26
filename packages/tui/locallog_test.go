// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/shared"
)

func TestTailLinesMissingFile(t *testing.T) {
	dir := t.TempDir()
	if got := TailLines(filepath.Join(dir, "missing.jsonl"), 1024); got != nil {
		t.Errorf("TailLines() on a missing file = %v, want nil", got)
	}
}

func TestTailLinesReturnsAllLinesWhenUnderBudget(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "log.jsonl")
	content := "line1\nline2\nline3\n"
	if err := os.WriteFile(file, []byte(content), shared.FileMode); err != nil {
		t.Fatal(err)
	}
	got := TailLines(file, int64(len(content))+100)
	want := []string{"line1", "line2", "line3"}
	if !slicesEqual(got, want) {
		t.Errorf("TailLines() = %v, want %v", got, want)
	}
}

func TestTailLinesDropsPartialFirstLineWhenOverBudget(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "log.jsonl")
	content := "line1\nline2\nline3\n"
	if err := os.WriteFile(file, []byte(content), shared.FileMode); err != nil {
		t.Fatal(err)
	}
	// Seek lands mid-"line2" (budget 8 keeps the last 8 bytes: "2\nline3\n"),
	// so the partial leading fragment "2" must be dropped and "line3" kept.
	got := TailLines(file, 8)
	want := []string{"line3"}
	if !slicesEqual(got, want) {
		t.Errorf("TailLines() with a small budget = %v, want %v", got, want)
	}
}

// TestTailLinesBoundaryAlignedSeekKeepsFullLine guards against a regression
// in TailLines (packages/tui/locallog.go): when the seek offset lands
// exactly on a newline, the leading-fragment drop must only fire when the
// read actually starts mid-line, not when it starts with a complete line.
func TestTailLinesBoundaryAlignedSeekKeepsFullLine(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "log.jsonl")
	content := "line1\nline2\nline3\n"
	if err := os.WriteFile(file, []byte(content), shared.FileMode); err != nil {
		t.Fatal(err)
	}
	// budget=7 seeks to offset 11, which is exactly the "\n" ending "line2" —
	// a boundary-aligned cut, so "line3" is a complete line and must be kept.
	got := TailLines(file, 7)
	want := []string{"line3"}
	if !slicesEqual(got, want) {
		t.Errorf("TailLines() at a boundary-aligned seek = %v, want %v", got, want)
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParseLocalLinesSkipsInvalidJSONAndBadTimestamps(t *testing.T) {
	lines := []string{
		`{"ts":"2024-01-02T03:04:05Z","tool":"bash"}`,
		`not json at all`,
		`{"ts":"","tool":"edit"}`,
		`{"ts":"garbage-timestamp","tool":"edit"}`,
		`{"ts":"2024-01-02T03:04:06Z","tool":"write"}`,
	}
	got := ParseLocalLines(lines)
	if len(got) != 2 {
		t.Fatalf("ParseLocalLines() kept %d entries, want 2", len(got))
	}
	if got[0].Tool != "bash" || got[1].Tool != "write" {
		t.Errorf("ParseLocalLines() = %+v, want bash then write", got)
	}
	if got[0].At == 0 || got[1].At == 0 {
		t.Error("ParseLocalLines() left At unset on a valid line")
	}
}

func TestReasonSignalsDetectsDLPWithName(t *testing.T) {
	reason := "Security layer (DLP): blocked, arguments contain a credit card number. Blocked by SolonGate."
	dlp, burst := ReasonSignals(reason)
	if burst {
		t.Error("ReasonSignals() flagged burst on a pure DLP message, want false")
	}
	if len(dlp) != 1 || dlp[0] != "credit card number" {
		t.Errorf("ReasonSignals() dlp = %v, want [\"credit card number\"]", dlp)
	}
}

func TestReasonSignalsDLPFallsBackToGenericName(t *testing.T) {
	reason := "Security layer (DLP): reading a file is blocked."
	dlp, _ := ReasonSignals(reason)
	if len(dlp) != 1 || dlp[0] != "DLP" {
		t.Errorf("ReasonSignals() dlp = %v, want the generic [\"DLP\"] fallback", dlp)
	}
}

func TestReasonSignalsDetectsRateLimit(t *testing.T) {
	cases := []string{
		"Security layer (rate limit): exceeded 5 calls/minute for this agent. Blocked by SolonGate (rate limit).",
		"Rate limited and the quota was exceeded for this window",
		"Blocked: exceeded 10 calls in the burst window.",
	}
	for _, reason := range cases {
		if _, burst := ReasonSignals(reason); !burst {
			t.Errorf("ReasonSignals(%q) burst = false, want true", reason)
		}
	}
}

func TestReasonSignalsNoMatch(t *testing.T) {
	dlp, burst := ReasonSignals("Allowed by policy rule: default-allow")
	if dlp != nil || burst {
		t.Errorf("ReasonSignals() on a plain allow reason = dlp=%v burst=%v, want nil,false", dlp, burst)
	}
}

// localLogHome points config.Dir() at a fresh home and creates the default
// local-logs directory so DeleteLocalEntry/ClearLocalLog have somewhere to
// read and write without touching the real machine.
func localLogHome(t *testing.T) string {
	t.Helper()
	newHome(t)
	dir := filepath.Dir(config.LocalLogFile())
	if err := os.MkdirAll(dir, shared.DirMode); err != nil {
		t.Fatal(err)
	}
	return config.LocalLogFile()
}

func writeLogLines(t *testing.T, file string, lines []string) {
	t.Helper()
	body := ""
	if len(lines) > 0 {
		body = strings.Join(lines, "\n") + "\n"
	}
	if err := os.WriteFile(file, []byte(body), shared.FileMode); err != nil {
		t.Fatal(err)
	}
}

func atMillis(t *testing.T, rfc3339 string) int64 {
	t.Helper()
	at, ok := ParseMillis(rfc3339)
	if !ok {
		t.Fatalf("ParseMillis(%q) failed", rfc3339)
	}
	return at
}

func TestDeleteLocalEntryRemovesExactlyOneMatch(t *testing.T) {
	file := localLogHome(t)
	writeLogLines(t, file, []string{
		`{"ts":"2024-01-01T00:00:00Z","tool":"bash","session_id":"s1"}`,
		`{"ts":"2024-01-01T00:00:01Z","tool":"bash","session_id":"s2"}`,
		`{"ts":"2024-01-01T00:00:02Z","tool":"edit","session_id":"s1"}`,
	})

	removed := DeleteLocalEntry(atMillis(t, "2024-01-01T00:00:01Z"), "bash", "s2")
	if removed != 1 {
		t.Fatalf("DeleteLocalEntry() removed = %d, want 1", removed)
	}

	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	remaining := ParseLocalLines(strings.Split(strings.TrimRight(string(b), "\n"), "\n"))
	if len(remaining) != 2 {
		t.Fatalf("after delete, %d entries remain, want 2", len(remaining))
	}
	for _, e := range remaining {
		if e.SessionID == "s2" {
			t.Error("the targeted entry is still present after DeleteLocalEntry")
		}
	}
}

func TestDeleteLocalEntryNoMatchRemovesNothing(t *testing.T) {
	file := localLogHome(t)
	lines := []string{`{"ts":"2024-01-01T00:00:00Z","tool":"bash","session_id":"s1"}`}
	writeLogLines(t, file, lines)

	removed := DeleteLocalEntry(atMillis(t, "2099-01-01T00:00:00Z"), "bash", "s1")
	if removed != 0 {
		t.Errorf("DeleteLocalEntry() with no matching entry removed = %d, want 0", removed)
	}
	b, _ := os.ReadFile(file)
	if strings.TrimRight(string(b), "\n") != lines[0] {
		t.Errorf("file content changed after a no-op delete: %q", string(b))
	}
}

func TestDeleteLocalEntryMissingFileIsNoop(t *testing.T) {
	newHome(t)
	if removed := DeleteLocalEntry(1, "bash", ""); removed != 0 {
		t.Errorf("DeleteLocalEntry() against a missing log = %d, want 0", removed)
	}
}

func TestDeleteLocalEntryEmptySessionMatchesAny(t *testing.T) {
	file := localLogHome(t)
	writeLogLines(t, file, []string{
		`{"ts":"2024-01-01T00:00:03Z","tool":"bash","session_id":"anything"}`,
	})
	removed := DeleteLocalEntry(atMillis(t, "2024-01-01T00:00:03Z"), "bash", "")
	if removed != 1 {
		t.Errorf("DeleteLocalEntry() with an empty session filter removed = %d, want 1 (match any session)", removed)
	}
}

func TestClearLocalLogCountsAndTruncates(t *testing.T) {
	file := localLogHome(t)
	writeLogLines(t, file, []string{
		`{"ts":"2024-01-01T00:00:00Z","tool":"bash"}`,
		`{"ts":"2024-01-01T00:00:01Z","tool":"edit"}`,
	})

	n := ClearLocalLog()
	if n != 2 {
		t.Errorf("ClearLocalLog() = %d, want 2", n)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 0 {
		t.Errorf("file after ClearLocalLog() has %d bytes, want 0", len(b))
	}
}

func TestClearLocalLogMissingFileIsNoop(t *testing.T) {
	newHome(t)
	if n := ClearLocalLog(); n != 0 {
		t.Errorf("ClearLocalLog() against a missing log = %d, want 0", n)
	}
}

func TestReadLogWithSizeMissingFile(t *testing.T) {
	dir := t.TempDir()
	_, _, ok := readLogWithSize(filepath.Join(dir, "missing.jsonl"))
	if ok {
		t.Error("readLogWithSize() on a missing file returned ok=true, want false")
	}
}

func TestReadLogWithSizeReadsContentAndSize(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "log.jsonl")
	if err := os.WriteFile(file, []byte("hello"), shared.FileMode); err != nil {
		t.Fatal(err)
	}
	b, size, ok := readLogWithSize(file)
	if !ok || string(b) != "hello" || size != 5 {
		t.Errorf("readLogWithSize() = %q,%d,%v, want \"hello\",5,true", b, size, ok)
	}
}

func TestRewriteLogRefusesOnSizeMismatch(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "log.jsonl")
	if err := os.WriteFile(file, []byte("0123456789"), shared.FileMode); err != nil {
		t.Fatal(err)
	}
	if ok := rewriteLog(file, 999, []byte("new content")); ok {
		t.Error("rewriteLog() with a mismatched size returned true, want false")
	}
	b, _ := os.ReadFile(file)
	if string(b) != "0123456789" {
		t.Errorf("rewriteLog() modified the file despite a size mismatch: %q", b)
	}
}

func TestRewriteLogSucceedsOnMatch(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "log.jsonl")
	if err := os.WriteFile(file, []byte("0123456789"), shared.FileMode); err != nil {
		t.Fatal(err)
	}
	if ok := rewriteLog(file, 10, []byte("replaced")); !ok {
		t.Fatal("rewriteLog() with a matching size returned false, want true")
	}
	b, _ := os.ReadFile(file)
	if string(b) != "replaced" {
		t.Errorf("file content = %q, want \"replaced\"", b)
	}
}

func TestLockAuditLogSucceedsAndUnlockRemovesFile(t *testing.T) {
	dir := t.TempDir()
	unlock, ok := lockAuditLog(dir)
	if !ok {
		t.Fatal("lockAuditLog() on a free directory returned ok=false, want true")
	}
	lockPath := filepath.Join(dir, shared.AuditLockName)
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("lock file was not created: %v", err)
	}
	unlock()
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Error("unlock() did not remove the lock file")
	}
}

func TestLockAuditLogRemovesStaleLock(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, shared.AuditLockName)
	if err := os.WriteFile(lockPath, nil, shared.FileMode); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-2 * shared.AuditLockStaleAfterMS * time.Millisecond)
	if err := os.Chtimes(lockPath, stale, stale); err != nil {
		t.Fatal(err)
	}

	unlock, ok := lockAuditLog(dir)
	if !ok {
		t.Fatal("lockAuditLog() did not recover from a stale lock, want ok=true")
	}
	unlock()
}

func TestLockAuditLogTimesOutOnAHeldLock(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, shared.AuditLockName)
	if err := os.WriteFile(lockPath, nil, shared.FileMode); err != nil {
		t.Fatal(err)
	}
	// Freshly created: not stale, so lockAuditLog must wait out the full
	// deadline and then report failure.
	_, ok := lockAuditLog(dir)
	if ok {
		t.Error("lockAuditLog() against a live, held lock returned ok=true, want false")
	}
}