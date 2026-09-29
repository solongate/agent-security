package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// ── the document ───────────────────────────────────────────────────────────

func TestPolicyDocKeepsFieldsThisBuildDoesNotModel(t *testing.T) {
	// The dashboard adds fields faster than any one binary is rebuilt. A
	// read-modify-write through a struct deletes every one of them, and the
	// deletion is invisible until somebody notices a setting reverting.
	raw := `{
	  "id":"pol_1","name":"Prod","version":3,
	  "mode":"denylist",
	  "somethingNewerThanThisBuild":{"nested":true},
	  "rules":[{"id":"r1","effect":"DENY","toolPattern":"*","enabled":true,"futureField":42}]
	}`

	doc, err := DecodePolicyDoc([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	out, err := EncodeIndented(doc.WithoutID())
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"somethingNewerThanThisBuild", "futureField", `"mode"`} {
		if !strings.Contains(string(out), needle) {
			t.Errorf("%s was dropped on the round trip:\n%s", needle, out)
		}
	}
}

func TestWithoutIDDropsOnlyTheID(t *testing.T) {
	// The cloud id is owned by --policy-id. Writing it into the file makes the
	// file a second place it is configured, and the two then disagree.
	doc, err := DecodePolicyDoc([]byte(`{"id":"pol_1","name":"Prod","version":1,"rules":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	out, err := EncodeIndented(doc.WithoutID())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), `"id"`) {
		t.Fatalf("the id survived:\n%s", out)
	}
	if !strings.Contains(string(out), `"name"`) {
		t.Fatalf("the name was dropped:\n%s", out)
	}
	if !strings.HasSuffix(string(out), "\n") {
		t.Fatal("no trailing newline")
	}
}

func TestUndecodableRulesDoNotTakeTheWholePolicyDown(t *testing.T) {
	// Decoding the array in one call means a single mistyped field anywhere
	// leaves the caller holding a policy with no rules, while the dashboard
	// still shows them as active.
	raw := `{"name":"P","version":1,"rules":[
	  {"id":"good","effect":"DENY","toolPattern":"shell*","enabled":true},
	  {"id":"bad","effect":"DENY","priority":"not-a-number","enabled":true},
	  {"id":"good2","effect":"ALLOW","toolPattern":"*","enabled":true}
	]}`

	doc, err := DecodePolicyDoc([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Set.Rules) != 2 {
		t.Fatalf("decoded %d rules, want the 2 readable ones", len(doc.Set.Rules))
	}
	if doc.Unreadable != 1 {
		t.Fatalf("Unreadable = %d, want 1", doc.Unreadable)
	}
	// The rule that could not be read must still be pushed back as it arrived,
	// or a round trip through this proxy quietly deletes it from the account.
	if !strings.Contains(string(doc.RawRules()), "not-a-number") {
		t.Fatalf("the unreadable rule was dropped from the raw view: %s", doc.RawRules())
	}
}

func TestRulesEqualIgnoresFormattingAndCatchesContent(t *testing.T) {
	a, _ := DecodePolicyDoc([]byte(`{"name":"P","rules":[{"id":"r1","effect":"DENY","toolPattern":"a","enabled":true}]}`))
	sameReindented, _ := DecodePolicyDoc([]byte("{\n \"name\":\"P\",\n \"rules\":[\n  {\"effect\":\"DENY\",\"id\":\"r1\",\"toolPattern\":\"a\",\"enabled\":true}\n ]\n}"))
	different, _ := DecodePolicyDoc([]byte(`{"name":"P","rules":[{"id":"r1","effect":"ALLOW","toolPattern":"a","enabled":true}]}`))

	if !RulesEqual(a, sameReindented) {
		t.Fatal("a re-indented policy read as a changed one")
	}
	if RulesEqual(a, different) {
		t.Fatal("a changed effect read as unchanged")
	}
}

func TestSetVersionMovesBothViews(t *testing.T) {
	// Updating only one view is how a policy gets pushed under a number the
	// local file does not have, and the two ends then bounce a version at each
	// other forever.
	doc, _ := DecodePolicyDoc([]byte(`{"name":"P","version":1,"rules":[]}`))
	doc.SetVersion(7)
	if doc.Set.Version != 7 {
		t.Fatalf("Set.Version = %d", doc.Set.Version)
	}
	out, _ := EncodeIndented(doc.Fields)
	if !strings.Contains(string(out), `"version": 7`) {
		t.Fatalf("the document still holds the old version:\n%s", out)
	}
}

// ── the file watcher ───────────────────────────────────────────────────────

func writePolicyFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestALocalEditIsPickedUp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writePolicyFile(t, path, `{"name":"P","version":1,"rules":[]}`)

	initial, _ := DecodePolicyDoc([]byte(`{"name":"P","version":1,"rules":[]}`))

	updates := make(chan PolicyDoc, 4)
	m := NewSyncManager(SyncOptions{
		LocalPath:      path,
		WatchInterval:  20 * time.Millisecond,
		Initial:        initial,
		OnPolicyUpdate: func(doc PolicyDoc) { updates <- doc },
	})
	m.Start()
	defer m.Stop()

	// Long enough for the watcher to take its baseline stat, which it does on its own
	// goroutine after Start returns. An edit that lands first IS the baseline, and
	// nothing has changed by the time the first tick looks. This used to be 1100ms,
	// covering the second-long window in which the sync ignored writes it could not
	// tell from its own — with nothing of ours to ignore, one tick is enough.
	time.Sleep(100 * time.Millisecond)

	edited := `{"name":"P","version":1,"rules":[{"id":"r1","effect":"DENY","toolPattern":"shell*","enabled":true}]}`
	writePolicyFile(t, path, edited)

	select {
	case doc := <-updates:
		if len(doc.Set.Rules) != 1 {
			t.Fatalf("update carried %d rules", len(doc.Set.Rules))
		}
		// AN EDIT THAT LEAVES THE VERSION ALONE IS STILL IN FORCE. This used to
		// require the opposite — `version = %d, want it auto-incremented past 1` —
		// because the cloud would not accept an edit as newer without a higher
		// version, so the sync bumped it and REWROTE THE FILE. Nothing has to accept
		// it now. The rules are enforced because they parsed.
		if doc.Set.Version != 1 {
			t.Fatalf("version = %d, want the 1 the file says", doc.Set.Version)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a local edit was never noticed")
	}

	// AND THE FILE IS BYTE-FOR-BYTE WHAT WAS WRITTEN. A person editing a policy has
	// an editor holding that buffer; rewriting it under them to change a number only
	// a status line reads is the sort of help nobody asked for.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != edited {
		t.Fatalf("the sync rewrote the user's file:\n have %s\n want %s", after, edited)
	}
}

// ONE EDIT IS ONE UPDATE.
//
// This was TestTheSyncDoesNotReactToItsOwnWrite, and it guarded a real hazard: the
// version bump rewrote the file, the watcher saw the ModTime move, and without a
// window in which our own write did not count, the two ends bounced versions at each
// other forever. The sync writes nothing now, so the hazard is gone — but "one edit,
// one reload" is the property that mattered, and a reload is not free: it recompiles
// the policy for every call in flight.
func TestOneEditIsOneUpdate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writePolicyFile(t, path, `{"name":"P","version":1,"rules":[]}`)

	initial, _ := DecodePolicyDoc([]byte(`{"name":"P","version":1,"rules":[]}`))

	var mu sync.Mutex
	var count int
	m := NewSyncManager(SyncOptions{
		LocalPath:     path,
		WatchInterval: 20 * time.Millisecond,
		Initial:       initial,
		OnPolicyUpdate: func(PolicyDoc) {
			mu.Lock()
			count++
			mu.Unlock()
		},
	})
	m.Start()
	defer m.Stop()

	time.Sleep(100 * time.Millisecond)
	writePolicyFile(t, path, `{"name":"P","version":1,"rules":[{"id":"r1","effect":"DENY","toolPattern":"shell*","enabled":true}]}`)
	// Several watch intervals, so a second reload would have happened by now.
	time.Sleep(1500 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if count != 1 {
		t.Fatalf("OnPolicyUpdate fired %d times for one edit", count)
	}
}

func TestADeletedPolicyFileKeepsTheLoadedPolicy(t *testing.T) {
	// An editor's atomic save briefly removes the file. Treating that as "no
	// rules" opens a window with nothing enforced every time somebody saves.
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writePolicyFile(t, path, `{"name":"P","version":1,"rules":[]}`)

	initial, _ := DecodePolicyDoc([]byte(`{"name":"P","version":1,"rules":[]}`))

	var mu sync.Mutex
	var lines []string
	m := NewSyncManager(SyncOptions{
		LocalPath:      path,
		WatchInterval:  20 * time.Millisecond,
		Initial:        initial,
		OnPolicyUpdate: func(PolicyDoc) { t.Error("a deleted file produced a policy update") },
		Log: func(line string) {
			mu.Lock()
			lines = append(lines, line)
			mu.Unlock()
		},
	})
	m.Start()
	defer m.Stop()

	time.Sleep(200 * time.Millisecond)
	_ = os.Remove(path)
	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, l := range lines {
		if strings.Contains(l, "keeping current policy") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the deletion was not reported: %v", lines)
	}
}

// ── pushing up ─────────────────────────────────────────────────────────────

// ── the audit backup ───────────────────────────────────────────────────────

// The audit record lands in THIS MACHINE's trail — the same file the guard and the
// hooks append to, so a machine has one log rather than two.
//
// Four tests here used to cover a service instead: a policy pushed up and created
// on a 404, a version read out of `_version`, a client error not being retried, and
// an entry falling back to `.solongate-audit-backup.jsonl` when every attempt
// failed. That backup is the shape worth not repeating — a second log, in whatever
// directory the proxy started in, holding exactly the entries somebody would most
// want to find.
func TestTheProxyRecordIsWrittenWhereEverythingElseReadsIt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	var logged []string
	writeAuditEntry(auditEntry{
		Tool:      "Bash",
		Arguments: map[string]any{"command": "rm -rf /tmp/x"},
		Decision:  "DENY",
		Reason:    "Blocked by policy",
		Timestamp: "2026-01-01T00:00:00.000Z",
	}, func(line string) { logged = append(logged, line) })

	if len(logged) != 0 {
		t.Fatalf("writing the record reported a problem: %v", logged)
	}
	path := filepath.Join(config.LocalLogsDir(), "solongate-audit.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the record was not written to %s: %v", path, err)
	}

	var back map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &back); err != nil {
		t.Fatalf("the line is not one JSON object: %v\n%s", err, raw)
	}
	if back["decision"] != "DENY" || back["tool"] != "Bash" {
		t.Errorf("the entry does not say what happened: %v", back)
	}
	// The timestamp used to be omitted for anything going to a service, which
	// stamped its own. The file is the record now and the readers sort on it.
	if back["timestamp"] != "2026-01-01T00:00:00.000Z" {
		t.Errorf("timestamp = %v, want the one that was written", back["timestamp"])
	}

	// A log of what somebody was working on: owner-only, in an owner-only folder.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %04o, want 0600", mode)
	}
	dir, err := os.Stat(config.LocalLogsDir())
	if err != nil {
		t.Fatal(err)
	}
	if mode := dir.Mode().Perm(); mode != 0o700 {
		t.Errorf("folder mode = %04o, want 0700", mode)
	}
}
