package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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
		APIKey:         "sg_test_local_only",
		WatchInterval:  20 * time.Millisecond,
		Initial:        initial,
		OnPolicyUpdate: func(doc PolicyDoc) { updates <- doc },
	})
	m.Start()
	defer m.Stop()

	// The watcher's own-write guard is a full second, so the edit has to land
	// clear of the manager's startup.
	time.Sleep(1100 * time.Millisecond)
	writePolicyFile(t, path, `{"name":"P","version":1,"rules":[{"id":"r1","effect":"DENY","toolPattern":"shell*","enabled":true}]}`)

	select {
	case doc := <-updates:
		if len(doc.Set.Rules) != 1 {
			t.Fatalf("update carried %d rules", len(doc.Set.Rules))
		}
		// The edit did not move the version, so the sync has to, or the cloud
		// will never accept it as newer.
		if doc.Set.Version <= 1 {
			t.Fatalf("version = %d, want it auto-incremented past 1", doc.Set.Version)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a local edit was never noticed")
	}
}

func TestTheSyncDoesNotReactToItsOwnWrite(t *testing.T) {
	// The auto-increment rewrites the file. Without the own-write guard that
	// rewrite reads as a fresh edit and the two ends bounce versions forever.
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writePolicyFile(t, path, `{"name":"P","version":1,"rules":[]}`)

	initial, _ := DecodePolicyDoc([]byte(`{"name":"P","version":1,"rules":[]}`))

	var mu sync.Mutex
	var count int
	m := NewSyncManager(SyncOptions{
		LocalPath:     path,
		APIKey:        "sg_test_local_only",
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

	time.Sleep(1100 * time.Millisecond)
	writePolicyFile(t, path, `{"name":"P","version":1,"rules":[{"id":"r1","effect":"DENY","toolPattern":"shell*","enabled":true}]}`)
	time.Sleep(2500 * time.Millisecond)

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
		APIKey:         "sg_test_local_only",
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

func TestPushCreatesThePolicyWhenThePutIs404(t *testing.T) {
	var methods []string
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"NOT_FOUND","message":"no such policy"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"pol_1","_version":9}`))
	}))
	defer server.Close()

	client := newCloudClient("sg_live_test_key", server.URL)
	doc, _ := DecodePolicyDoc([]byte(`{"name":"P","version":1,"rules":[]}`))

	version, err := pushPolicy(t.Context(), client, "pol_1", doc)
	if err != nil {
		t.Fatal(err)
	}
	if version != 9 {
		t.Fatalf("version = %d, want the 9 the API answered with", version)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(methods) != 2 || !strings.HasPrefix(methods[0], "PUT") || !strings.HasPrefix(methods[1], "POST") {
		t.Fatalf("calls = %v, want a PUT then a POST", methods)
	}
}

func TestFetchCloudPolicyReadsTheUnderscoreVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/policies") {
			_, _ = w.Write([]byte(`{"policies":[{"id":"pol_first"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"pol_first","name":"Cloud","_version":4,"rules":[]}`))
	}))
	defer server.Close()

	client := newCloudClient("sg_live_test_key", server.URL)
	doc, err := fetchCloudPolicy(t.Context(), client, "")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Set.Version != 4 {
		t.Fatalf("version = %d, want 4", doc.Set.Version)
	}
	if doc.Set.ID != "pol_first" {
		t.Fatalf("id = %q", doc.Set.ID)
	}
}

// ── the audit backup ───────────────────────────────────────────────────────

func TestAuditEntriesLandInTheBackupWhenEveryAttemptFails(t *testing.T) {
	// An audit trail with a hole in it is worse than one that is late.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	dir := t.TempDir()
	restore, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(restore)

	client := newCloudClient("sg_live_test_key", server.URL)
	sendAuditLog(t.Context(), client, auditEntry{
		Tool: "shell_exec", Decision: "DENY", Reason: "blocked",
		Arguments: map[string]any{"cmd": "rm -rf /"},
	}, func(string) {})

	body, err := os.ReadFile(filepath.Join(dir, ".solongate-audit-backup.jsonl"))
	if err != nil {
		t.Fatalf("no backup file: %v", err)
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(body))), &entry); err != nil {
		t.Fatal(err)
	}
	if entry["tool"] != "shell_exec" || entry["decision"] != "DENY" {
		t.Fatalf("entry = %v", entry)
	}
	if entry["timestamp"] == nil {
		t.Fatal("the backup entry has no timestamp")
	}
}

func TestAClientErrorIsNotRetried(t *testing.T) {
	// A 4xx is an answer. Sending it again produces the same answer while
	// delaying the next entry.
	var attempts int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"BAD","message":"malformed"}}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	restore, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer os.Chdir(restore)

	client := newCloudClient("sg_live_test_key", server.URL)
	sendAuditLog(t.Context(), client, auditEntry{Tool: "t", Decision: "ALLOW"}, func(string) {})

	mu.Lock()
	defer mu.Unlock()
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}
