package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The expected hashes come from running the hooks' own projectKey (the function
// in packages/proxy/hooks/audit.mjs, unchanged) over the same paths. They are
// pinned here rather than recomputed, because "both implementations run the
// same algorithm" is exactly the claim that has to be tested, and a test that
// re-derives the answer proves nothing about it.
func TestProjectKeyMatchesTheHooks(t *testing.T) {
	cases := map[string]string{
		"/home/me/proj":       "d8c3495e",
		"/":                   "2a0c975e",
		"":                    "811c9dc5",
		`C:\Users\me\proj`:    "2ba5a1a5",
		"/home/müşteri/proj":  "98d8e9fc",
		"/home/日本/x":          "c4141884",
		"/home/me/\U0001F600": "b4bb03b0",
	}
	for path, want := range cases {
		if got := ProjectKey(path); got != want {
			t.Errorf("ProjectKey(%q) = %s, the hooks say %s", path, got, want)
		}
	}
}

// packages/guard-go hashes bytes where the hooks hash UTF-16 units. This test
// exists to catch the day someone "aligns" the two by copying the byte version
// over: it would pass every ASCII case and quietly break every machine whose
// home directory is not ASCII.
func TestProjectKeyIsNotBytewise(t *testing.T) {
	var h uint32 = 0x811c9dc5
	const path = "/home/müşteri/proj"
	for i := 0; i < len(path); i++ {
		h ^= uint32(path[i])
		h = h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))
	}
	if got := ProjectKey(path); got == "1ec69c96" {
		t.Fatalf("ProjectKey has reverted to hashing bytes (%s); the hooks hash UTF-16 units", got)
	}
}

func TestAgentKeyMatchesTheHooks(t *testing.T) {
	cases := map[string]string{
		"claude-code":  "claude-code",
		"codex":        "codex",
		"":             "default",
		"a b/c":        "a_b_c",
		"anti.gravity": "anti_gravity",
		// One emoji is two UTF-16 units, so the hooks' per-unit replace writes
		// two underscores.
		"x\U0001F600": "x__",
	}
	for agent, want := range cases {
		if got := AgentKey(agent); got != want {
			t.Errorf("AgentKey(%q) = %q, want %q", agent, got, want)
		}
	}
}

// Credential precedence has to match the Node client's exactly: env, then the
// active-key file, then a .env in the working directory. Getting the order
// wrong means a machine with a stale project .env enforces with one account and
// reports on another.
func TestResolvePrecedence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeCred(t, Credential{APIKey: "sg_live_fromfile0000000000", APIURL: "https://file.example"})

	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, ".env"), []byte("SOLONGATE_API_KEY=sg_live_fromdotenv000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	chdir(t, cwd)

	t.Run("env wins", func(t *testing.T) {
		t.Setenv("SOLONGATE_API_KEY", "sg_live_fromenv00000000000")
		r := &Resolver{}
		c, err := r.Resolve("")
		if err != nil {
			t.Fatal(err)
		}
		if c.APIKey != "sg_live_fromenv00000000000" {
			t.Errorf("key = %q, want the environment's", c.APIKey)
		}
		// The URL still comes from the file: only the key was overridden.
		if c.APIURL != "https://file.example" {
			t.Errorf("url = %q, want the file's", c.APIURL)
		}
	})

	t.Run("file beats dotenv", func(t *testing.T) {
		t.Setenv("SOLONGATE_API_KEY", "")
		r := &Resolver{}
		c, err := r.Resolve("")
		if err != nil {
			t.Fatal(err)
		}
		if c.APIKey != "sg_live_fromfile0000000000" {
			t.Errorf("key = %q, want the active-key file's", c.APIKey)
		}
	})

	t.Run("dotenv is the last resort", func(t *testing.T) {
		t.Setenv("SOLONGATE_API_KEY", "")
		if err := os.Remove(CredentialPath()); err != nil {
			t.Fatal(err)
		}
		r := &Resolver{}
		c, err := r.Resolve("")
		if err != nil {
			t.Fatal(err)
		}
		if c.APIKey != "sg_live_fromdotenv000000" {
			t.Errorf("key = %q, want the .env's", c.APIKey)
		}
		if c.APIURL != DefaultAPIURL {
			t.Errorf("url = %q, want the default", c.APIURL)
		}
	})
}

// A --api-url override must not be cached and must not be answered from the
// view override, or one request against another environment changes what the
// whole process reads afterwards.
func TestAPIURLOverrideDoesNotLeak(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SOLONGATE_API_KEY", "")
	t.Setenv("SOLONGATE_API_URL", "")
	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeCred(t, Credential{APIKey: "sg_live_abcdef0123456789", APIURL: "https://stored.example"})
	chdir(t, t.TempDir())

	r := &Resolver{}
	if c, _ := r.Resolve("https://other.example/"); c.APIURL != "https://other.example" {
		t.Errorf("override url = %q, want the override with its trailing slash trimmed", c.APIURL)
	}
	c, err := r.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if c.APIURL != "https://stored.example" {
		t.Errorf("url after an override = %q, want the stored one", c.APIURL)
	}
}

// The view override is what the dataroom's account switcher sets. It must never
// reach disk: the guard hooks keep enforcing with the device's real key while
// the user looks at another account.
func TestViewOverrideNeverTouchesDisk(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SOLONGATE_API_KEY", "")
	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeCred(t, Credential{APIKey: "sg_live_enforcing00000000", APIURL: DefaultAPIURL})
	chdir(t, t.TempDir())

	r := &Resolver{}
	r.SetView(&Credential{APIKey: "sg_live_viewing000000000", APIURL: DefaultAPIURL})
	if c, _ := r.Resolve(""); c.APIKey != "sg_live_viewing000000000" {
		t.Errorf("view override ignored, got %q", c.APIKey)
	}
	if EnforcingKey() != "sg_live_enforcing00000000" {
		t.Errorf("the on-disk enforcing key changed: %q", EnforcingKey())
	}
}

// ListAccounts seeds from the active-key file so the account this device
// enforces with is always visible, including on a machine that paired before
// accounts.json existed.
func TestListAccountsSeedsFromTheActiveKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeCred(t, Credential{APIKey: "sg_live_active0000000000", APIURL: DefaultAPIURL})

	list := ListAccounts()
	if len(list) != 1 || list[0].APIKey != "sg_live_active0000000000" {
		t.Fatalf("expected the active key to be seeded, got %+v", list)
	}

	SaveAccount(SavedAccount{APIKey: "sg_live_other00000000000", APIURL: DefaultAPIURL, Email: "b@example.com"})
	list = ListAccounts()
	if len(list) != 2 {
		t.Fatalf("expected both accounts, got %+v", list)
	}
	// The seed goes to the FRONT, matching the Node client: the account this
	// device enforces with is the one the dataroom should land on.
	if list[0].APIKey != "sg_live_active0000000000" {
		t.Errorf("the enforcing account is not first: %+v", list)
	}

	RemoveAccount("sg_live_other00000000000")
	if len(ListAccounts()) != 1 {
		t.Errorf("remove did not take: %+v", ListAccounts())
	}
}

// SetActiveAccount must merge, not replace. The file can carry keys written by
// a newer version of the npm package and this CLI overwriting them would be one
// implementation deleting the other's state.
func TestSetActiveAccountPreservesUnknownFields(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}
	raw := `{"apiKey":"sg_live_old000000000000","apiUrl":"https://old.example","somethingElse":{"kept":true}}`
	if err := os.WriteFile(CredentialPath(), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}

	if !SetActiveAccount(Credential{APIKey: "sg_live_new000000000000", APIURL: "https://new.example"}) {
		t.Fatal("SetActiveAccount reported failure")
	}
	var got map[string]any
	b, err := os.ReadFile(CredentialPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got["apiKey"] != "sg_live_new000000000000" {
		t.Errorf("apiKey not updated: %v", got["apiKey"])
	}
	if _, ok := got["somethingElse"]; !ok {
		t.Errorf("an unknown field was dropped: %v", got)
	}
}

// Signing out clears the key without deleting the file, so ListAccounts stops
// re-seeding the account that was just removed — the "phantom account" this
// function exists to prevent.
func TestClearActiveCredentialRemovesThePhantom(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeCred(t, Credential{APIKey: "sg_live_gone0000000000000", APIURL: DefaultAPIURL})

	if !ClearActiveCredential() {
		t.Fatal("ClearActiveCredential reported failure")
	}
	if EnforcingKey() != "" {
		t.Errorf("key survived the sign-out: %q", EnforcingKey())
	}
	if len(ListAccounts()) != 0 {
		t.Errorf("phantom account still listed: %+v", ListAccounts())
	}
}

// A key that will not work must not be treated as a key. The guard reads an
// unusable one as "no project selected", which means allow, so a placeholder
// left in a config file would silently disarm it.
func TestIsRealKey(t *testing.T) {
	real := []string{"sg_live_0123456789abcdef", "sg_test_ABCDEF0123456789ff"}
	fake := []string{
		"", "nope", "sg_live_", "sg_live_short",
		"sg_live_your_key_here_0000000000", "sg_live_placeholder000000000",
		"sg_live_example00000000000000", "sg_live_not-hex-at-all-here!!",
	}
	for _, k := range real {
		if !IsRealKey(k) {
			t.Errorf("IsRealKey(%q) = false, want true", k)
		}
	}
	for _, k := range fake {
		if IsRealKey(k) {
			t.Errorf("IsRealKey(%q) = true, want false", k)
		}
	}
}

// Local logging: the setting and the evidence of the setting are different
// questions. An enabled-but-empty log must not report as off.
func TestLocalLogsSetting(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Run("no cache is off", func(t *testing.T) {
		s := LocalLogsSetting()
		if s.Enabled || s.File != DefaultLocalLogFile() {
			t.Errorf("got %+v", s)
		}
	})

	t.Run("enabled with no folder uses the default", func(t *testing.T) {
		writeCache(t, "claude-code", `{"security":{"localLogs":{"enabled":true,"path":"  "}}}`)
		s := LocalLogsSetting()
		if !s.Enabled || !s.UsableHere || s.File != DefaultLocalLogFile() {
			t.Errorf("got %+v", s)
		}
	})

	t.Run("a folder from another OS falls back rather than dropping", func(t *testing.T) {
		writeCache(t, "claude-code", `{"security":{"localLogs":{"enabled":true,"path":"C:/logs/"}}}`)
		s := LocalLogsSetting()
		if !s.Enabled {
			t.Fatalf("got %+v", s)
		}
		if s.UsableHere {
			t.Errorf("a Windows path should not be usable on this host: %+v", s)
		}
		if s.File != DefaultLocalLogFile() {
			t.Errorf("entries must still land somewhere: %+v", s)
		}
		if s.ConfiguredPath != "C:/logs/" {
			t.Errorf("the configured folder should be reported verbatim: %+v", s)
		}
	})

	t.Run("an existing folder is used", func(t *testing.T) {
		dir := t.TempDir()
		writeCache(t, "claude-code", `{"security":{"localLogs":{"enabled":true,"path":"`+dir+`/"}}}`)
		s := LocalLogsSetting()
		want := filepath.Join(dir, "solongate-audit.jsonl")
		if !s.Enabled || !s.UsableHere || s.File != want {
			t.Errorf("got %+v, want file %s", s, want)
		}
	})
}

// A cache that carries no answer must not out-vote one that does. An older
// agent's cache without the localLogs field used to silently win.
func TestLocalLogsSkipsCachesWithNoAnswer(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeCache(t, "old-agent", `{"security":{}}`)
	writeCache(t, "new-agent", `{"security":{"localLogs":{"enabled":true,"path":""}}}`)
	if s := LocalLogsSetting(); !s.Enabled {
		t.Errorf("the cache with an answer was ignored: %+v", s)
	}
}

// A policy cache carrying `security: null` is an ANSWER, not an absence, and
// the two have to stay distinguishable.
func TestPolicyCacheDistinguishesNullSecurity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}

	writeCache(t, "a", `{"policy":null,"security":null}`)
	c := LoadPolicyCache("a")
	if c == nil {
		t.Fatal("cache did not load")
	}
	if !c.HasSecurity {
		t.Error("an explicit null security should still count as present")
	}
	if c.Security != nil {
		t.Error("null security should decode to nil")
	}

	writeCache(t, "b", `{"policy":null}`)
	c = LoadPolicyCache("b")
	if c == nil {
		t.Fatal("cache did not load")
	}
	if c.HasSecurity {
		t.Error("an absent security field should not count as present")
	}
}

// TUI notifications default ON, so an absent field must not read as off.
func TestTUIConfigDefaults(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}

	if cfg := LoadTUIConfig(); !cfg.Notifications {
		t.Error("no file should mean notifications on")
	}
	if err := os.WriteFile(TUIConfigPath(), []byte(`{"accent":"cyan"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := LoadTUIConfig()
	if !cfg.Notifications {
		t.Error("an absent notifications field should mean on")
	}
	if cfg.Accent != "cyan" {
		t.Errorf("accent = %q", cfg.Accent)
	}
	if err := os.WriteFile(TUIConfigPath(), []byte(`{"notifications":false,"pollMs":500}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if cfg := LoadTUIConfig(); cfg.Notifications || cfg.PollMs != 500 {
		t.Errorf("explicit settings ignored: %+v", cfg)
	}
}

func writeCred(t *testing.T, c Credential) {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(CredentialPath(), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeCache(t *testing.T, agent, body string) {
	t.Helper()
	if err := os.WriteFile(PolicyCachePath(agent), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
}
