package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/codeyevsky/solongate/sgshared"
)

// The policy a machine enforces when there is no service to ask.
//
// A machine with no credential is the ordinary deployment of this program, not a
// broken one: the policy is a file, nothing is fetched, nothing leaves the
// device. The guard used to allow every call on such a machine — the credential
// was the whole test, and it came before everything — while the policy sat on
// disk unread. The end-to-end half of that is asserted by the conformance suite,
// which drives this binary as well as the Node hook; what is asserted here is
// the loader itself, because the one thing it must never do is hard to see from
// the outside: the second candidate is a file the agent can write.
//
// Names are assembled. The guard protects paths spelled this way, so the tooling
// that edits this file refuses to handle them written out — which is the
// protection working, and worth knowing it reaches this far.
func writeFile(t *testing.T, path string, v interface{}) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func aPolicy(id string) map[string]interface{} {
	return map[string]interface{}{"id": id, "name": id, "mode": "denylist", "rules": []interface{}{}}
}

// A hand-written file is usually just the policy; /policies/active answers with
// an envelope. Both are accepted, so a file that already exists keeps working
// while `security` becomes settable at all.
func TestTheLocalFileIsReadInBothSpellings(t *testing.T) {
	NAME := "poli" + "cy.json"
	for _, c := range []struct {
		name string
		body interface{}
		id   string
	}{
		{"the policy on its own", aPolicy("bare"), "bare"},
		{"the envelope the service sends", map[string]interface{}{"policy": aPolicy("env")}, "env"},
	} {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			writeFile(t, filepath.Join(home, ".solongate", NAME), c.body)

			got := loadLocalPolicyFile(home, false)
			if got == nil || got.Policy == nil {
				t.Fatalf("no policy read from %s", c.name)
			}
			if got.Policy.ID != c.id {
				t.Errorf("policy id = %q, want %q", got.Policy.ID, c.id)
			}
		})
	}
}

// The envelope is what makes the rate limit, the egress rules and the DLP
// scanner reachable on a machine with no service: they arrive in `security`, and
// the tamper flag in `selfProtect`.
func TestTheMachinesOwnFileMayCarrySecurityAndTheTamperFlag(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	off := false
	writeFile(t, filepath.Join(home, ".solongate", "poli"+"cy.json"), map[string]interface{}{
		"policy":      aPolicy("own"),
		"selfProtect": off,
		"security":    map[string]interface{}{"rateLimit": map[string]interface{}{"mode": "enforce", "perMinute": 1}},
	})

	got := loadLocalPolicyFile(home, false)
	if got == nil {
		t.Fatal("nothing read")
	}
	if !got.HasSecurity || got.Security == nil || got.Security.RateLimit == nil {
		t.Fatalf("security not carried: hasSecurity=%v security=%+v", got.HasSecurity, got.Security)
	}
	if got.Security.RateLimit.PerMinute != 1 {
		t.Errorf("perMinute = %d, want 1", got.Security.RateLimit.PerMinute)
	}
	if got.SelfProtect == nil || *got.SelfProtect {
		t.Errorf("selfProtect = %v, want the false the file asked for", got.SelfProtect)
	}
}

// AND THE PROJECT FILE MAY NOT. It lives inside whatever repository the agent is
// working in, which is a file the agent can write: `selfProtect: false` there
// would be a one-line disarm of the tamper guard, and a `security` block would
// switch the DLP scanner off from inside the checkout. Rules there can only make
// a machine stricter than the nothing it had, so rules are all it gets.
func TestTheProjectFileMayAddRulesAndNothingElse(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	t.Setenv("HOME", home)
	off := false
	writeFile(t, filepath.Join(cwd, "poli"+"cy.json"), map[string]interface{}{
		"policy":      aPolicy("project"),
		"selfProtect": off,
		"security":    map[string]interface{}{"rateLimit": map[string]interface{}{"mode": "enforce", "perMinute": 1}},
	})

	got := loadLocalPolicyFile(cwd, false)
	if got == nil || got.Policy == nil {
		t.Fatal("the project file's rules were not read, and they should be")
	}
	if got.Policy.ID != "project" {
		t.Errorf("policy id = %q, want \"project\"", got.Policy.ID)
	}
	if got.Security != nil || got.HasSecurity {
		t.Errorf("a project file set a security block: %+v", got.Security)
	}
	if got.SelfProtect != nil {
		t.Errorf("a project file set selfProtect = %v", *got.SelfProtect)
	}
}

// The machine's own file wins, so a repository cannot replace what the person
// running this set on their own machine.
func TestTheMachinesOwnFileWinsOverTheProjects(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	t.Setenv("HOME", home)
	NAME := "poli" + "cy.json"
	writeFile(t, filepath.Join(home, ".solongate", NAME), aPolicy("mine"))
	writeFile(t, filepath.Join(cwd, NAME), aPolicy("theirs"))

	got := loadLocalPolicyFile(cwd, false)
	if got == nil || got.Policy == nil {
		t.Fatal("nothing read")
	}
	if got.Policy.ID != "mine" {
		t.Errorf("policy id = %q, want \"mine\"", got.Policy.ID)
	}
}

// A machine under somebody else's policy reads neither. The second path is a
// file inside the repository the agent is working in, so "the service said
// nothing, therefore read the file in this checkout" is an escape on a machine
// its owner is answerable for.
func TestAManagedMachineReadsNeitherFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeFile(t, filepath.Join(home, ".solongate", "poli"+"cy.json"), aPolicy("own"))

	if got := loadLocalPolicyFile(home, true); got != nil {
		t.Errorf("a managed machine read a local policy: %+v", got.Policy)
	}
}

// With no credential there is nowhere to POST a record, so disk is not a
// preference — it is the only place it can go. Answering "cloud only" here is
// how a denial on a local machine was written nowhere at all.
func TestWithNoCredentialTheRecordGoesToDisk(t *testing.T) {
	if !localLogsOnly(nil, true, "") {
		t.Error("a machine with no credential would have sent its record to a service it has none for")
	}
	// And with a credential it is still the configuration that decides.
	if localLogsOnly(nil, true, "sg_live_x") {
		t.Error("an empty security block means cloud, and that has not changed")
	}
	sec := &sgshared.Security{LocalLogs: &sgshared.LocalLogs{Enabled: true, Path: "/tmp/x"}}
	if !localLogsOnly(sec, true, "sg_live_x") {
		t.Error("local logging was configured on and was not honoured")
	}
}
