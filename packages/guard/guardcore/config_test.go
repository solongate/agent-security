// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package guardcore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	pcrypto "github.com/solongate/agent-security/packages/crypto"
	"github.com/solongate/agent-security/packages/shared"
)

func TestSecurityInsidePolicy(t *testing.T) {
	cases := []struct {
		name    string
		doc     []byte
		wantOK  bool
		wantNil bool
	}{
		{"empty document", nil, false, true},
		{"no security field", []byte(`{"id":"x"}`), false, true},
		{"security is explicitly null", []byte(`{"security":null}`), false, true},
		{"security is an empty object", []byte(`{"security":{}}`), true, false},
		{"security carries real fields", []byte(`{"security":{"requireSandbox":true}}`), true, false},
		{"the whole document is malformed", []byte(`{not json`), false, true},
		{"security is not an object", []byte(`{"security":"nope"}`), false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sec, ok := securityInsidePolicy(c.doc)
			if ok != c.wantOK {
				t.Errorf("ok = %v, want %v", ok, c.wantOK)
			}
			if (sec == nil) != c.wantNil {
				t.Errorf("sec == nil is %v, want %v", sec == nil, c.wantNil)
			}
		})
	}
}

func TestSecurityInsidePolicyReadsRealFields(t *testing.T) {
	sec, ok := securityInsidePolicy([]byte(`{"security":{"requireSandbox":true,"dlpBlock":{"patterns":["JWT"]}}}`))
	if !ok || sec == nil {
		t.Fatal("expected security to be found")
	}
	if !sec.RequireSandbox {
		t.Error("RequireSandbox did not round-trip")
	}
	if sec.DLPBlock == nil || len(sec.DLPBlock.Patterns) != 1 || sec.DLPBlock.Patterns[0] != "JWT" {
		t.Errorf("DLPBlock did not round-trip: %+v", sec.DLPBlock)
	}
}

func sgHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func writeOwnPolicy(t *testing.T, raw []byte) {
	t.Helper()
	own := filepath.Join(shared.SGDir(), "policy.json")
	if err := os.MkdirAll(filepath.Dir(own), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(own, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeProjectPolicy(t *testing.T, cwd string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(cwd, "policy.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func marshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLoadLocalPolicyFileWithNoFilesReturnsNil(t *testing.T) {
	sgHome(t)
	cwd := t.TempDir()

	env, err := LoadLocalPolicyFile(cwd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env != nil {
		t.Errorf("expected nil cache, got %+v", env)
	}
}

func TestLoadLocalPolicyFileOwnUnsignedEnvelope(t *testing.T) {
	sgHome(t)
	cwd := t.TempDir()

	doc := map[string]interface{}{
		"_ts": float64(1700000000000),
		"policy": map[string]interface{}{
			"id":   "home-pol",
			"name": "Home",
			"mode": "advisory",
		},
		"security":    map[string]interface{}{"requireSandbox": true},
		"selfProtect": true,
	}
	writeOwnPolicy(t, marshal(t, doc))

	env, err := LoadLocalPolicyFile(cwd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env == nil {
		t.Fatal("expected a policy cache, got nil")
	}
	if env.Policy == nil || env.Policy.ID != "home-pol" {
		t.Fatalf("policy did not load correctly: %+v", env.Policy)
	}
	if !env.HasSecurity || env.Security == nil || !env.Security.RequireSandbox {
		t.Errorf("security did not load correctly: hasSecurity=%v security=%+v", env.HasSecurity, env.Security)
	}
	if env.SelfProtect == nil || !*env.SelfProtect {
		t.Errorf("selfProtect did not load correctly: %+v", env.SelfProtect)
	}
}

func TestLoadLocalPolicyFileOwnSignedAndValid(t *testing.T) {
	sgHome(t)
	cwd := t.TempDir()

	kp, err := pcrypto.LoadOrCreateKeyPair(filepath.Join(shared.SGDir(), "crypto"))
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]interface{}{
		"policy": map[string]interface{}{"id": "signed-pol", "name": "Signed", "mode": "advisory"},
	}
	signed, err := pcrypto.SignDocument(kp, doc)
	if err != nil {
		t.Fatal(err)
	}
	writeOwnPolicy(t, marshal(t, signed))

	env, err := LoadLocalPolicyFile(cwd)
	if err != nil {
		t.Fatalf("a validly signed policy file was rejected: %v", err)
	}
	if env == nil || env.Policy == nil || env.Policy.ID != "signed-pol" {
		t.Fatalf("policy did not load correctly: %+v", env)
	}
}

func TestLoadLocalPolicyFileOwnSignedAndTamperedIsRejected(t *testing.T) {
	sgHome(t)
	cwd := t.TempDir()

	kp, err := pcrypto.LoadOrCreateKeyPair(filepath.Join(shared.SGDir(), "crypto"))
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]interface{}{
		"policy":      map[string]interface{}{"id": "signed-pol", "name": "Signed", "mode": "advisory"},
		"selfProtect": true,
	}
	signed, err := pcrypto.SignDocument(kp, doc)
	if err != nil {
		t.Fatal(err)
	}
	body := marshal(t, signed)

	// Tamper with the document after signing, without re-signing it - this
	// simulates a direct edit to policy.json that bypassed SolonGate.
	var tampered map[string]interface{}
	if err := json.Unmarshal(body, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered["selfProtect"] = false
	writeOwnPolicy(t, marshal(t, tampered))

	env, err := LoadLocalPolicyFile(cwd)
	if !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("got err=%v, want ErrPolicyTampered", err)
	}
	if env != nil {
		t.Errorf("expected no cache on a tampered file, got %+v", env)
	}
}

func TestLoadLocalPolicyFileProjectLocalStripsSecurityAndSelfProtect(t *testing.T) {
	sgHome(t)
	cwd := t.TempDir()

	doc := map[string]interface{}{
		"id":          "proj-pol",
		"name":        "Project",
		"mode":        "advisory",
		"security":    map[string]interface{}{"requireSandbox": true},
		"selfProtect": true,
	}
	writeProjectPolicy(t, cwd, marshal(t, doc))

	env, err := LoadLocalPolicyFile(cwd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env == nil || env.Policy == nil || env.Policy.ID != "proj-pol" {
		t.Fatalf("policy did not load correctly: %+v", env)
	}
	if env.HasSecurity || env.Security != nil {
		t.Errorf("a project-local policy file must never carry trusted security settings: hasSecurity=%v security=%+v",
			env.HasSecurity, env.Security)
	}
	if env.SelfProtect != nil {
		t.Errorf("a project-local policy file must never override selfProtect: %+v", env.SelfProtect)
	}
}

func TestLoadLocalPolicyFileOwnTakesPrecedenceOverProjectLocal(t *testing.T) {
	sgHome(t)
	cwd := t.TempDir()

	writeOwnPolicy(t, marshal(t, map[string]interface{}{
		"policy": map[string]interface{}{"id": "home-pol", "name": "Home", "mode": "advisory"},
	}))
	writeProjectPolicy(t, cwd, marshal(t, map[string]interface{}{
		"id": "proj-pol", "name": "Project", "mode": "advisory",
	}))

	env, err := LoadLocalPolicyFile(cwd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env == nil || env.Policy == nil || env.Policy.ID != "home-pol" {
		t.Fatalf("expected the own policy to win, got %+v", env)
	}
}

func TestLoadLocalPolicyFileCorruptOwnFileIsRejectedNotSkipped(t *testing.T) {
	sgHome(t)
	cwd := t.TempDir()

	// A home policy that cannot be parsed is a broken trust anchor, not an
	// absent one. Skipping it used to fall through to the project-local policy,
	// which carries no Security fields at all - so corrupting the file quietly
	// downgraded the guard instead of stopping it.
	writeOwnPolicy(t, []byte(`{not valid json at all`))
	writeProjectPolicy(t, cwd, marshal(t, map[string]interface{}{
		"id": "proj-pol", "name": "Project", "mode": "advisory",
	}))

	env, err := LoadLocalPolicyFile(cwd)
	if !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("got err=%v, want ErrPolicyTampered for a corrupt own policy", err)
	}
	if env != nil {
		t.Errorf("expected no cache for a corrupt own policy, got %+v", env)
	}
}

func TestLoadLocalPolicyFileResolvesCwdFromGetwdWhenEmpty(t *testing.T) {
	sgHome(t)

	writeOwnPolicy(t, marshal(t, map[string]interface{}{
		"policy": map[string]interface{}{"id": "home-pol", "name": "Home", "mode": "advisory"},
	}))

	env, err := LoadLocalPolicyFile("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env == nil || env.Policy == nil || env.Policy.ID != "home-pol" {
		t.Fatalf("expected the own policy to load with an empty cwd, got %+v", env)
	}
}
func TestLoadLocalPolicyFileOwnMalformedSignatureIsRejected(t *testing.T) {
	sgHome(t)
	cwd := t.TempDir()

	// A signature field that is present but cannot even be decoded: the loader
	// used to skip the check on any verification error and trust the file.
	doc := map[string]interface{}{
		"policy": map[string]interface{}{"id": "home-pol", "name": "Home", "mode": "advisory"},
		"_sig":   "%not-base64%",
	}
	writeOwnPolicy(t, marshal(t, doc))

	env, err := LoadLocalPolicyFile(cwd)
	if !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("got err=%v, want ErrPolicyTampered for an undecodable signature", err)
	}
	if env != nil {
		t.Errorf("expected no cache for an undecodable signature, got %+v", env)
	}
}

func TestLoadLocalPolicyFileOwnUnsignedAfterTheMachineHasASigningKeyIsRejected(t *testing.T) {
	sgHome(t)
	cwd := t.TempDir()

	// Once this machine has a signing key, its own policy.json is always written
	// signed, so a missing signature means the signature was stripped.
	if _, err := pcrypto.LoadOrCreateKeyPair(filepath.Join(shared.SGDir(), "crypto")); err != nil {
		t.Fatal(err)
	}
	doc := map[string]interface{}{
		"policy": map[string]interface{}{"id": "home-pol", "name": "Home", "mode": "advisory"},
	}
	writeOwnPolicy(t, marshal(t, doc))

	env, err := LoadLocalPolicyFile(cwd)
	if !errors.Is(err, ErrPolicyTampered) {
		t.Fatalf("got err=%v, want ErrPolicyTampered for a stripped signature", err)
	}
	if env != nil {
		t.Errorf("expected no cache for a stripped signature, got %+v", env)
	}
}

func TestLoadLocalPolicyFileDoesNotCreateASigningKey(t *testing.T) {
	sgHome(t)
	cwd := t.TempDir()

	// Pre-signature installs and the parity fixtures write an unsigned
	// policy.json. Loading it must not create a key pair: if it did, the next run
	// would see a keyed machine and reject the very same file.
	doc := map[string]interface{}{
		"policy":   map[string]interface{}{"id": "home-pol", "name": "Home", "mode": "advisory"},
		"security": map[string]interface{}{"protectedPaths": []string{"/tmp/keep"}},
	}
	writeOwnPolicy(t, marshal(t, doc))

	for i := 0; i < 2; i++ {
		env, err := LoadLocalPolicyFile(cwd)
		if err != nil {
			t.Fatalf("load %d: got err=%v, want the unsigned policy to load", i+1, err)
		}
		if env == nil || env.Policy == nil || env.Policy.ID != "home-pol" {
			t.Fatalf("load %d: got %+v, want the home policy", i+1, env)
		}
		if pcrypto.HasKeyPair(filepath.Join(shared.SGDir(), "crypto")) {
			t.Fatalf("load %d: loading a policy created a signing key", i+1)
		}
	}
}
