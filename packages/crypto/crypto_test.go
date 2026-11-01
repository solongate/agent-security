// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package crypto

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("policy.json contents")
	sig := Sign(kp.Private, payload)
	if !Verify(kp.Public, payload, sig) {
		t.Fatal("expected signature to verify")
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("policy.json contents")
	sig := Sign(kp.Private, payload)
	tampered := []byte("policy.json contentS")
	if Verify(kp.Public, tampered, sig) {
		t.Fatal("expected tampered payload to fail verification")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("policy.json contents")
	sig := Sign(kp.Private, payload)
	if Verify(other.Public, payload, sig) {
		t.Fatal("expected signature to fail against the wrong public key")
	}
}

func TestLoadOrCreateKeyPairIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Public) != string(second.Public) {
		t.Fatal("expected the same key pair to be loaded on the second call")
	}
}

func TestLoadOrCreateKeyPairWritesFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "crypto")
	if _, err := LoadOrCreateKeyPair(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKeyPair(dir); err != nil {
		t.Fatalf("second load of freshly created keys failed: %v", err)
	}
}

func TestSignVerifyDocumentRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{"policy": "default", "version": float64(1)}

	signed, err := SignDocument(kp, doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}

	payload, isSigned, valid, err := VerifyDocument(raw, kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !isSigned || !valid {
		t.Fatalf("expected signed=true valid=true, got signed=%v valid=%v", isSigned, valid)
	}
	if payload["policy"] != "default" {
		t.Fatalf("expected payload to round-trip, got %v", payload)
	}
}

func TestVerifyDocumentDetectsTamper(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{"policy": "default"}
	signed, err := SignDocument(kp, doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}

	// Flip the last 'd', not the first: map keys marshal as
	// _sig, _sig_pub, policy (alphabetical), so the first 'd' can land
	// inside _sig_pub's base64 - a field VerifyDocument deliberately
	// ignores (it trusts the caller's key, never the document's own
	// embedded one), making that tamper invisible to verification.
	// "policy":"default" is the last field, so searching from the end
	// guarantees the flip lands in the actually-verified payload.
	tampered := make([]byte, len(raw))
	copy(tampered, raw)
	for i := len(tampered) - 1; i >= 0; i-- {
		if tampered[i] == 'd' {
			tampered[i] = 'x'
			break
		}
	}

	_, isSigned, valid, err := VerifyDocument(tampered, kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !isSigned {
		t.Fatal("expected the tampered document to still report as signed")
	}
	if valid {
		t.Fatal("expected the tampered document to fail verification")
	}
}

func TestVerifyDocumentTreatsMissingSignatureAsUnsigned(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"policy":"default"}`)
	_, signed, valid, err := VerifyDocument(raw, kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	if signed || valid {
		t.Fatalf("expected signed=false valid=false for a legacy unsigned document, got signed=%v valid=%v", signed, valid)
	}
}

func TestFingerprintIsStableAndDistinct(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(kp1.Public) != Fingerprint(append([]byte(nil), kp1.Public...)) {
		t.Fatal("fingerprint should be stable for the same key")
	}
	if Fingerprint(kp1.Public) == Fingerprint(kp2.Public) {
		t.Fatal("fingerprint should differ between distinct keys")
	}
}
func TestHasKeyPair(t *testing.T) {
	dir := t.TempDir()
	if HasKeyPair(dir) {
		t.Error("HasKeyPair = true on an empty directory, want false")
	}
	if _, err := LoadOrCreateKeyPair(dir); err != nil {
		t.Fatal(err)
	}
	if !HasKeyPair(dir) {
		t.Error("HasKeyPair = false after LoadOrCreateKeyPair created the pair, want true")
	}
}

func TestLoadOrCreateKeyPairRestoresMissingPublicKey(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, publicKeyFile)); err != nil {
		t.Fatal(err)
	}

	second, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second.Private, first.Private) || !bytes.Equal(second.Public, first.Public) {
		t.Fatal("a missing machine.pub replaced the surviving machine.key with a new identity")
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, privateKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, first.Private) {
		t.Fatal("machine.key on disk was overwritten")
	}
	pub, err := os.ReadFile(filepath.Join(dir, publicKeyFile))
	if err != nil {
		t.Fatalf("machine.pub was not rewritten: %v", err)
	}
	if !bytes.Equal(pub, first.Public) {
		t.Fatal("the rewritten machine.pub is not the public half of machine.key")
	}
}

func TestLoadOrCreateKeyPairRejectsMismatchedPair(t *testing.T) {
	dir := t.TempDir()
	mine, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, publicKeyFile)
	if err := os.WriteFile(pubPath, other.Public, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrCreateKeyPair(dir); err == nil {
		t.Fatal("a machine.pub from another key pair was accepted")
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, privateKeyFile))
	if err != nil || !bytes.Equal(onDisk, mine.Private) {
		t.Fatal("rejecting the pair still touched machine.key")
	}
	if pub, err := os.ReadFile(pubPath); err != nil || !bytes.Equal(pub, other.Public) {
		t.Fatal("rejecting the pair rewrote machine.pub, hiding what was found")
	}
}

func TestLoadOrCreateKeyPairRejectsInconsistentPrivateKey(t *testing.T) {
	dir := t.TempDir()
	kp, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	// The right length, but the public half it carries is not the one its seed derives.
	spliced := append(append([]byte{}, kp.Private.Seed()...), other.Public...)
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), spliced, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKeyPair(dir); err == nil {
		t.Fatal("a machine.key whose halves do not belong together was accepted")
	}
}

func TestLoadOrCreateKeyPairReplacesOrphanedPublicKey(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, privateKeyFile)); err != nil {
		t.Fatal(err)
	}

	second, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatalf("a machine.pub with no private key left blocked creating a new pair: %v", err)
	}
	if bytes.Equal(second.Public, first.Public) {
		t.Fatal("a new key pair was expected once the private key was gone")
	}
	if _, err := LoadOrCreateKeyPair(dir); err != nil {
		t.Fatalf("the new pair does not load back: %v", err)
	}
}

func TestLoadOrCreateKeyPairConcurrentFirstRunsAgree(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "crypto")
	const runs = 16
	got := make([]KeyPair, runs)
	errs := make([]error, runs)
	var wg sync.WaitGroup
	for i := range runs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], errs[i] = LoadOrCreateKeyPair(dir)
		}()
	}
	wg.Wait()

	for i := range runs {
		if errs[i] != nil {
			t.Fatalf("run %d: %v", i, errs[i])
		}
		if !bytes.Equal(got[i].Private, got[0].Private) {
			t.Fatal("concurrent first runs came back with different key pairs")
		}
	}
	loaded, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatalf("the pair left on disk does not load: %v", err)
	}
	if !bytes.Equal(loaded.Private, got[0].Private) {
		t.Fatal("the key on disk is not the one every run was handed")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != privateKeyFile && e.Name() != publicKeyFile {
			t.Errorf("left behind %s", e.Name())
		}
	}
}

func TestLoadOrCreateKeyPairFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not have Unix permission bits")
	}
	dir := t.TempDir()
	if _, err := LoadOrCreateKeyPair(dir); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]os.FileMode{privateKeyFile: 0o600, publicKeyFile: 0o644} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != want {
			t.Errorf("%s has mode %v, want %v", name, got, want)
		}
	}
}
