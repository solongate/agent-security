// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package crypto

import (
	"encoding/json"
	"path/filepath"
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
