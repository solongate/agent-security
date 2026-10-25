// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestReleasePublicKeyDecodesToValidSize(t *testing.T) {
	if len(ReleasePublicKey) != ed25519.PublicKeySize {
		t.Fatalf("expected embedded release public key to be %d bytes, got %d", ed25519.PublicKeySize, len(ReleasePublicKey))
	}
}

func TestMustDecodeReleaseKeyRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(kp.Public)
	decoded := mustDecodeReleaseKey(b64)
	if string(decoded) != string(kp.Public) {
		t.Fatal("expected decoded key to match the original public key")
	}
}

func TestMustDecodeReleaseKeyPanicsOnInvalidBase64(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic for invalid base64 input")
		}
	}()
	mustDecodeReleaseKey("not valid base64!!")
}

func TestMustDecodeReleaseKeyPanicsOnWrongSize(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic for a key of the wrong size")
		}
	}()
	mustDecodeReleaseKey(base64.StdEncoding.EncodeToString([]byte("too-short")))
}
