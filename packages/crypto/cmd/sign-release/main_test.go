// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestDecodeReleaseKeyRejectsInvalidBase64(t *testing.T) {
	_, err := decodeReleaseKey("!!not-base64!!")
	if err == nil {
		t.Fatal("decodeReleaseKey: got no error, want a not-valid-base64 error")
	}
	if !strings.Contains(err.Error(), "not valid base64") {
		t.Errorf("error = %q, want it to say the value is not valid base64", err)
	}
	if strings.Contains(err.Error(), "decoded to") {
		t.Errorf("error = %q, want no decoded-length complaint for a base64 failure", err)
	}
}

func TestDecodeReleaseKeyRejectsWrongLength(t *testing.T) {
	// Valid base64, but only 32 bytes: a public key or a seed, not a
	// 64-byte private key.
	short := base64.StdEncoding.EncodeToString(make([]byte, 32))
	_, err := decodeReleaseKey(short)
	if err == nil {
		t.Fatal("decodeReleaseKey: got no error, want a wrong-length error")
	}
	if !strings.Contains(err.Error(), "decoded to 32 bytes, want 64") {
		t.Errorf("error = %q, want it to name the decoded length and 64", err)
	}
	if strings.Contains(err.Error(), "not valid base64") {
		t.Errorf("error = %q, want no base64 complaint for a decodable value", err)
	}
}

func TestDecodeReleaseKeyAcceptsValidKey(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	want := ed25519.NewKeyFromSeed(seed)
	got, err := decodeReleaseKey(base64.StdEncoding.EncodeToString(want))
	if err != nil {
		t.Fatalf("decodeReleaseKey: %v", err)
	}
	if !bytes.Equal([]byte(got), []byte(want)) {
		t.Errorf("decoded key differs from the encoded key")
	}
}
