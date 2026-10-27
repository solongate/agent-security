// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

// Package crypto holds every cryptographic primitive SolonGate uses: the
// local machine identity that signs policy.json, document signing, and
// release-tag signature verification for self-update. Nothing outside this
// package should implement signing or verification directly - consumers
// call into it instead.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

const (
	privateKeyFile = "machine.key"
	publicKeyFile  = "machine.pub"
)

// KeyPair is an Ed25519 signing identity.
type KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// GenerateKeyPair creates a new random Ed25519 key pair.
func GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{Public: pub, Private: priv}, nil
}

// HasKeyPair reports whether this machine already has a signing key pair in
// dir. Callers use it to tell a first run without a signing identity (where an
// unsigned document can only be legacy) from a machine that has signed before
// (where an unsigned document has had its signature stripped).
func HasKeyPair(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, privateKeyFile)); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, publicKeyFile)); err != nil {
		return false
	}
	return true
}

// LoadOrCreateKeyPair reads the machine signing key from dir, generating and
// persisting a new one on first use. The private key is written with 0600
// permissions; the public key with 0644 so it can be read for verification
// without exposing the private half.
func LoadOrCreateKeyPair(dir string) (KeyPair, error) {
	keyPath := filepath.Join(dir, privateKeyFile)
	pubPath := filepath.Join(dir, publicKeyFile)

	privBytes, privErr := os.ReadFile(keyPath)
	pubBytes, pubErr := os.ReadFile(pubPath)
	if privErr == nil && pubErr == nil {
		if len(privBytes) != ed25519.PrivateKeySize || len(pubBytes) != ed25519.PublicKeySize {
			return KeyPair{}, errors.New("crypto: machine key files are corrupt")
		}
		return KeyPair{Public: ed25519.PublicKey(pubBytes), Private: ed25519.PrivateKey(privBytes)}, nil
	}
	if !errors.Is(privErr, os.ErrNotExist) && privErr != nil {
		return KeyPair{}, privErr
	}
	if !errors.Is(pubErr, os.ErrNotExist) && pubErr != nil {
		return KeyPair{}, pubErr
	}

	kp, err := GenerateKeyPair()
	if err != nil {
		return KeyPair{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return KeyPair{}, err
	}
	if err := os.WriteFile(keyPath, kp.Private, 0o600); err != nil {
		return KeyPair{}, err
	}
	if err := os.WriteFile(pubPath, kp.Public, 0o644); err != nil {
		return KeyPair{}, err
	}
	return kp, nil
}

// Fingerprint returns a short, human-displayable identifier for a public key.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}