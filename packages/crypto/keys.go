// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

// Package crypto holds every cryptographic primitive SolonGate uses: the
// local machine identity that signs policy.json, document signing, and
// release-tag signature verification for self-update. Nothing outside this
// package should implement signing or verification directly - consumers
// call into it instead.
package crypto

import (
	"bytes"
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

var errCorruptKey = errors.New("crypto: machine key files are corrupt")

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
//
// machine.key is the identity and machine.pub is derived from it, so a
// surviving private key is never replaced: a missing machine.pub is rewritten
// from it, and a machine.pub that does not belong to it is an error. Replacing
// the key would silently change what this machine signs with and destroy the
// only copy of the old one.
func LoadOrCreateKeyPair(dir string) (KeyPair, error) {
	keyPath := filepath.Join(dir, privateKeyFile)

	priv, err := readPrivateKey(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		if priv, err = createPrivateKey(dir, keyPath); err != nil {
			return KeyPair{}, err
		}
		// A machine.pub already here belonged to a private key that is gone,
		// or is this same key's, written by a run that raced this one. Either
		// way it is replaced rather than compared.
		pub := priv.Public().(ed25519.PublicKey)
		if err := writePublicKey(dir, pub); err != nil {
			return KeyPair{}, err
		}
		return KeyPair{Public: pub, Private: priv}, nil
	}
	if err != nil {
		return KeyPair{}, err
	}

	pub := priv.Public().(ed25519.PublicKey)
	onDisk, err := os.ReadFile(filepath.Join(dir, publicKeyFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := writePublicKey(dir, pub); err != nil {
			return KeyPair{}, err
		}
	case err != nil:
		return KeyPair{}, err
	case !bytes.Equal(onDisk, pub):
		return KeyPair{}, errors.New("crypto: machine.pub is not the public half of machine.key")
	}
	return KeyPair{Public: pub, Private: priv}, nil
}

// readPrivateKey loads machine.key and checks that it is a whole Ed25519 key:
// the public half embedded in its last 32 bytes must be the one its seed
// derives, or every signature made with it fails to verify.
func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, errCorruptKey
	}
	priv := ed25519.PrivateKey(b)
	if !bytes.Equal(ed25519.NewKeyFromSeed(priv.Seed()), priv) {
		return nil, errCorruptKey
	}
	return priv, nil
}

// createPrivateKey publishes a new machine.key with a hard link, which fails if
// the file already exists. Two first runs racing here therefore end up with one
// key: the loser drops the key it generated and loads the winner's, instead of
// overwriting it after the winner may already have signed with it. The key is
// written to a temporary file first, so machine.key never exists half-written.
func createPrivateKey(dir, path string) (ed25519.PrivateKey, error) {
	kp, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	tmp, err := writeTemp(dir, kp.Private, 0o600)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp)
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return readPrivateKey(path)
		}
		return nil, err
	}
	return kp.Private, nil
}

// writePublicKey replaces machine.pub in one rename, so a reader sees either
// the old file or the new one, never a partial write.
func writePublicKey(dir string, pub ed25519.PublicKey) error {
	tmp, err := writeTemp(dir, pub, 0o644)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, publicKeyFile)); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func writeTemp(dir string, data []byte, perm os.FileMode) (string, error) {
	f, err := os.CreateTemp(dir, ".machine-*.tmp")
	if err != nil {
		return "", err
	}
	name := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(name, perm)
	}
	if err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

// Fingerprint returns a short, human-displayable identifier for a public key.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}