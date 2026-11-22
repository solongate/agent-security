// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

// sign-release signs "<tag> <commit-sha>" with the release-signing private
// key and writes the base64 signature to stdout. It exists so
// .github/workflows/release.yaml never handles the raw private key bytes
// itself beyond passing the RELEASE_SIGNING_KEY secret through the
// environment - the signing logic stays in packages/crypto like everything
// else cryptographic in this repo.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/solongate/agent-security/packages/crypto"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: sign-release <tag> <commit-sha>")
		os.Exit(2)
	}
	tag, sha := os.Args[1], os.Args[2]

	keyB64 := os.Getenv("RELEASE_SIGNING_KEY")
	if keyB64 == "" {
		fmt.Fprintln(os.Stderr, "sign-release: RELEASE_SIGNING_KEY is not set")
		os.Exit(1)
	}
	priv, err := decodeReleaseKey(keyB64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sign-release: "+err.Error())
		os.Exit(1)
	}

	sig := crypto.Sign(ed25519.PrivateKey(priv), []byte(tag+" "+sha))
	fmt.Println(base64.StdEncoding.EncodeToString(sig))
}

// decodeReleaseKey decodes the base64 release-signing private key, keeping
// the two failure modes distinct: a value that is not base64 at all and a
// value that decodes to the wrong number of bytes need different fixes when
// RELEASE_SIGNING_KEY is misconfigured in CI, so they get different errors.
func decodeReleaseKey(keyB64 string) (ed25519.PrivateKey, error) {
	priv, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("RELEASE_SIGNING_KEY is not valid base64: %w", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("RELEASE_SIGNING_KEY decoded to %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(priv), nil
}
