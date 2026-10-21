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
	priv, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		fmt.Fprintln(os.Stderr, "sign-release: RELEASE_SIGNING_KEY is not a valid base64 Ed25519 private key")
		os.Exit(1)
	}

	sig := crypto.Sign(ed25519.PrivateKey(priv), []byte(tag+" "+sha))
	fmt.Println(base64.StdEncoding.EncodeToString(sig))
}
