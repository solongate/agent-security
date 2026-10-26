// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
)

// releasePublicKeyB64 is the public half of the one-time release-signing
// keypair generated for .github/workflows/release.yaml. The matching private
// key lives only in the RELEASE_SIGNING_KEY repository secret; it is never
// committed. Embedding the public key here means it ships inside every built
// solongate binary with no runtime fetch and nothing a compromised remote can
// substitute.
const releasePublicKeyB64 = "00sq66KTpvmaRJl9ZT8bWabsuAPEdD+dgq43IwkxuUQ="

// ReleasePublicKey verifies the TAG_SIG asset release.yaml attaches to each
// tagged release. solongate update refuses to move to a tag whose signature
// does not verify against this key.
var ReleasePublicKey = mustDecodeReleaseKey(releasePublicKeyB64)

func mustDecodeReleaseKey(b64 string) ed25519.PublicKey {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic("crypto: invalid embedded release public key")
	}
	return ed25519.PublicKey(b)
}
