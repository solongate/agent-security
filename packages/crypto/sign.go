// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
)

const (
	sigField    = "_sig"
	sigPubField = "_sig_pub"
)

// Sign returns the Ed25519 signature of payload under priv.
func Sign(priv ed25519.PrivateKey, payload []byte) []byte {
	return ed25519.Sign(priv, payload)
}

// Verify reports whether sig is a valid Ed25519 signature of payload under pub.
func Verify(pub ed25519.PublicKey, payload, sig []byte) bool {
	return ed25519.Verify(pub, payload, sig)
}

// SignDocument strips any existing _sig/_sig_pub fields from doc, signs the
// canonical form of what's left with kp, and returns a copy with _sig and
// _sig_pub added. It returns a map rather than marshaled bytes so the caller
// controls the final encoding (e.g. indentation) - encoding/json sorts map
// keys on marshal regardless, so this canonical form is stable either way.
func SignDocument(kp KeyPair, doc map[string]any) (map[string]any, error) {
	clean := stripSigFields(doc)
	canonical, err := json.Marshal(clean)
	if err != nil {
		return nil, err
	}
	sig := Sign(kp.Private, canonical)

	signed := make(map[string]any, len(clean)+2)
	for k, v := range clean {
		signed[k] = v
	}
	signed[sigField] = base64.StdEncoding.EncodeToString(sig)
	signed[sigPubField] = base64.StdEncoding.EncodeToString(kp.Public)
	return signed, nil
}

// VerifyDocument unmarshals raw and checks its signature against trusted -
// never against the public key embedded in the document itself, since an
// attacker rewriting the document could regenerate a matching key pair and
// re-sign. signed reports whether a signature was present at all, so a
// caller can tell a legacy unsigned document (signed == false, not
// necessarily an error) apart from a present-but-invalid one (signed ==
// true, valid == false), which should be treated as tampering.
func VerifyDocument(raw []byte, trusted ed25519.PublicKey) (payload map[string]any, signed bool, valid bool, err error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, false, false, err
	}

	sigStr, hasSig := doc[sigField].(string)
	if !hasSig {
		return stripSigFields(doc), false, false, nil
	}
	sig, err := base64.StdEncoding.DecodeString(sigStr)
	if err != nil {
		return nil, true, false, errors.New("crypto: malformed signature encoding")
	}

	clean := stripSigFields(doc)
	canonical, err := json.Marshal(clean)
	if err != nil {
		return nil, true, false, err
	}
	return clean, true, Verify(trusted, canonical, sig), nil
}

func stripSigFields(doc map[string]any) map[string]any {
	clean := make(map[string]any, len(doc))
	for k, v := range doc {
		if k == sigField || k == sigPubField {
			continue
		}
		clean[k] = v
	}
	return clean
}