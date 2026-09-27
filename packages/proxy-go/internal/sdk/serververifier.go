package sdk

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/core"
)

// SignedRequest is a tool call that carries proof it came from the gateway.
//
// A tool server that accepts unsigned requests can be called directly, which
// makes every policy in front of it advisory. The signature covers the
// parameters AND the capability token together, so neither can be swapped for
// another call's.
type SignedRequest struct {
	Params          core.McpCallToolParams `json:"params"`
	CapabilityToken string                 `json:"capabilityToken"`
	Signature       string                 `json:"signature"`
	Timestamp       string                 `json:"timestamp"`
	Nonce           string                 `json:"nonce"`
}

type SignatureValidation struct {
	Valid  bool
	Reason string
}

// ServerVerifier signs outgoing requests and validates incoming ones.
type ServerVerifier struct {
	secret   []byte
	maxAge   time.Duration
	usedNonc *ExpiringSet
}

func NewServerVerifier(gatewaySecret string, maxAge time.Duration) (*ServerVerifier, error) {
	if len(gatewaySecret) < core.TokenMinSecretLength {
		return nil, errors.New("gateway secret must be at least 32 characters")
	}
	if maxAge <= 0 {
		maxAge = time.Minute
	}
	return &ServerVerifier{
		secret: []byte(gatewaySecret),
		maxAge: maxAge,
		// Nonces are kept for twice the acceptance window, so a request that
		// was valid when it arrived cannot be replayed the moment its nonce is
		// forgotten but before its timestamp goes stale.
		usedNonc: NewExpiringSet(maxAge * 2),
	}, nil
}

// SignRequest is the HMAC over the parameters and the token.
func (v *ServerVerifier) SignRequest(params core.McpCallToolParams, capabilityToken string) string {
	payload, err := json.Marshal(struct {
		Params          core.McpCallToolParams `json:"params"`
		CapabilityToken string                 `json:"capabilityToken"`
	}{params, capabilityToken})
	if err != nil {
		// A payload that will not marshal cannot be signed into anything a
		// verifier would accept, so sign the empty document and let validation
		// fail rather than returning a signature over partial data.
		payload = []byte("{}")
	}
	mac := hmac.New(sha256.New, v.secret)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func (v *ServerVerifier) VerifySignature(params core.McpCallToolParams, capabilityToken, signature string) bool {
	return hmac.Equal([]byte(v.SignRequest(params, capabilityToken)), []byte(signature))
}

func (v *ServerVerifier) CreateSignedRequest(params core.McpCallToolParams, capabilityToken string) (SignedRequest, error) {
	nonce, err := randomUUID()
	if err != nil {
		return SignedRequest{}, err
	}
	return SignedRequest{
		Params:          params,
		CapabilityToken: capabilityToken,
		Signature:       v.SignRequest(params, capabilityToken),
		Timestamp:       time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		Nonce:           nonce,
	}, nil
}

// ValidateSignedRequest checks freshness, uniqueness and the signature.
//
// The future-timestamp check matters as much as the age check: without it a
// request dated a year ahead is accepted forever, and clock skew is a normal
// thing rather than an attack, so a small tolerance is allowed and no more.
func (v *ServerVerifier) ValidateSignedRequest(req SignedRequest) SignatureValidation {
	t, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		return SignatureValidation{Reason: "Invalid timestamp"}
	}
	now := time.Now()
	if now.Sub(t) > v.maxAge {
		return SignatureValidation{Reason: "Request too old"}
	}
	if t.Sub(now) > 30*time.Second {
		return SignatureValidation{Reason: "Request timestamp in the future"}
	}
	if v.usedNonc.Has(req.Nonce) {
		return SignatureValidation{Reason: "Duplicate nonce (replay detected)"}
	}
	if !v.VerifySignature(req.Params, req.CapabilityToken, req.Signature) {
		return SignatureValidation{Reason: "Invalid signature"}
	}
	// The nonce is only consumed once everything else has passed, so a request
	// rejected for a bad signature does not burn a nonce a legitimate retry
	// would need.
	v.usedNonc.Add(req.Nonce)
	return SignatureValidation{Valid: true}
}
