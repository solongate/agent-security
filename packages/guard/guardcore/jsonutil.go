// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package guardcore

import (
	"encoding/json"

	"github.com/solongate/agent-security/packages/policy"
)

func RawFields(b json.RawMessage) map[string]json.RawMessage {
	m := map[string]json.RawMessage{}
	if len(b) == 0 {
		return m
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]json.RawMessage{}
	}
	return m
}

// firstTruthyRaw returns the raw value of the first key in keys whose value
// parses as JSON and is truthy in the JS sense (see policy.JSTruthy).
// Missing, empty, malformed, and falsy values are skipped.
func firstTruthyRaw(f map[string]json.RawMessage, keys ...string) (json.RawMessage, bool) {
	for _, k := range keys {
		v, ok := f[k]
		if !ok || len(v) == 0 {
			continue
		}
		var probe interface{}
		if json.Unmarshal(v, &probe) != nil {
			continue
		}
		if policy.JSTruthy(probe) {
			return v, true
		}
	}
	return nil, false
}

func JsOrRaw(f map[string]json.RawMessage, keys ...string) json.RawMessage {
	v, ok := firstTruthyRaw(f, keys...)
	if !ok {
		return nil
	}
	return v
}

func JsOrString(f map[string]json.RawMessage, keys ...string) string {
	v, ok := firstTruthyRaw(f, keys...)
	if !ok {
		return ""
	}
	var probe interface{}
	if json.Unmarshal(v, &probe) != nil {
		return ""
	}
	return policy.JSToString(probe)
}
