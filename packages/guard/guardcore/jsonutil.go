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

func JsOrRaw(f map[string]json.RawMessage, keys ...string) json.RawMessage {
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
			return v
		}
	}
	return nil
}

func JsOrString(f map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		v, ok := f[k]
		if !ok || len(v) == 0 {
			continue
		}
		var probe interface{}
		if json.Unmarshal(v, &probe) != nil {
			continue
		}
		if !policy.JSTruthy(probe) {
			continue
		}
		return policy.JSToString(probe)
	}
	return ""
}
