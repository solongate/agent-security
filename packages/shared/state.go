// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package shared

import "encoding/json"

type DLPCustom struct {
	Name string `json:"name"`
	Re   string `json:"re"`
}

type DLPConfig struct {
	Patterns []string    `json:"patterns"`
	Custom   []DLPCustom `json:"custom"`
}

type RateLimit struct {
	Mode      string `json:"mode"`
	PerMinute int    `json:"perMinute"`
	PerHour   int    `json:"perHour"`
	PerDay    int    `json:"perDay"`
}

type LocalLogs struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

type Security struct {
	DLPBlock  *DLPConfig `json:"dlpBlock"`
	DLPRedact *DLPConfig `json:"dlpRedact"`

	DLPObserve *DLPConfig `json:"dlpObserve"`
	RateLimit  *RateLimit `json:"rateLimit"`

	RateLimitObserve *RateLimit `json:"rateLimitObserve"`
	LocalLogs        *LocalLogs `json:"localLogs"`

	ProtectedPaths []string `json:"protectedPaths,omitempty"`

	Sandboxes []Sandbox `json:"sandboxes,omitempty"`

	RequireSandbox bool `json:"requireSandbox,omitempty"`
}

type Sandbox struct {
	ID string `json:"id"`

	Dir string `json:"dir"`

	Network bool `json:"network"`

	Label string `json:"label,omitempty"`
}

type Policy struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Mode  string          `json:"mode"`
	Rules json.RawMessage `json:"rules"`

	Agents []string `json:"agents,omitempty"`
}

func (p *Policy) AppliesTo(client string) bool {
	if p == nil || len(p.Agents) == 0 {
		return true
	}
	for _, a := range p.Agents {
		if a == "*" || a == client {
			return true
		}
	}
	return false
}

type PolicyCache struct {
	TS          int64     `json:"_ts"`
	Policy      *Policy   `json:"policy"`
	SelfProtect *bool     `json:"selfProtect"`
	Security    *Security `json:"security"`

	HasSecurity bool `json:"-"`
}

func (c *PolicyCache) UnmarshalJSON(b []byte) error {
	type raw PolicyCache
	var r raw
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	*c = PolicyCache(r)
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err == nil {
		_, c.HasSecurity = probe["security"]
	}
	return nil
}