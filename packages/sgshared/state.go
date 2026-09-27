// Package sgshared holds the shapes SolonGate keeps on disk, and the small
// functions that decide where on disk they go.
//
// It exists because the same declarations were written twice, in guard-go and
// in proxy-go, and the second copy immediately drifted. The drift was not a
// field: it was projectKey, hashing bytes in one module and UTF-16 code units
// in the other. That hash names a DIRECTORY and is computed independently in
// four places that never compare it, so the two implementations quietly used
// different folders for anyone whose home directory was not in English. Nothing
// errored. The dataroom just showed an empty ring.
//
// So the rule for this package is narrow and worth keeping: it holds only what
// MORE THAN ONE program must agree about. A type that one binary reads and
// nothing else writes does not belong here, because a shared package that
// collects everything becomes a reason to change it, and changing it is the
// thing that has to stay expensive.
//
// The JavaScript side is still the reference. guard.mjs, audit.mjs and the
// dataroom write these files today and will keep writing them for as long as
// the npm package is the entry point, so where this package and the JavaScript
// disagree, the JavaScript is right and this is a bug.
package sgshared

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

type GhostConfig struct {
	Patterns []string `json:"patterns"`
}

type Security struct {
	DLPBlock  *DLPConfig `json:"dlpBlock"`
	DLPRedact *DLPConfig `json:"dlpRedact"`
	RateLimit *RateLimit `json:"rateLimit"`

	// The DETECT-mode limits: count, do not block. Set by the API in place of
	// RateLimit when the mode is detect, so exactly one of the two is ever
	// present and a layer cannot accidentally enforce the observing one.
	//
	// Read by the post-tool audit hook on clients that have one, and by the
	// guard itself on clients that do not — where nothing else runs, so a
	// detect-mode burst that is not counted here is not counted anywhere.
	RateLimitObserve *RateLimit   `json:"rateLimitObserve"`
	LocalLogs        *LocalLogs   `json:"localLogs"`
	Ghost            *GhostConfig `json:"ghost"`
}

// Rules stays raw. The guard compiles it to Rego and the CLI passes it through;
// decoding it into a struct here would mean a policy loses any field this
// version does not know about the moment something round-trips it.
type Policy struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Mode  string          `json:"mode"`
	Rules json.RawMessage `json:"rules"`
}

// PolicyCache mirrors ~/.solongate/.policy-cache-<agent>.json.
//
// Security is a pointer on purpose. `null` there is an ANSWER — the API sent no
// security block, so this project has none — and it has to stay distinguishable
// from "the field was absent". Collapsing the two is what once made a stale
// device-wide marker decide where audit entries went.
type PolicyCache struct {
	TS          int64     `json:"_ts"`
	Policy      *Policy   `json:"policy"`
	SelfProtect *bool     `json:"selfProtect"`
	Security    *Security `json:"security"`

	// HasSecurity records whether the KEY was present, which is the distinction
	// the pointer above cannot carry on its own.
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

type Credential struct {
	APIKey string `json:"apiKey"`
	APIURL string `json:"apiUrl"`
}
