// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"

	"github.com/solongate/agent-security/packages/sgcore/core"
)

// Wire types for the SolonGate v1 API, as the CLI consumes them.
//
// CASING: the API is inconsistent and these types reflect what it actually
// sends rather than what it should. Policy list, version and audit responses
// are snake_case (created_by, _version, tool_name); settings, alerts and agent
// baselines are camelCase (perMinute, windowSeconds). Normalising here would
// mean guessing on every new field, so the mapping stays explicit.

type PolicyMode string

const (
	ModeDenylist  PolicyMode = "denylist"
	ModeWhitelist PolicyMode = "whitelist"
)

type Constraint struct {
	Allowed []string `json:"allowed,omitempty"`
	Denied  []string `json:"denied,omitempty"`
}

type PathConstraint struct {
	Allowed       []string `json:"allowed,omitempty"`
	Denied        []string `json:"denied,omitempty"`
	RootDirectory string   `json:"rootDirectory,omitempty"`
	AllowSymlinks *bool    `json:"allowSymlinks,omitempty"`
}

// PolicyRule as the wire carries it.
//
// Permission is RawMessage because the API sends either a string or an array of
// strings, and the difference is not cosmetic: the Rego generator compiles a
// single permission to `input.permission == "READ"` and a list to
// `input.permission in {…}`. Re-serialising one as the other changes what the
// compiled rule matches, so the bytes are kept and Permissions() reads them.
type PolicyRule struct {
	ID                  string          `json:"id"`
	Description         string          `json:"description"`
	Effect              string          `json:"effect"`
	Priority            int             `json:"priority"`
	ToolPattern         string          `json:"toolPattern"`
	Permission          json.RawMessage `json:"permission,omitempty"`
	MinimumTrustLevel   string          `json:"minimumTrustLevel"`
	Enabled             bool            `json:"enabled"`
	PathConstraints     *PathConstraint `json:"pathConstraints,omitempty"`
	CommandConstraints  *Constraint     `json:"commandConstraints,omitempty"`
	FilenameConstraints *Constraint     `json:"filenameConstraints,omitempty"`
	URLConstraints      *Constraint     `json:"urlConstraints,omitempty"`
	ArgumentConstraints json.RawMessage `json:"argumentConstraints,omitempty"`
}

// Permissions reads the permission field whichever way it was written.
func (r PolicyRule) Permissions() []core.Permission {
	if len(r.Permission) == 0 {
		return nil
	}
	var one string
	if json.Unmarshal(r.Permission, &one) == nil {
		if one == "" {
			return nil
		}
		return []core.Permission{core.Permission(one)}
	}
	var many []string
	if json.Unmarshal(r.Permission, &many) == nil {
		out := make([]core.Permission, 0, len(many))
		for _, p := range many {
			out = append(out, core.Permission(p))
		}
		return out
	}
	return nil
}

// Rules decodes a rule array one element at a time.
//
// A single `json.Unmarshal` over the array means one mistyped field anywhere —
// a `denied` written as a bare string, a quoted priority — fails the whole
// decode and the caller sees a policy with no rules while the dashboard still
// shows them as active. The guard learned this the expensive way: there, an
// empty rule list means allow everything. Here it means a policy renders as
// empty and a `policy update` would write that emptiness back.
//
// Raw keeps every element exactly as it arrived, including the ones that would
// not decode, so a read-modify-write path can put back what it never
// understood. Unreadable is how many did not decode, so a caller can say so
// instead of silently showing fewer rules than exist.
type Rules struct {
	Items      []PolicyRule
	Raw        []json.RawMessage
	Unreadable int
}

func (r *Rules) UnmarshalJSON(b []byte) error {
	*r = Rules{}
	var elems []json.RawMessage
	if err := json.Unmarshal(b, &elems); err != nil {
		return err
	}
	r.Raw = elems
	for _, e := range elems {
		var rule PolicyRule
		if json.Unmarshal(e, &rule) != nil {
			r.Unreadable++
			continue
		}
		r.Items = append(r.Items, rule)
	}
	return nil
}

// MarshalJSON writes back the bytes that arrived when they are still held, so a
// policy the CLI merely passed through is not narrowed by fields this version
// does not know about.
func (r Rules) MarshalJSON() ([]byte, error) {
	if r.Raw != nil {
		return json.Marshal(r.Raw)
	}
	if r.Items == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(r.Items)
}

type PolicySet struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Version     int        `json:"version,omitempty"`
	Rules       Rules      `json:"rules"`
	Mode        PolicyMode `json:"mode,omitempty"`
	Agents      []string   `json:"agents,omitempty"`

	// A policy is not one set of rules. It is a set of interchangeable
	// VARIANTS, one of which each machine enforces: the same policy can put a
	// contractor under a whitelist and everybody else under a denylist without
	// being two policies that drift apart.
	//
	// Top-level Rules above is still the shape every installed guard reads —
	// the API projects the chosen variant into it on the way out — so these
	// three fields are what the EDITOR sees and never what a guard is served.
	// A policy written before variants existed has none of them, which is why
	// they are all omitempty: sending `"variants": null` back on a save would
	// erase a bundle this binary merely passed through.
	Variants       []PolicyVariant `json:"variants,omitempty"`
	DefaultVariant string          `json:"defaultVariant,omitempty"`

	// Security is the base variant's own layers. A variant carries its own and
	// falls back to this one, the same order the dashboard editor reads them in.
	Security *SecurityLayers `json:"security,omitempty"`
}

// PolicyVariant is one interchangeable setting of a policy: its own rules, its
// own secret detectors, its own rate limit.
//
// Name is what a person picks from a list and ID is what a fleet grant pins, so
// renaming a variant must not change its id — the dashboard does not offer the
// rename for exactly that reason.
type PolicyVariant struct {
	ID       string          `json:"id"`
	Name     string          `json:"name,omitempty"`
	Rules    Rules           `json:"rules"`
	Security *SecurityLayers `json:"security,omitempty"`
}

// VariantList is every variant a policy has, including the implicit one.
//
// A policy with no variants array still has a setting in force: its top-level
// rules. Returning that as a variant named Base means every caller reads one
// list rather than branching on whether the bundle exists, and the id is empty
// because there is nothing for a grant to pin — an empty pin already means "the
// default", which is what Base is.
func (p PolicySet) VariantList() []PolicyVariant {
	if len(p.Variants) == 0 {
		return []PolicyVariant{{ID: "", Name: "Base", Rules: p.Rules, Security: p.Security}}
	}
	return p.Variants
}

// VariantLayers is the layers in force for one variant: its own when it has
// them, the policy's otherwise, and zero values when neither does.
func (p PolicySet) VariantLayers(v PolicyVariant) SecurityLayers {
	if v.Security != nil {
		return *v.Security
	}
	if p.Security != nil {
		return *p.Security
	}
	return SecurityLayers{}
}

type PolicyListEntry struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Rules     Rules      `json:"rules"`
	Mode      PolicyMode `json:"mode"`
	Version   int        `json:"version"`
	Hash      string     `json:"hash"`
	CreatedBy string     `json:"created_by"`
	CreatedAt string     `json:"created_at"`
}

type PolicyDetail struct {
	PolicySet
	VersionMeta int    `json:"_version"`
	Hash        string `json:"_hash"`
	CreatedAtV  string `json:"_created_at"`
}

type RateLimitSettings struct {
	PerMinute int `json:"perMinute"`
	PerHour   int `json:"perHour"`
	PerDay    int `json:"perDay"`
}

type DLPSettings struct {
	Patterns []string          `json:"patterns"`
	Custom   []json.RawMessage `json:"custom"`
}

// ActivePolicySecurity mirrors the /policies/active security block. Every field
// is a pointer because `null` there is an ANSWER — this project has no such
// layer configured — and has to stay distinguishable from a field the API did
// not send.
type ActivePolicySecurity struct {
	RateLimit *RateLimitSettings `json:"rateLimit"`
	// RateLimitObserve carries the same numbers in DETECT mode, where a burst is
	// flagged and never blocked. Exactly one of the two is ever set, and reading
	// only the first reported a project in detect as having no rate limit at all.
	RateLimitObserve *RateLimitSettings `json:"rateLimitObserve"`
	DLPBlock         *DLPSettings       `json:"dlpBlock"`
	DLPRedact        *DLPSettings       `json:"dlpRedact"`
	// DLPObserve carries the same patterns in DETECT mode, where a hit is
	// recorded and nothing the caller sees changes. Exactly one of the three
	// shapes is ever set.
	DLPObserve *DLPSettings    `json:"dlpObserve"`
	LocalLogs  json.RawMessage `json:"localLogs"`
}

type ActivePolicy struct {
	Policy                *PolicySet            `json:"policy"`
	Version               int                   `json:"version,omitempty"`
	Hash                  string                `json:"hash,omitempty"`
	MatchedBy             string                `json:"matched_by,omitempty"`
	SelfProtectionEnabled bool                  `json:"self_protection_enabled"`
	Security              *ActivePolicySecurity `json:"security"`

	// Variant is which setting of that policy this machine is enforcing.
	// It is only ever set for a guest whose host pinned one, which makes it the
	// honest answer to "am I under somebody else's policy": it comes from what
	// the guard is actually served rather than from a flag the dataroom keeps.
	Variant      string `json:"variant,omitempty"`
	HookVersions struct {
		Guard  int `json:"guard"`
		Audit  int `json:"audit"`
		Shield int `json:"shield"`
	} `json:"hook_versions"`
}

// ── Security layers ────────────────────────────────────────────────────────

// LayerMode is how hard a layer bites.
//
//	off     nothing happens
//	detect  scan, record, change nothing the caller sees
//	redact  DLP ONLY: mask the secret, let the call through
//	block   refuse the call
//
// `redact` sits between the other two and belongs to DLP alone: there is no
// middle step for a rate limit, where a call either counts or is refused.
type LayerMode string

const (
	LayerOff    LayerMode = "off"
	LayerDetect LayerMode = "detect"
	LayerRedact LayerMode = "redact"
	LayerBlock  LayerMode = "block"
)

type CustomPattern struct {
	Name string `json:"name"`
	Re   string `json:"re"`
}

type SecurityLayers struct {
	RateLimit struct {
		Mode      LayerMode `json:"mode"`
		PerMinute int       `json:"perMinute"`
		PerHour   int       `json:"perHour"`
		PerDay    int       `json:"perDay"`
	} `json:"rateLimit"`
	DLP struct {
		Mode     LayerMode       `json:"mode"`
		Patterns []string        `json:"patterns"`
		Custom   []CustomPattern `json:"custom"`
	} `json:"dlp"`
}

type RateLimitChange struct {
	TS     int64 `json:"ts"`
	Minute int   `json:"minute"`
	Hour   int   `json:"hour"`
	Day    int   `json:"day"`
}

// ── Stats ──────────────────────────────────────────────────────────────────

type Stats struct {
	TotalCalls      int `json:"total_calls"`
	Allowed         int `json:"allowed"`
	Denied          int `json:"denied"`
	ActivePolicies  int `json:"active_policies"`
	RegisteredTools int `json:"registered_tools"`
	RecentActivity  []struct {
		ID               string   `json:"id"`
		ToolName         string   `json:"tool_name"`
		Decision         string   `json:"decision"`
		TrustLevel       string   `json:"trust_level"`
		EvaluationTimeMs *float64 `json:"evaluation_time_ms"`
		CreatedAt        string   `json:"created_at"`
	} `json:"recent_activity"`
}

type TimeseriesPoint struct {
	Timestamp    string  `json:"timestamp"`
	Total        int     `json:"total"`
	Allowed      int     `json:"allowed"`
	Denied       int     `json:"denied"`
	AvgEvalTimeM float64 `json:"avg_eval_time_ms"`
}

type Timeseries struct {
	Timeseries  []TimeseriesPoint `json:"timeseries"`
	Period      string            `json:"period"`
	Granularity string            `json:"granularity"`
}

type Drift struct {
	Days          int `json:"days"`
	TotalCurrent  int `json:"total_current"`
	TotalPrevious int `json:"total_previous"`
	Rules         []struct {
		RuleID   *string  `json:"rule_id"`
		Reason   *string  `json:"reason"`
		LastTool *string  `json:"last_tool"`
		Current  int      `json:"current"`
		Previous int      `json:"previous"`
		Delta    int      `json:"delta"`
		DeltaPct *float64 `json:"delta_pct"`
		IsNew    bool     `json:"is_new"`
		Spike    bool     `json:"spike"`
	} `json:"rules"`
}

// ── Audit ──────────────────────────────────────────────────────────────────

type AuditEntry struct {
	ID               string          `json:"id"`
	RequestID        string          `json:"request_id"`
	SessionID        *string         `json:"session_id"`
	ToolName         string          `json:"tool_name"`
	ServerName       string          `json:"server_name"`
	Permission       string          `json:"permission"`
	TrustLevel       string          `json:"trust_level"`
	Decision         string          `json:"decision"`
	MatchedRuleID    *string         `json:"matched_rule_id"`
	Reason           *string         `json:"reason"`
	EvaluationTimeMs *float64        `json:"evaluation_time_ms"`
	ArgumentsSummary json.RawMessage `json:"arguments_summary"`
	DLPMatches       []string        `json:"dlp_matches"`
	RateLimitBurst   bool            `json:"rate_limit_burst"`
	AgentID          *string         `json:"agent_id"`
	AgentName        *string         `json:"agent_name"`
	CreatedAt        string          `json:"created_at"`
}

type AuditList struct {
	Entries            []AuditEntry `json:"entries"`
	Total              int          `json:"total"`
	Limit              int          `json:"limit"`
	Offset             int          `json:"offset"`
	RateLimitPerMinute int          `json:"rate_limit_per_minute"`
}
