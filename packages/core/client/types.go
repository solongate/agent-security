// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package client

import (
	"encoding/json"

	"github.com/solongate/agent-security/packages/core/vocab"
)

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

func (r PolicyRule) Permissions() []vocab.Permission {
	if len(r.Permission) == 0 {
		return nil
	}
	var one string
	if json.Unmarshal(r.Permission, &one) == nil {
		if one == "" {
			return nil
		}
		return []vocab.Permission{vocab.Permission(one)}
	}
	var many []string
	if json.Unmarshal(r.Permission, &many) == nil {
		out := make([]vocab.Permission, 0, len(many))
		for _, p := range many {
			out = append(out, vocab.Permission(p))
		}
		return out
	}
	return nil
}

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

	Variants       []PolicyVariant `json:"variants,omitempty"`
	DefaultVariant string          `json:"defaultVariant,omitempty"`

	Security *SecurityLayers `json:"security,omitempty"`
}

type PolicyVariant struct {
	ID       string          `json:"id"`
	Name     string          `json:"name,omitempty"`
	Rules    Rules           `json:"rules"`
	Security *SecurityLayers `json:"security,omitempty"`
}

func (p PolicySet) VariantList() []PolicyVariant {
	if len(p.Variants) == 0 {
		return []PolicyVariant{{ID: "", Name: "Base", Rules: p.Rules, Security: p.Security}}
	}
	return p.Variants
}

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

type ActivePolicySecurity struct {
	RateLimit *RateLimitSettings `json:"rateLimit"`

	RateLimitObserve *RateLimitSettings `json:"rateLimitObserve"`
	DLPBlock         *DLPSettings       `json:"dlpBlock"`
	DLPRedact        *DLPSettings       `json:"dlpRedact"`

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

	Variant      string `json:"variant,omitempty"`
	HookVersions struct {
		Guard  int `json:"guard"`
		Audit  int `json:"audit"`
		Shield int `json:"shield"`
	} `json:"hook_versions"`
}

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