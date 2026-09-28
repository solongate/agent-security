package api

import (
	"context"
	"encoding/json"
	"net/url"
)

// One type per API namespace, each holding the client. Method names and request
// shapes track packages/proxy/src/api-client/* one for one, so a command ported
// from TypeScript can be read next to its original.

// ── /auth ──────────────────────────────────────────────────────────────────

type AuthAPI struct{ c *Client }

// Me is who the key in use belongs to: the project it selects and the owner.
type Me struct {
	User *struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"user"`
	Project *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Slug string `json:"slug"`
	} `json:"project"`
}

func (a AuthAPI) Me(ctx context.Context) (Me, error) {
	var out Me
	return out, a.c.get(ctx, "/auth/me", nil, &out)
}

// ── /policies ──────────────────────────────────────────────────────────────

type PoliciesAPI struct{ c *Client }

func (p PoliciesAPI) List(ctx context.Context) ([]PolicyListEntry, error) {
	var out struct {
		Policies []PolicyListEntry `json:"policies"`
	}
	return out.Policies, p.c.get(ctx, "/policies", nil, &out)
}

// Get fetches one policy. version 0 means the current one.
func (p PoliciesAPI) Get(ctx context.Context, id string, version int) (PolicyDetail, error) {
	var q url.Values
	if version > 0 {
		q = Query(map[string]any{"version": version})
	}
	var out PolicyDetail
	return out, p.c.get(ctx, "/policies/"+esc(id), q, &out)
}

func (p PoliciesAPI) Create(ctx context.Context, policy PolicySet) (PolicyDetail, error) {
	var out PolicyDetail
	return out, p.c.post(ctx, "/policies", policy, &out)
}

func (p PoliciesAPI) Update(ctx context.Context, id string, policy PolicySet) (PolicyDetail, error) {
	var out PolicyDetail
	return out, p.c.put(ctx, "/policies/"+esc(id), policy, &out)
}

func (p PoliciesAPI) Remove(ctx context.Context, id string) error {
	return p.c.del(ctx, "/policies/"+esc(id), nil, nil, nil)
}

// RuleSpec is the shorthand the API expands into a full rule. The CLI sends
// intent — deny this command, allow this path — and the API decides the rule's
// id, priority and trust level, so two clients cannot produce differently
// shaped rules for the same request.
type RuleSpec struct {
	ToolPattern string   `json:"toolPattern,omitempty"`
	Kind        string   `json:"kind,omitempty"`
	Value       string   `json:"value,omitempty"`
	Effect      string   `json:"effect,omitempty"`
	Permission  []string `json:"permission,omitempty"`
}

// RuleMutation is the answer to any call that adds or changes a rule. Deduped
// says the rule was already there, which is a success, not a failure.
type RuleMutation struct {
	OK            bool        `json:"ok"`
	Deduped       bool        `json:"deduped"`
	Rule          *PolicyRule `json:"rule,omitempty"`
	PolicyID      string      `json:"policy_id"`
	PolicyVersion int         `json:"policy_version,omitempty"`
	Message       string      `json:"message,omitempty"`
}

func (p PoliciesAPI) AddRule(ctx context.Context, id string, spec RuleSpec) (RuleMutation, error) {
	var out RuleMutation
	return out, p.c.post(ctx, "/policies/"+esc(id)+"/rules", spec, &out)
}

func (p PoliciesAPI) RevokeRule(ctx context.Context, id, ruleID string) (RuleMutation, error) {
	var out RuleMutation
	return out, p.c.del(ctx, "/policies/"+esc(id)+"/rules/"+esc(ruleID), nil, nil, &out)
}

// Active resolves which policy governs a given agent right now, including the
// security layers that travel with it.
func (p PoliciesAPI) Active(ctx context.Context, agentID string) (ActivePolicy, error) {
	var q url.Values
	if agentID != "" {
		q = Query(map[string]any{"agent_id": agentID})
	}
	var out ActivePolicy
	return out, p.c.get(ctx, "/policies/active", q, &out)
}

// SetActive pins a policy, or unpins with an empty id. The API takes "" rather
// than null for the unpin, which is why this does not use a pointer.
func (p PoliciesAPI) SetActive(ctx context.Context, policyID string) error {
	return p.c.post(ctx, "/policies/active", map[string]any{"policyId": policyID}, nil)
}

// ── /settings ──────────────────────────────────────────────────────────────

type SettingsAPI struct{ c *Client }

type SecurityLayersResponse struct {
	Layers            SecurityLayers `json:"layers"`
	AvailablePatterns []string       `json:"availablePatterns"`
}

func (s SettingsAPI) GetSecurityLayers(ctx context.Context) (SecurityLayersResponse, error) {
	var out SecurityLayersResponse
	return out, s.c.get(ctx, "/settings/security-layers", nil, &out)
}

func (s SettingsAPI) SetSecurityLayers(ctx context.Context, layers SecurityLayers) (SecurityLayers, error) {
	var out struct {
		Layers SecurityLayers `json:"layers"`
	}
	return out.Layers, s.c.put(ctx, "/settings/security-layers", map[string]any{"layers": layers}, &out)
}

func (s SettingsAPI) GetRateLimitHistory(ctx context.Context) ([]RateLimitChange, error) {
	var out struct {
		History []RateLimitChange `json:"history"`
	}
	return out.History, s.c.get(ctx, "/settings/rate-limit-history", nil, &out)
}

func (s SettingsAPI) ClearRateLimitHistory(ctx context.Context) error {
	return s.c.del(ctx, "/settings/rate-limit-history", Query(map[string]any{"all": 1}), nil, nil)
}

// GuardStatus is the fleet's view: what the newest guard is, what this device
// has, and how many devices are behind.
type GuardStatus struct {
	Latest        int  `json:"latest"`
	Installed     *int `json:"installed"`
	UpToDate      bool `json:"up_to_date"`
	DeviceCount   int  `json:"device_count"`
	OutdatedCount int  `json:"outdated_count"`
}

func (s SettingsAPI) GetGuardStatus(ctx context.Context) (GuardStatus, error) {
	var out GuardStatus
	return out, s.c.get(ctx, "/settings/guard-status", nil, &out)
}

func (s SettingsAPI) GetSelfProtection(ctx context.Context) (bool, error) {
	var out struct {
		Enabled bool `json:"enabled"`
	}
	return out.Enabled, s.c.get(ctx, "/settings/self-protection", nil, &out)
}

func (s SettingsAPI) SetSelfProtection(ctx context.Context, enabled bool) (bool, error) {
	var out struct {
		Enabled bool `json:"enabled"`
	}
	return out.Enabled, s.c.put(ctx, "/settings/self-protection", map[string]any{"enabled": enabled}, &out)
}

// LocalLogsConfig mirrors the hooks' local mirror of the audit trail. The API
// forces enabled:false when path is empty, so a caller that wants it on has to
// set a path in the same request or in an earlier one.
type LocalLogsConfig struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

func (s SettingsAPI) GetLocalLogs(ctx context.Context) (LocalLogsConfig, error) {
	var out LocalLogsConfig
	return out, s.c.get(ctx, "/settings/local-logs", nil, &out)
}

func (s SettingsAPI) SetLocalLogs(ctx context.Context, cfg LocalLogsConfig) (LocalLogsConfig, error) {
	var out LocalLogsConfig
	return out, s.c.put(ctx, "/settings/local-logs", cfg, &out)
}

// ── /stats ─────────────────────────────────────────────────────────────────

type StatsAPI struct{ c *Client }

func (s StatsAPI) Get(ctx context.Context) (Stats, error) {
	var out Stats
	return out, s.c.get(ctx, "/stats", nil, &out)
}

func (s StatsAPI) Timeseries(ctx context.Context, period, granularity string) (Timeseries, error) {
	var out Timeseries
	q := Query(map[string]any{"period": period, "granularity": granularity})
	return out, s.c.get(ctx, "/stats/timeseries", q, &out)
}

func (s StatsAPI) Drift(ctx context.Context, days int) (Drift, error) {
	var out Drift
	return out, s.c.get(ctx, "/stats/drift", Query(map[string]any{"days": days}), &out)
}

// SecurityInsights is a rich, still-moving payload. Left as raw JSON on purpose:
// pinning a struct to it would mean this version silently dropping whatever the
// API adds next.
func (s StatsAPI) SecurityInsights(ctx context.Context, days int) (json.RawMessage, error) {
	var out json.RawMessage
	return out, s.c.get(ctx, "/stats/security-insights", Query(map[string]any{"days": days}), &out)
}

// ── /audit-logs ────────────────────────────────────────────────────────────

type AuditAPI struct{ c *Client }

// AuditQuery is every filter the audit list accepts. Signal is derived by the
// API from the reason plus the detect-mode observation, not stored as a column,
// so it is a filter here and not a field on AuditEntry.
type AuditQuery struct {
	Filter    string
	Tool      string
	Limit     int
	Offset    int
	From      int64
	To        int64
	AgentName string
	SessionID string
	Search    string
	Signal    string
}

func (q AuditQuery) values() url.Values {
	return Query(map[string]any{
		"filter":     q.Filter,
		"tool":       q.Tool,
		"limit":      q.Limit,
		"offset":     q.Offset,
		"from":       q.From,
		"to":         q.To,
		"agent_name": q.AgentName,
		"session_id": q.SessionID,
		"search":     q.Search,
		"signal":     q.Signal,
	})
}

func (a AuditAPI) List(ctx context.Context, q AuditQuery) (AuditList, error) {
	var out AuditList
	return out, a.c.get(ctx, "/audit-logs", q.values(), &out)
}

type Deleted struct {
	Deleted struct {
		Logs   int `json:"logs"`
		Agents int `json:"agents"`
	} `json:"deleted"`
}

func (a AuditAPI) Remove(ctx context.Context, ids []string) (Deleted, error) {
	var out Deleted
	return out, a.c.del(ctx, "/audit-logs", nil, map[string]any{"ids": ids}, &out)
}

// RemoveAll deletes every audit log of the project. Agents and sessions are
// kept, so the trust map survives a log wipe.
func (a AuditAPI) RemoveAll(ctx context.Context) (Deleted, error) {
	var out Deleted
	return out, a.c.del(ctx, "/audit-logs", nil, map[string]any{"scope": "logs"}, &out)
}

// Whitelist turns a denial into an ALLOW rule. scope "exact" matches the call
// as it happened; "tool" matches the tool whatever its arguments.
func (a AuditAPI) Whitelist(ctx context.Context, id, scope string) (RuleMutation, error) {
	if scope == "" {
		scope = "exact"
	}
	var out RuleMutation
	return out, a.c.post(ctx, "/audit-logs/"+esc(id)+"/whitelist", map[string]any{"scope": scope}, &out)
}

// Block is the inverse of Whitelist: turn a call that was allowed into a DENY
// rule.
func (a AuditAPI) Block(ctx context.Context, id, scope string) (RuleMutation, error) {
	if scope == "" {
		scope = "exact"
	}
	var out RuleMutation
	return out, a.c.post(ctx, "/audit-logs/"+esc(id)+"/block", map[string]any{"scope": scope}, &out)
}

// ── /keys ──────────────────────────────────────────────────────────────────

type KeysAPI struct{ c *Client }

// APIKey is a key's METADATA. The secret itself is only ever returned once, by
// Create; nothing here can read an existing key back.
type APIKey struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	KeyPrefix string `json:"key_prefix"`
	IsLive    bool   `json:"is_live"`
	CreatedAt string `json:"created_at"`
}

func (k KeysAPI) List(ctx context.Context) ([]APIKey, error) {
	var out struct {
		Keys []APIKey `json:"keys"`
	}
	return out.Keys, k.c.get(ctx, "/keys", nil, &out)
}

// CreatedKey carries the only copy of the secret the caller will ever see. It
// must not be logged, and callers should hand it straight to the user.
type CreatedKey struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Key       string `json:"key"`
	KeyPrefix string `json:"key_prefix"`
}

func (k KeysAPI) Create(ctx context.Context, name string, isLive bool) (CreatedKey, error) {
	var out CreatedKey
	return out, k.c.post(ctx, "/keys", map[string]any{"name": name, "is_live": isLive}, &out)
}

func (k KeysAPI) Revoke(ctx context.Context, id string) error {
	return k.c.del(ctx, "/keys/"+esc(id), nil, nil, nil)
}

// ── /mcp-servers ───────────────────────────────────────────────────────────

type McpAPI struct{ c *Client }

type McpServer struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url,omitempty"`
	Command string `json:"command,omitempty"`
	Status  string `json:"status"`
}

func (m McpAPI) List(ctx context.Context) ([]McpServer, error) {
	var out struct {
		Servers []McpServer `json:"servers"`
	}
	return out.Servers, m.c.get(ctx, "/mcp-servers", nil, &out)
}
