package api

import (
	"context"
	"encoding/json"
	"net/http"
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

type VersionList struct {
	Versions   []PolicyVersion `json:"versions"`
	Pagination struct {
		Total  int `json:"total"`
		Limit  int `json:"limit"`
		Offset int `json:"offset"`
	} `json:"pagination"`
}

func (p PoliciesAPI) Versions(ctx context.Context, id string, limit, offset int) (VersionList, error) {
	var out VersionList
	q := Query(map[string]any{"limit": limit, "offset": offset})
	return out, p.c.get(ctx, "/policies/"+esc(id)+"/versions", q, &out)
}

type Rollback struct {
	Version        int    `json:"version"`
	RolledBackFrom int    `json:"rolled_back_from"`
	PolicyID       string `json:"policy_id"`
	Hash           string `json:"hash"`
}

func (p PoliciesAPI) Rollback(ctx context.Context, id string, version int) (Rollback, error) {
	var out Rollback
	return out, p.c.post(ctx, "/policies/"+esc(id)+"/rollback", map[string]any{"version": version}, &out)
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

type AlertRule struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Enabled       bool     `json:"enabled"`
	Threshold     int      `json:"threshold"`
	WindowSeconds int      `json:"windowSeconds"`
	Signal        string   `json:"signal"`
	SlackUrls     []string `json:"slackUrls,omitempty"`
	Emails        []string `json:"emails,omitempty"`
	Telegram      []string `json:"telegram,omitempty"`
	CreatedAt     string   `json:"createdAt"`
}

func (s SettingsAPI) GetAlerts(ctx context.Context) ([]AlertRule, error) {
	var out struct {
		Rules []AlertRule `json:"rules"`
	}
	return out.Rules, s.c.get(ctx, "/settings/denial-alerts", nil, &out)
}

// CreateAlert takes the raw body the API expects: the create shape differs from
// AlertRule (it accepts a single slackUrl, not a list) and forcing them into
// one struct would mean sending fields the API rejects.
func (s SettingsAPI) CreateAlert(ctx context.Context, body map[string]any) (AlertRule, error) {
	var out struct {
		Rule AlertRule `json:"rule"`
	}
	return out.Rule, s.c.post(ctx, "/settings/denial-alerts", body, &out)
}

func (s SettingsAPI) DeleteAlert(ctx context.Context, id string) error {
	return s.c.del(ctx, "/settings/denial-alerts", Query(map[string]any{"id": id}), nil, nil)
}

func (s SettingsAPI) SetAlertEnabled(ctx context.Context, id string, enabled bool) error {
	return s.c.patch(ctx, "/settings/denial-alerts", Query(map[string]any{"id": id}),
		map[string]any{"enabled": enabled}, nil)
}

func (s SettingsAPI) UpdateAlert(ctx context.Context, id string, patch map[string]any) (AlertRule, error) {
	var out struct {
		Rule AlertRule `json:"rule"`
	}
	return out.Rule, s.c.patch(ctx, "/settings/denial-alerts", Query(map[string]any{"id": id}), patch, &out)
}

// There is deliberately no send-test for alerts. Delivering a real message to
// an arbitrary email or Telegram id on demand is an abuse and rate-limit
// vector; only webhooks, which post to the user's own URL, are testable.

type DenialWebhook struct {
	ID        string            `json:"id"`
	URL       string            `json:"url"`
	Enabled   bool              `json:"enabled"`
	Events    string            `json:"events"`
	Headers   map[string]string `json:"headers,omitempty"`
	CreatedAt string            `json:"createdAt"`
}

func (s SettingsAPI) GetWebhooks(ctx context.Context) ([]DenialWebhook, error) {
	var out struct {
		Webhooks []DenialWebhook `json:"webhooks"`
	}
	return out.Webhooks, s.c.get(ctx, "/settings/denial-webhook", nil, &out)
}

func (s SettingsAPI) CreateWebhook(ctx context.Context, body map[string]any) (DenialWebhook, error) {
	var out struct {
		Webhook DenialWebhook `json:"webhook"`
	}
	return out.Webhook, s.c.post(ctx, "/settings/denial-webhook", body, &out)
}

func (s SettingsAPI) DeleteWebhook(ctx context.Context, id string) error {
	return s.c.del(ctx, "/settings/denial-webhook", Query(map[string]any{"id": id}), nil, nil)
}

func (s SettingsAPI) SendTestWebhook(ctx context.Context, id string) (bool, error) {
	var out struct {
		Delivered bool `json:"delivered"`
	}
	return out.Delivered, s.c.post(ctx, "/settings/denial-webhook/send-test", map[string]any{"id": id}, &out)
}

func (s SettingsAPI) UpdateWebhook(ctx context.Context, id string, patch map[string]any) error {
	body := map[string]any{"id": id}
	for k, v := range patch {
		body[k] = v
	}
	return s.c.patch(ctx, "/settings/denial-webhook", nil, body, nil)
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

// ── /agents ────────────────────────────────────────────────────────────────

type AgentsAPI struct{ c *Client }

func (a AgentsAPI) Live(ctx context.Context, limit int, includeDeactivated bool) (LiveAgents, error) {
	var out LiveAgents
	q := Query(map[string]any{"limit": limit})
	if includeDeactivated {
		q.Set("include_deactivated", "1")
	}
	return out, a.c.get(ctx, "/agents/live", q, &out)
}

// Get is deep detail for one agent. The payload is rich and still changing, so
// it stays raw rather than being narrowed by this version's idea of it.
func (a AgentsAPI) Get(ctx context.Context, id string, scan bool) (json.RawMessage, error) {
	var q url.Values
	if scan {
		q = Query(map[string]any{"scan": 1})
	}
	var out json.RawMessage
	return out, a.c.get(ctx, "/agents/"+esc(id), q, &out)
}

func (a AgentsAPI) Anomalies(ctx context.Context, id string, limit int) ([]json.RawMessage, error) {
	var out struct {
		Anomalies []json.RawMessage `json:"anomalies"`
	}
	return out.Anomalies, a.c.get(ctx, "/agents/"+esc(id)+"/anomalies", Query(map[string]any{"limit": limit}), &out)
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

// ── /fleet ─────────────────────────────────────────────────────────────────

// The host/guest arrangement, as the CLI sees it.
//
// A host configures a policy once and hands it to the developers on their team;
// nothing about a developer's machine changes until they ACCEPT. After that
// they cannot leave and cannot change what they were given, which the server
// enforces rather than this package. This API is the two halves of that: what a
// host has sent, and what has been sent to you.
type FleetAPI struct{ c *Client }

type FleetGrant struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	// GuestUserID is who accepted, and is absent until somebody has. It is the
	// key everything about a person is asked by — their activity, their
	// numbers — and a row on the roster is the only place it is known.
	GuestUserID string `json:"guest_user_id"`
	Email       string `json:"email"`
	Status      string `json:"status"`
	VariantID   string `json:"variant_id"`
	// Group is the host's own label for this person. Empty is ungrouped, which
	// is what an invitation is until somebody says otherwise.
	Group string `json:"group"`
	// PolicyID is the policy pinned to this ONE person, empty when they follow
	// their group's. An exception, not a default.
	PolicyID string `json:"policy_id"`
	// TopAgent is the client they reach for most.
	TopAgent string `json:"top_agent"`
	// IsHost is whether this person runs a fleet of their OWN, which is a
	// different question from whether they are a guest on this one.
	IsHost     bool   `json:"is_host"`
	CreatedAt  string `json:"created_at"`
	AcceptedAt string `json:"accepted_at"`
}

// FleetState is the host's own view: whether this account may hand policies
// out, how many seats it has, and who is holding one.
//
// Host is false rather than an error for an account with no entitlement: the
// endpoint is asked before the panel decides what to draw, and "you are not a
// host" is an answer to that question.
type FleetState struct {
	Host  bool `json:"host"`
	Seats int  `json:"seats"`
	Used  int  `json:"used"`
	// HostGroup is the reader's OWN label, and HostTopAgent their own most-used
	// client. Neither is on a row above: the host holds no grant, so there is
	// nothing in that list to carry them.
	HostGroup    string       `json:"host_group"`
	HostTopAgent string       `json:"host_top_agent"`
	Invitations  []FleetGrant `json:"invitations"`
}

func (f FleetAPI) State(ctx context.Context) (FleetState, error) {
	var out FleetState
	return out, f.c.get(ctx, "/fleet", nil, &out)
}

// Inbox is the other half: every request addressed to this account, across
// every host.
func (f FleetAPI) Inbox(ctx context.Context) ([]FleetGrant, error) {
	var out struct {
		Invitations []FleetGrant `json:"invitations"`
	}
	if err := f.c.get(ctx, "/fleet/inbox", nil, &out); err != nil {
		return nil, err
	}
	return out.Invitations, nil
}

func (f FleetAPI) Invite(ctx context.Context, email, policyID, variantID string) error {
	return f.c.post(ctx, "/fleet/invitations", map[string]string{
		"email": email, "policy_id": policyID, "variant_id": variantID,
	}, nil)
}

// SetVariant moves a developer onto another setting of the same policy. It is
// a PUT rather than a second invitation: the arrangement is the same one, and
// re-inviting would ask them to accept something they already accepted.
func (f FleetAPI) SetVariant(ctx context.Context, id, variantID string) error {
	return f.c.put(ctx, "/fleet/invitations/"+url.PathEscape(id),
		map[string]string{"variant_id": variantID}, nil)
}

func (f FleetAPI) Revoke(ctx context.Context, id string) error {
	return f.c.Do(ctx, http.MethodDelete, "/fleet/invitations/"+url.PathEscape(id),
		RequestOptions{}, nil)
}

// Accept is the one transition a guest makes, and the only one. There is no
// call that moves a grant back out of accepted: that absence is what "cannot
// leave the host" means, and it is not a flag anybody could clear from here.
func (f FleetAPI) Accept(ctx context.Context, id string) error {
	return f.c.post(ctx, "/fleet/inbox/"+url.PathEscape(id)+"/accept", nil, nil)
}

func (f FleetAPI) Decline(ctx context.Context, id string) error {
	return f.c.post(ctx, "/fleet/inbox/"+url.PathEscape(id)+"/decline", nil, nil)
}
