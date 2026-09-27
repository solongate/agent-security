package store

import "encoding/json"

// The tables, as Go.
//
// These are the schema's tables, in its order —
// which src/db/index.ts creates at runtime and never declared in the drizzle
// schema, and which the whole CLI login flow is built on.
//
// Field names follow the Go convention rather than the column names; the column
// names live in the queries, which is the only place they are load-bearing.
// Nullable text is flattened to a string and nullable timestamps are pointers,
// for the reasons in store.go.
//
// The JSON columns stay as json.RawMessage. Decoding policy_data into a struct
// here would mean a policy loses any field this version does not know about the
// moment something round-trips it, and the guard — not this service — is the
// program that understands its contents.

// ── 1. users ────────────────────────────────────────────────────────────────

// User is `users`. PasswordHash is `pbkdf2:100000:<salt>:<hex>` when set and
// empty for accounts created through Supabase or /v1/setup, which is why
// /v1/auth login answers NO_PASSWORD rather than INVALID_CREDENTIALS for them:
// telling the two apart is deliberate there and must survive the port.
//
// It is never logged and never returned; only the routes that verify it read
// the column.
type User struct {
	ID           string
	Email        string
	Name         string
	PasswordHash string
	CreatedAt    int64
	UpdatedAt    int64
}

// ── 2. organizations ────────────────────────────────────────────────────────

type Organization struct {
	ID        string
	Name      string
	Slug      string
	OwnerID   string
	CreatedAt int64
	UpdatedAt int64
}

// ── 3. org_members ──────────────────────────────────────────────────────────

// OrgMember is `org_members`. Role is one of owner, admin, member, viewer —
// unchecked by the database, because the enum only ever existed in TypeScript's
// type system. OrgRoles is the set the write paths check against.
type OrgMember struct {
	ID        string
	OrgID     string
	UserID    string
	Role      string
	CreatedAt int64
	UpdatedAt int64
}

// ── 4. projects ─────────────────────────────────────────────────────────────

// Project is `projects`, and it is the tenant boundary. Every scoped table
// below carries a project_id, and an endpoint that forgets to filter on the one
// the API key resolved to is a cross-tenant read.
//
// TokenSecret signs that project's capability tokens. It is a credential: it
// belongs in no response body and no log line, which is why ProjectSummary
// exists for the routes that want to describe a project.
//
// The Pi* fields are prompt-injection settings and the AIJudge* fields are the
// optional second-opinion model. Both have defaults in the schema, so a row
// written before a column existed reads as its default rather than as zero —
// PiEnabled in particular defaults to TRUE, and reading a NULL there as false
// would disable injection detection for every project created before the
// column landed.
type Project struct {
	ID          string
	OwnerID     string
	OrgID       string
	Name        string
	Slug        string
	Description string
	TokenSecret string

	PiEnabled        bool
	PiThreshold      float64
	PiMode           string
	PiWhitelist      string
	PiToolConfig     string
	PiCustomPatterns string
	PiWebhookURL     string

	AIJudgeEnabled   bool
	AIJudgeModel     string
	AIJudgeEndpoint  string
	AIJudgeTimeoutMs int64

	CreatedAt int64
	UpdatedAt int64
}

// ProjectSummary is a project without its token secret, for the routes that
// list or describe one. Handing back a Project by accident is how a signing key
// ends up in a dashboard's network tab.
type ProjectSummary struct {
	ID          string
	OwnerID     string
	OrgID       string
	Name        string
	Slug        string
	Description string
	CreatedAt   int64
	UpdatedAt   int64
}

// ── 5. api_keys ─────────────────────────────────────────────────────────────

// APIKey is `api_keys`. KeyHash is the SHA-256 of the full key as lowercase
// hex; the key itself is never stored and cannot be recovered, which is why
// creation is the only time a route returns one.
//
// KeyPrefix is the first sixteen characters — `sg_live_` plus eight hex — and
// is what the lookup indexes on. It is safe to show and does appear in
// responses; the hash is not and does not.
//
// RevokedAt nil means live. Every authenticating query filters on it.
type APIKey struct {
	ID        string
	ProjectID string
	KeyPrefix string
	KeyHash   string
	Name      string
	IsLive    bool
	// UserID is who the key was issued to. Empty writes NULL, which reads back
	// as "acts as the project owner"; see KeyIdentity.UserID.
	UserID     string
	LastUsedAt *int64
	RevokedAt  *int64
	CreatedAt  int64
}

// ── 6. policy_versions ──────────────────────────────────────────────────────

// PolicyVersion is `policy_versions`: one row per saved revision, never
// updated in place. Version is per-project and monotonic, which is what
// /policies/{id}/rollback and /policies/{id}/versions are built on.
//
// PolicyData is the full PolicySet as stored. Hash is the SHA-256 of its
// serialisation and travels to the guard in the /policies/active response, so
// it has to be the hash of the bytes that were stored rather than of a
// re-serialisation.
//
// RegoSource and WasmBundle are the compiled forms and are absent on rows
// written before src/db/index.ts added the columns.
type PolicyVersion struct {
	ID         string
	ProjectID  string
	Version    int64
	PolicyData json.RawMessage
	Hash       string
	Reason     string
	CreatedBy  string
	RegoSource string
	WasmBundle string
	CreatedAt  int64
}

// ── 7. tools ────────────────────────────────────────────────────────────────

// Tool is `tools`. Permissions is a JSON array of READ/WRITE/EXECUTE/NETWORK
// and defaults to ["READ"].
//
// Description is a POINTER where every other flattened text column here is a
// string, and the reason is the endpoint rather than the schema: PUT
// /v1/tools/{name} writes NULL when a body sends `"description": null`, and the
// GET that follows has to answer null rather than "". Collapsing the two would
// be invisible in Go and a changed body for a client that already stores one.
type Tool struct {
	ID          string
	ProjectID   string
	Name        string
	Description *string
	InputSchema json.RawMessage
	Permissions json.RawMessage
	Enabled     bool
	CreatedAt   int64
	UpdatedAt   int64
}

// ── 8. used_nonces ──────────────────────────────────────────────────────────

// UsedNonce is `used_nonces`, the replay table for capability tokens. A row
// here means that token has been spent; the primary key is what makes the
// second presentation fail rather than a lookup-then-insert race.
type UsedNonce struct {
	Nonce     string
	ProjectID string
	UsedAt    int64
}

// ── 9. audit_logs ───────────────────────────────────────────────────────────

// AuditLog is `audit_logs`: one row per tool call the guard or the audit hook
// reported. It is the largest table in the database and every query against it
// is project-scoped and bounded.
//
// Decision is ALLOW or DENY. The DLP and rate-limit signals the dashboard shows
// are NOT columns — they are derived from Reason plus the observe-mode hook, so
// nothing here needs to store them.
//
// PiDetected is a *bool because NULL and false differ: NULL is "the injection
// scanner did not run on this call", false is "it ran and found nothing".
type AuditLog struct {
	ID               string
	ProjectID        string
	RequestID        string
	SessionID        string
	ToolName         string
	ServerName       string
	Permission       string
	TrustLevel       string
	Decision         string
	MatchedRuleID    string
	Reason           string
	EvaluationTimeMs *float64
	ArgumentsHash    string
	ArgumentsSummary string
	PiDetected       *bool
	PiTrustScore     *float64
	PiBlocked        *bool
	PiCategories     string
	PiStageScores    string
	AgentID          string
	AgentName        string
	SubAgentID       string
	SubAgentName     string
	APIKeyID         string
	CreatedAt        int64
}

// ── 10. sessions ────────────────────────────────────────────────────────────

// Session is `sessions`, one row per agent session, with the per-session
// counters the live view reads. These are agent sessions and have nothing to do
// with authentication.
//
// The id is the sessionId the client chose. It is the primary key, so it is
// globally unique rather than unique per project — which means every read still
// has to filter on project_id or one tenant's session id resolves another
// tenant's row.
type Session struct {
	ID              string
	ProjectID       string
	AgentID         string
	AgentName       string
	APIKeyID        string
	StartedAt       int64
	LastSeenAt      int64
	TotalCalls      int64
	AllowedCalls    int64
	DeniedCalls     int64
	DLPEvents       int64
	RateLimitEvents int64
	PiDetections    int64
	ReadCalls       int64
	WriteCalls      int64
	ExecuteCalls    int64
	NetworkCalls    int64
}

// ── 11. agent_baselines ─────────────────────────────────────────────────────

// AgentBaseline is `agent_baselines`: what normal looks like for one agent, so
// anomaly_events can say what abnormal is. The four Known* columns and the two
// distribution columns are JSON.
type AgentBaseline struct {
	ID               string
	ProjectID        string
	AgentID          string
	ToolDistribution json.RawMessage
	PermissionMix    json.RawMessage
	KnownPaths       json.RawMessage
	KnownDomains     json.RawMessage
	KnownTools       json.RawMessage
	AvgCallsPerHour  float64
	DenyRate         float64
	SampleSize       int64
	Character        string
	TrustScore       float64
	ComputedAt       int64
}

// ── 12. anomaly_events ──────────────────────────────────────────────────────

// AnomalyEvent is `anomaly_events`. Kind is one of new_tool, new_path,
// new_domain, rate_spike, deny_spike, pi_spike; Severity is low, medium or
// high. Neither is constrained by the database.
type AnomalyEvent struct {
	ID          string
	ProjectID   string
	AgentID     string
	SessionID   string
	AuditLogID  string
	Kind        string
	Severity    string
	Score       float64
	Description string
	Detail      json.RawMessage
	CreatedAt   int64
}

// ── 13. agents ──────────────────────────────────────────────────────────────

// Agent is `agents`, the per-project roll-up of one agent identity. AgentID is
// the client's own identifier and is unique only within a project — the primary
// key is the surrogate ID.
type Agent struct {
	ID            string
	ProjectID     string
	AgentID       string
	AgentName     string
	FirstSeenAt   int64
	LastSeenAt    int64
	TotalCalls    int64
	AllowedCalls  int64
	DeniedCalls   int64
	PiDetections  int64
	ParentAgentID string
	APIKeyID      string
	APIKeyName    string
}

// ── 14. agent_groups ────────────────────────────────────────────────────────

// AgentGroup is `agent_groups`. PolicyRules is a JSON array of partial rules
// applied to every member.
type AgentGroup struct {
	ID          string
	ProjectID   string
	Name        string
	Description string
	Color       string
	PolicyRules json.RawMessage
	CreatedAt   int64
	UpdatedAt   int64
}

// ── 15. agent_group_members ─────────────────────────────────────────────────

// AgentGroupMember is `agent_group_members`. It carries project_id as well as
// group_id, redundantly, and the redundancy is useful: a membership query can
// be tenant-scoped without joining the group.
type AgentGroupMember struct {
	ID        string
	GroupID   string
	AgentID   string
	ProjectID string
	CreatedAt int64
}

// ── 16. agent_relationships ─────────────────────────────────────────────────

// AgentRelationship is `agent_relationships`: what one agent may delegate to
// another. RelationshipType is peer, delegation or supervisor; TrustLevel is
// UNTRUSTED, VERIFIED or TRUSTED.
type AgentRelationship struct {
	ID                 string
	ProjectID          string
	SourceAgentID      string
	TargetAgentID      string
	RelationshipType   string
	TrustLevel         string
	AllowedTools       json.RawMessage
	DeniedTools        json.RawMessage
	AllowedPermissions json.RawMessage
	MaxDelegationDepth int64
	Enabled            bool
	CreatedAt          int64
	UpdatedAt          int64
}

// ── 17. delegation_chains ───────────────────────────────────────────────────

// DelegationChain is `delegation_chains`. Chain is the ordered JSON array of
// agent ids; Status is active, revoked or expired.
type DelegationChain struct {
	ID                   string
	ProjectID            string
	Chain                json.RawMessage
	OriginAgentID        string
	TerminalAgentID      string
	EffectiveTools       json.RawMessage
	EffectivePermissions json.RawMessage
	Status               string
	ExpiresAt            *int64
	CreatedAt            int64
	RevokedAt            *int64
}

// ── 18-21. the blog tables ──────────────────────────────────────────────────
//
// blog_posts, blog_categories, blog_tags and blog_post_tags are in this
// database and no route under src/app/api reads them — apps/manage owns the
// blog. They are modelled because they are part of the schema and because a
// shared database means this binary must not be surprised by them; see blog.go,
// which has the reads and nothing else.

// BlogPost is `blog_posts`.
type BlogPost struct {
	ID             string
	Title          string
	Slug           string
	Content        string
	Excerpt        string
	FeaturedImage  string
	Status         string
	AuthorID       string
	CategoryID     string
	SEOTitle       string
	SEODescription string
	PublishedAt    *int64
	CreatedAt      int64
	UpdatedAt      int64
}

// BlogCategory is `blog_categories`.
type BlogCategory struct {
	ID          string
	Name        string
	Slug        string
	Description string
	CreatedAt   int64
}

// BlogTag is `blog_tags`.
type BlogTag struct {
	ID        string
	Name      string
	Slug      string
	CreatedAt int64
}

// BlogPostTag is `blog_post_tags`, the join table. Its primary key is the pair,
// so a post cannot carry the same tag twice.
type BlogPostTag struct {
	PostID string
	TagID  string
}

// ── 22. admin_roles ─────────────────────────────────────────────────────────

// AdminRole is `admin_roles`. Role is super_admin, admin, editor or viewer.
type AdminRole struct {
	ID        string
	UserID    string
	Role      string
	GrantedBy string
	CreatedAt int64
	UpdatedAt int64
}

// ── 23. user_invitations ────────────────────────────────────────────────────

// UserInvitation is `user_invitations`. Token is a bearer credential: whoever
// holds it can accept the invitation, so it is looked up and never listed.
type UserInvitation struct {
	ID         string
	Email      string
	Role       string
	InvitedBy  string
	Token      string
	ExpiresAt  int64
	AcceptedAt *int64
	CreatedAt  int64
}

// ── 24. system_settings ─────────────────────────────────────────────────────

// SystemSetting is `system_settings`, a key/value table keyed by a string.
//
// It carries far more than its name suggests: self-protection, the security
// layers, local logs, the active-policy override, the rate-limit history and
// the per-device guard versions are all rows here, namespaced by a
// `<name>:<projectId>` key. That namespacing is the ONLY thing scoping them to
// a tenant — there is no project_id column — so a caller-supplied key must
// never reach this table. See settings.go, where every key is built from a
// constant plus a project id the API key resolved to.
type SystemSetting struct {
	Key         string
	Value       string
	Description string
	UpdatedBy   string
	UpdatedAt   int64
}

// ── 25. mcp_servers ─────────────────────────────────────────────────────────

// McpServer is `mcp_servers`. URL is an HTTP URL or `stdio://<command>`;
// Status is active, inactive or error.
type McpServer struct {
	ID        string
	ProjectID string
	Name      string
	URL       string
	Status    string
	Command   string
	Args      string
	CreatedAt int64
	UpdatedAt int64
}

// ── 26. solon_usage ─────────────────────────────────────────────────────────

// The value sets the write paths check against. They are the enums from
// schema.ts, which SQLite does not enforce: the columns are plain TEXT, so a
// value outside these would be stored happily and read back as garbage by
// whatever expects the enum.
var (
	OrgRoles              = []string{"owner", "admin", "member", "viewer"}
	AdminRoles            = []string{"super_admin", "admin", "editor", "viewer"}
	BlogPostStatuses      = []string{"draft", "published", "archived"}
	McpServerStatuses     = []string{"active", "inactive", "error"}
	RelationshipTypes     = []string{"peer", "delegation", "supervisor"}
	TrustLevels           = []string{"UNTRUSTED", "VERIFIED", "TRUSTED"}
	DelegationStatuses    = []string{"active", "revoked", "expired"}
	Permissions           = []string{"READ", "WRITE", "EXECUTE", "NETWORK"}
	AnomalySeverities     = []string{"low", "medium", "high"}
	PolicyDecisionEffects = []string{"ALLOW", "DENY"}
)

// OneOf reports whether v is in allowed. Write paths use it to drop a value
// rather than store it, because the column would not refuse it.
func OneOf(v string, allowed []string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}
