package store

import "encoding/json"

// The tables, as Go.
//
// These are the schema's tables, in the order schema.go creates them.
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
// the append-only history is built on.
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

// ── 8. audit_logs ───────────────────────────────────────────────────────────

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

// ── 9. mcp_servers ─────────────────────────────────────────────────────────

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

// ── 10. solon_usage ─────────────────────────────────────────────────────────

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
