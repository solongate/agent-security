package core

import (
	"fmt"
	"strings"
	"time"
)

// ── Trust ──────────────────────────────────────────────────────────────────

// TrustLevel is the security model's central assumption made explicit: an LLM
// is UNTRUSTED, and trust is granted, scoped, and never assumed.
//
//	UNTRUSTED — every LLM-originated request starts here. No permissions.
//	VERIFIED  — passed schema validation and policy evaluation; may execute
//	            within the granted scope.
//	TRUSTED   — system-internal only, and never reachable from a request that
//	            came in from outside.
type TrustLevel string

const (
	TrustUntrusted TrustLevel = "UNTRUSTED"
	TrustVerified  TrustLevel = "VERIFIED"
	TrustTrusted   TrustLevel = "TRUSTED"
)

// IsValidTrustLevel rejects a string that merely looks like a trust level.
// Without it a caller can hand in any string and every comparison below it
// quietly answers "not TRUSTED, therefore fine".
func IsValidTrustLevel(v string) bool {
	switch TrustLevel(v) {
	case TrustUntrusted, TrustVerified, TrustTrusted:
		return true
	}
	return false
}

// AssertValidTransition allows UNTRUSTED to VERIFIED (via policy evaluation)
// and any downgrade. Escalation to TRUSTED is refused outright: it is the level
// that skips every check, so there must be no path to it from a request.
func AssertValidTransition(from, to TrustLevel) error {
	if to == TrustTrusted {
		return &TrustEscalationError{Base: newBase(
			"Cannot escalate to TRUSTED level. TRUSTED is reserved for system-internal operations.",
			"TRUST_ESCALATION", nil)}
	}
	if from == to ||
		(from == TrustVerified && to == TrustUntrusted) ||
		(from == TrustUntrusted && to == TrustVerified) {
		return nil
	}
	return &TrustEscalationError{Base: newBase(
		fmt.Sprintf("Invalid trust transition from %s to %s", from, to),
		"TRUST_ESCALATION", nil)}
}

// ── Permissions ────────────────────────────────────────────────────────────

// Permission categories are ALWAYS evaluated independently. Holding READ does
// not imply WRITE or EXECUTE.
type Permission string

const (
	PermRead    Permission = "READ"
	PermWrite   Permission = "WRITE"
	PermExecute Permission = "EXECUTE"
	PermNetwork Permission = "NETWORK"
)

func IsValidPermission(v string) bool {
	switch Permission(v) {
	case PermRead, PermWrite, PermExecute, PermNetwork:
		return true
	}
	return false
}

// GuessPermission classifies a tool name, and is a faithful port of the core
// module's classifier.
//
// IT IS NOT THE ENFORCING ONE. What a policy rule actually matches on is
// `input.permission`, produced by packages/guard-go's guessPermission, which is
// a superset: it maps Codex's `apply_patch` to WRITE (no substring here catches
// it, so this function calls a Codex file edit a READ) and matches `bash` and
// `websearch` exactly. Use this for display and for describing a tool. Do not
// use it to decide anything — see the caveat about sharing the classifier.
func GuessPermission(toolName string) Permission {
	n := strings.ToLower(toolName)
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(n, s) {
				return true
			}
		}
		return false
	}
	switch {
	case has("exec", "shell", "run", "eval"):
		return PermExecute
	case has("fetch", "http", "request", "curl", "network", "download", "upload"):
		return PermNetwork
	case has("write", "create", "delete", "update", "set", "edit", "remove", "insert"):
		return PermWrite
	default:
		return PermRead
	}
}

// PermissionForMethod maps an MCP protocol method to a permission. An unknown
// method is EXECUTE, the most restrictive answer, so a method added upstream
// starts out governed rather than ungoverned.
func PermissionForMethod(method string) Permission {
	if strings.HasPrefix(method, "resources/") || strings.HasPrefix(method, "prompts/") || method == "tools/list" {
		return PermRead
	}
	return PermExecute
}

// PermissionSet is a set of granted permissions. The zero value grants nothing,
// which is the default every new tool starts from.
type PermissionSet map[Permission]struct{}

func NewPermissionSet(perms ...Permission) (PermissionSet, error) {
	s := make(PermissionSet, len(perms))
	for _, p := range perms {
		if !IsValidPermission(string(p)) {
			return nil, fmt.Errorf("invalid permission %q", p)
		}
		s[p] = struct{}{}
	}
	return s, nil
}

func (s PermissionSet) Has(p Permission) bool {
	_, ok := s[p]
	return ok
}

func (s PermissionSet) HasAll(required ...Permission) bool {
	for _, p := range required {
		if !s.Has(p) {
			return false
		}
	}
	return true
}

// ReadOnly is the maximum default for a new tool.
func ReadOnly() PermissionSet { return PermissionSet{PermRead: {}} }

// ── Policy ─────────────────────────────────────────────────────────────────

// PolicyEffect has two values and no third. A security decision that can come
// back "maybe" is one nobody can act on.
type PolicyEffect string

const (
	EffectAllow PolicyEffect = "ALLOW"
	EffectDeny  PolicyEffect = "DENY"
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

// PolicyRule as the core module models it: one permission, not a list. The wire
// shape the API sends allows either, and that difference is handled in the api
// package rather than papered over here.
type PolicyRule struct {
	ID                  string          `json:"id"`
	Description         string          `json:"description"`
	Effect              PolicyEffect    `json:"effect"`
	Priority            int             `json:"priority"`
	ToolPattern         string          `json:"toolPattern"`
	Permission          Permission      `json:"permission,omitempty"`
	MinimumTrustLevel   TrustLevel      `json:"minimumTrustLevel"`
	ArgumentConstraints map[string]any  `json:"argumentConstraints,omitempty"`
	PathConstraints     *PathConstraint `json:"pathConstraints,omitempty"`
	CommandConstraints  *Constraint     `json:"commandConstraints,omitempty"`
	FilenameConstraints *Constraint     `json:"filenameConstraints,omitempty"`
	URLConstraints      *Constraint     `json:"urlConstraints,omitempty"`
	Enabled             bool            `json:"enabled"`
	CreatedAt           string          `json:"createdAt"`
	UpdatedAt           string          `json:"updatedAt"`
}

// PolicySet is a versioned, ordered set of rules. Rules are evaluated by
// priority and the first match wins; when nothing matches the answer is DENY.
type PolicySet struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Version     int          `json:"version"`
	Rules       []PolicyRule `json:"rules"`
	CreatedAt   string       `json:"createdAt"`
	UpdatedAt   string       `json:"updatedAt"`
}

// PolicyDecision is the result of evaluating a policy against a request.
type PolicyDecision struct {
	Effect           PolicyEffect      `json:"effect"`
	MatchedRule      *PolicyRule       `json:"matchedRule"`
	Reason           string            `json:"reason"`
	Timestamp        string            `json:"timestamp"`
	EvaluationTimeMs float64           `json:"evaluationTimeMs"`
	Metadata         *DecisionMetadata `json:"metadata,omitempty"`
}

type DecisionMetadata struct {
	EvaluatedRules int      `json:"evaluatedRules"`
	RuleIDs        []string `json:"ruleIds,omitempty"`
	RequestContext struct {
		Tool      string   `json:"tool"`
		Arguments []string `json:"arguments"`
	} `json:"requestContext"`
}

// ── Tools ──────────────────────────────────────────────────────────────────

// ToolCapability wraps an MCP tool definition with what it is allowed to do.
type ToolCapability struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	ServerName  string `json:"serverName"`
	// The ceiling: the most this tool can ever be granted.
	MaxPermissions []Permission `json:"maxPermissions"`
	// What it gets with no explicit policy. Empty, because the model is
	// default-deny.
	DefaultPermissions []Permission   `json:"defaultPermissions"`
	InputSchema        map[string]any `json:"inputSchema"`
	// A tool with side effects cannot be treated as READ-only.
	HasSideEffects bool `json:"hasSideEffects"`
	// Affects audit-log redaction.
	AccessesSensitiveData bool `json:"accessesSensitiveData"`
	// 0 means unlimited.
	RateLimitPerMinute int `json:"rateLimitPerMinute"`
}

// NewToolCapability starts from the most restrictive answer to every question
// the caller did not answer: no permissions, assume side effects, assume
// sensitive data.
func NewToolCapability(name, description, serverName string, inputSchema map[string]any) ToolCapability {
	return ToolCapability{
		Name:                  name,
		Description:           description,
		ServerName:            serverName,
		InputSchema:           inputSchema,
		MaxPermissions:        nil,
		DefaultPermissions:    nil,
		HasSideEffects:        true,
		AccessesSensitiveData: true,
		RateLimitPerMinute:    60,
	}
}

// ── Context ────────────────────────────────────────────────────────────────

// SecurityContext is the security state of ONE request. It is created fresh per
// request and never reused: a context that outlives its request is a grant that
// outlives the reason it was given.
type SecurityContext struct {
	RequestID          string
	TrustLevel         TrustLevel
	GrantedPermissions PermissionSet
	SessionID          string
	CreatedAt          string
	Metadata           map[string]any
	CapabilityToken    string
}

// ExecutionContext adds the tool call to a SecurityContext.
type ExecutionContext struct {
	SecurityContext
	ToolName   string
	ServerName string
	Arguments  map[string]any
}

// NewSecurityContext starts default-deny: UNTRUSTED, no permissions.
func NewSecurityContext(requestID string) SecurityContext {
	return SecurityContext{
		RequestID:          requestID,
		TrustLevel:         TrustUntrusted,
		GrantedPermissions: PermissionSet{},
		Metadata:           map[string]any{},
		CreatedAt:          time.Now().UTC().Format(time.RFC3339Nano),
	}
}

// ── Execution ──────────────────────────────────────────────────────────────

type ExecutionRequest struct {
	Context            SecurityContext
	ToolName           string
	ServerName         string
	Arguments          map[string]any
	RequiredPermission Permission
	Timestamp          string
}

// ExecutionStatus discriminates an ExecutionResult. Kept explicit so a caller
// that forgets a case fails loudly rather than treating an error as an allow.
type ExecutionStatus string

const (
	StatusAllowed ExecutionStatus = "ALLOWED"
	StatusDenied  ExecutionStatus = "DENIED"
	StatusError   ExecutionStatus = "ERROR"
)

type ExecutionResult struct {
	Status     ExecutionStatus
	Request    ExecutionRequest
	Decision   *PolicyDecision
	ToolResult any
	Err        error
	DurationMs float64
	Timestamp  string
}

// ── MCP bridge types ───────────────────────────────────────────────────────

type McpToolDefinition struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	InputSchema struct {
		Type       string         `json:"type"`
		Properties map[string]any `json:"properties,omitempty"`
		Required   []string       `json:"required,omitempty"`
	} `json:"inputSchema"`
}

type McpCallToolParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

type McpToolResultContent struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	Resource any    `json:"resource,omitempty"`
}

type McpCallToolResult struct {
	Content           []McpToolResultContent `json:"content"`
	IsError           bool                   `json:"isError,omitempty"`
	StructuredContent any                    `json:"structuredContent,omitempty"`
}

// ── Capability tokens ──────────────────────────────────────────────────────

// CapabilityToken is short-lived, single-use and scoped. The CLI does not issue
// or verify them; the shape is here because it travels with the core types.
type CapabilityToken struct {
	JTI         string       `json:"jti"`
	Iss         string       `json:"iss"`
	Sub         string       `json:"sub"`
	Iat         int64        `json:"iat"`
	Exp         int64        `json:"exp"`
	Permissions []Permission `json:"permissions"`
	ToolScope   []string     `json:"toolScope"`
	ServerScope []string     `json:"serverScope"`
	PathScope   []string     `json:"pathScope,omitempty"`
}

const TokenAlgorithm = "HS256"
