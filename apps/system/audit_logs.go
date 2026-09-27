package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/policyjson"
	"github.com/codeyevsky/solongate/system/internal/store"
)

// /api/v1/audit-logs — the port of src/app/api/v1/audit-logs/route.ts.
//
// POST is the highest-volume endpoint in this service. Every installed guard
// fires it from a DETACHED child that does not wait for the answer, and the
// audit hook fires it fire-and-forget with a five-second timeout, so its body
// shape is a contract with software on somebody's laptop that will not be
// redeployed with this. The field list below is that body, read off the
// clients rather than off the schema: `evaluationTimeMs` is camelCase because
// the audit hook spells it that way, `session_id` has a `sessionId` twin
// because two versions of the hook are in the wild, and `promptInjection` is an
// object with flat `pi_*` fallbacks for the same reason.
//
// GET is the dashboard's audit page and the CLI's `solongate logs`. Its
// response carries two fields that are not columns — see audit_signals.go.
//
// There is no third verb. See the note in init().

func init() {
	Register("POST /api/v1/audit-logs", buildAuditLogPost)
	Register("GET /api/v1/audit-logs", buildAuditLogList)

	// There is no delete, and its absence is the feature.
	//
	// An audit log that the audited party can erase is not an audit log. This
	// service records what an agent was allowed to run on somebody's machine,
	// and a host is answerable for a fleet on the strength of it; a button that
	// clears the history makes every one of those records provisional, and the
	// one time it matters is the one time it will have been pressed.
	//
	// Retention is a different question from deletion and is answered
	// differently: conversation_turns expires on a schedule nobody has to
	// operate. If this table ever needs bounding it belongs there, as a sweep
	// with an age on it, not as an endpoint somebody can call.
}

// ── POST ────────────────────────────────────────────────────────────────────

// auditPostBody is the reported call.
//
// Almost every field is `any` rather than `string`, and that is not laziness:
// the live route reads them through `String(x || ”)`, so a client sending a
// number where a name was expected gets it stringified rather than rejected.
// Typing these as strings here would turn a working client into a 400 the first
// time it sent `agent_id: 3`.
type auditPostBody struct {
	Tool        any             `json:"tool"`
	RequestID   any             `json:"request_id"`
	Arguments   json.RawMessage `json:"arguments"`
	Source      any             `json:"source"`
	Permission  any             `json:"permission"`
	TrustLevel  any             `json:"trust_level"`
	Decision    any             `json:"decision"`
	MatchedRule any             `json:"matchedRule"`
	Reason      any             `json:"reason"`

	EvaluationTimeMsSnake any `json:"evaluation_time_ms"`
	EvaluationTimeMsCamel any `json:"evaluationTimeMs"`

	PromptInjection *promptInjectionBlock `json:"promptInjection"`
	PiDetected      any                   `json:"pi_detected"`
	PiTrustScore    any                   `json:"pi_trust_score"`
	PiBlocked       any                   `json:"pi_blocked"`
	PiCategories    json.RawMessage       `json:"pi_categories"`
	PiStageScores   json.RawMessage       `json:"pi_stage_scores"`

	AgentID      any `json:"agent_id"`
	AgentName    any `json:"agent_name"`
	SubAgentID   any `json:"sub_agent_id"`
	SubAgentName any `json:"sub_agent_name"`

	SessionIDSnake any `json:"session_id"`
	SessionIDCamel any `json:"sessionId"`
}

type promptInjectionBlock struct {
	Detected          any             `json:"detected"`
	TrustScore        any             `json:"trustScore"`
	Blocked           any             `json:"blocked"`
	MatchedCategories json.RawMessage `json:"matchedCategories"`
	StageScores       json.RawMessage `json:"stageScores"`
}

func buildAuditLogPost(s *server) http.Handler {
	return s.auth.WithAuth(func(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
		var body auditPostBody
		if !apiauth.DecodeJSON(w, r, &body, false) {
			return
		}
		if !jsTruthy(body.Tool) {
			apiauth.BadRequest(w, "Missing required field: tool")
			return
		}

		ctx := r.Context()
		entry := body.toAuditLog(key)

		if err := s.store.InsertAuditLog(ctx, entry); err != nil {
			apiauth.Internal(w, "api", err)
			return
		}

		// The webhook and the alert evaluation are fire-and-forget in the live
		// route — `void (async () => …)()` — and have to stay that way. This is
		// the endpoint a detached child calls on every denial; making it wait on
		// somebody's Slack endpoint would put a stranger's outage on the path of
		// every audit write.
		//
		// The context is detached from the request's, because the request's is
		// cancelled the moment this handler returns and that is before either of
		// these has sent anything.
		s.notifyAudit(context.WithoutCancel(ctx), key.ProjectID, entry)

		// The roll-ups are best-effort and their failures are logged, not
		// returned: an audit entry that was stored must be reported as stored,
		// or a client that retries writes it twice.
		if entry.AgentID != "" && key.IsLive {
			recordAgentRollup(ctx, s.store, key, entry)
		}
		if entry.SessionID != "" && key.IsLive {
			recordSessionRollup(ctx, s.store, key, entry)
		}

		apiauth.JSON(w, http.StatusCreated, map[string]string{
			"id":     entry.ID,
			"status": "recorded",
		})
	})
}

// The field widths. They are the live route's `.slice(n)` calls and they are
// the reason store.Clip exists — JavaScript counts UTF-16 code units and Go
// counts bytes, so a naive s[:n] would cut a multi-byte character in half and
// store invalid UTF-8 under a name nobody can search for.
const (
	maxRequestID    = 64
	maxToolName     = 256
	maxServerName   = 256
	maxPermission   = 20
	maxTrustLevel   = 20
	maxDecision     = 10
	maxMatchedRule  = 100
	maxReason       = 1000
	maxAgentField   = 256
	maxSessionID    = 128
	maxPiCategories = 50
)

// toAuditLog is the body as a row. Every default here is the live route's.
func (b auditPostBody) toAuditLog(key apiauth.KeyInfo) store.AuditLog {
	requestID := jsString(b.RequestID)
	if requestID == "" {
		// A client that does not send one gets a generated id rather than an
		// empty column: the request id is how a denial in the dashboard is
		// matched to a line in somebody's local log.
		requestID = uuid.NewString()
	}

	argsHash, argsSummary := summariseArguments(b.Arguments)

	entry := store.AuditLog{
		ID:               uuid.NewString(),
		ProjectID:        key.ProjectID,
		RequestID:        store.Clip(requestID, maxRequestID),
		SessionID:        store.Clip(firstNonEmpty(jsString(b.SessionIDSnake), jsString(b.SessionIDCamel)), maxSessionID),
		ToolName:         store.Clip(jsString(b.Tool), maxToolName),
		ServerName:       store.Clip(orDefault(jsString(b.Source), "proxy"), maxServerName),
		Permission:       store.Clip(orDefault(jsString(b.Permission), "EXECUTE"), maxPermission),
		TrustLevel:       store.Clip(orDefault(jsString(b.TrustLevel), "UNTRUSTED"), maxTrustLevel),
		Decision:         store.Clip(orDefault(jsString(b.Decision), "ALLOW"), maxDecision),
		ArgumentsHash:    argsHash,
		ArgumentsSummary: argsSummary,
		AgentID:          store.Clip(jsString(b.AgentID), maxAgentField),
		AgentName:        store.Clip(jsString(b.AgentName), maxAgentField),
		SubAgentID:       store.Clip(jsString(b.SubAgentID), maxAgentField),
		SubAgentName:     store.Clip(jsString(b.SubAgentName), maxAgentField),
		APIKeyID:         key.KeyID,
		CreatedAt:        store.Now(),
	}

	if jsTruthy(b.MatchedRule) {
		entry.MatchedRuleID = store.Clip(jsString(b.MatchedRule), maxMatchedRule)
	}
	if jsTruthy(b.Reason) {
		entry.Reason = store.Clip(jsString(b.Reason), maxReason)
	}
	entry.EvaluationTimeMs = firstNumber(b.EvaluationTimeMsSnake, b.EvaluationTimeMsCamel)

	b.applyPromptInjection(&entry)
	return entry
}

// applyPromptInjection fills the pi_* columns from either shape.
//
// The nested `promptInjection` object wins over the flat fields, and NULL is
// kept distinct from false throughout: NULL is "the scanner did not run on this
// call" and false is "it ran and found nothing". Collapsing them would make
// every call from a client with injection detection disabled look like a call
// that had been checked and cleared.
func (b auditPostBody) applyPromptInjection(entry *store.AuditLog) {
	pi := b.PromptInjection

	if pi != nil && pi.Detected != nil {
		entry.PiDetected = asBoolPtr(jsTruthy(pi.Detected))
	} else if b.PiDetected != nil {
		entry.PiDetected = asBoolPtr(jsTruthy(b.PiDetected))
	}

	if pi != nil && pi.Blocked != nil {
		entry.PiBlocked = asBoolPtr(jsTruthy(pi.Blocked))
	} else if b.PiBlocked != nil {
		entry.PiBlocked = asBoolPtr(jsTruthy(b.PiBlocked))
	}

	var rawScore any
	switch {
	case pi != nil && pi.TrustScore != nil:
		rawScore = pi.TrustScore
	case b.PiTrustScore != nil:
		rawScore = b.PiTrustScore
	}
	if rawScore != nil {
		score := clamp01(rawScore)
		entry.PiTrustScore = &score
	}

	var nestedCategories, nestedStages json.RawMessage
	if pi != nil {
		nestedCategories, nestedStages = pi.MatchedCategories, pi.StageScores
	}
	entry.PiCategories = piCategoriesJSON(pickPiRaw(nestedCategories, b.PiCategories))
	entry.PiStageScores = piStageScoresJSON(pickPiRaw(nestedStages, b.PiStageScores))
}

// pickPiRaw is the `pi?.x ?? body.x_flat` chain, with the flat form's extra
// rule: it may arrive as a JSON STRING holding JSON, because one version of the
// hook double-encoded it and those clients are still installed.
func pickPiRaw(nested, flat json.RawMessage) json.RawMessage {
	if isJSONValue(nested) {
		return nested
	}
	if !isJSONValue(flat) {
		return nil
	}
	var asString string
	if json.Unmarshal(flat, &asString) == nil {
		if asString == "" || !json.Valid([]byte(asString)) {
			return nil
		}
		return json.RawMessage(asString)
	}
	return flat
}

// isJSONValue reports whether a field was present with something other than
// null — the distinction `??` makes.
func isJSONValue(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}

// piCategoriesJSON keeps an array of strings and drops anything else.
//
// "Anything else" includes an array with one non-string in it, which the live
// route rejects wholesale with `.every`. That is the safe reading: the column
// is handed to JSON.parse by the dashboard and iterated as strings.
func piCategoriesJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var list []any
	if json.Unmarshal(raw, &list) != nil {
		return ""
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, ok := v.(string)
		if !ok {
			return ""
		}
		out = append(out, s)
		if len(out) >= maxPiCategories {
			break
		}
	}
	b, err := marshalNoEscape(out)
	if err != nil {
		return ""
	}
	return string(b)
}

// piStageScoresJSON normalises the three stage scores.
//
// The stored shape is exactly {rules, embedding, classifier}, each clamped to
// 0..1, whatever the client sent — a stage the client does not run is stored as
// 0 rather than omitted, because the dashboard's three-bar display reads all
// three and a missing key renders as a bar of NaN.
func piStageScoresJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var obj map[string]any
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		return ""
	}
	b, err := marshalNoEscape(map[string]float64{
		"rules":      clamp01(obj["rules"]),
		"embedding":  clamp01(obj["embedding"]),
		"classifier": clamp01(obj["classifier"]),
	})
	if err != nil {
		return ""
	}
	return string(b)
}

// summariseArguments produces the two argument columns.
//
// The hash is over the FULL arguments and the summary is over a copy with long
// strings cut, so the two are not serialisations of the same value — that is
// the live behaviour and it is why a summary can be truncated while the hash
// still identifies the call exactly.
//
// Only an object is accepted. The live route's guard is `typeof === 'object'`,
// which an array also passes, and Object.entries would then give it index keys
// — a shape no deployed client sends, since the arguments are always a tool's
// input object.
func summariseArguments(raw json.RawMessage) (hash string, summary string) {
	args, ok := policyjson.ParseObject(raw)
	if !ok {
		return "", ""
	}

	// policyjson.Stringify, not encoding/json: the key ORDER is what the
	// dashboard renders arguments in, and a Go map would sort them.
	sum := sha256.Sum256([]byte(policyjson.Stringify(args, nil)))
	// Sixteen hex characters, as the live route slices it. It is a call
	// fingerprint for grouping, not a checksum anything verifies.
	hash = hex.EncodeToString(sum[:])[:16]

	clipped := policyjson.NewObject()
	for _, key := range args.Keys() {
		clipped.Set(key, clipLongString(args.Get(key)))
	}
	// The 16384 cut can land mid-token and leave the column holding a JSON
	// fragment. That is the live behaviour, and every reader of this column
	// already parses it inside a try/catch for exactly this reason.
	return hash, store.Clip(policyjson.Stringify(clipped, nil), maxArgumentsSummary)
}

const (
	// maxArgumentValue is the per-value cut, and the ellipsis is the live
	// route's single character rather than three dots.
	maxArgumentValue    = 8000
	maxArgumentsSummary = 16384
	argumentEllipsis    = "…"
)

// clipLongString shortens one argument value if it is a long string, leaving
// every other JSON type untouched.
//
// store.Clip counts RUNES where JavaScript's slice counts UTF-16 code units.
// The difference shows only for astral-plane characters, and it errs the right
// way: JavaScript can cut a surrogate pair in half and store a lone surrogate,
// which is not valid UTF-8 and not searchable.
func clipLongString(v any) any {
	s, isString := v.(string)
	if !isString || len([]rune(s)) <= maxArgumentValue {
		return v
	}
	return store.Clip(s, maxArgumentValue) + argumentEllipsis
}

// ── the roll-ups ────────────────────────────────────────────────────────────

// recordAgentRollup applies the call to the agents table, and to the sub-agent
// row when the call named one.
//
// Both are best-effort: a failure here is logged and the request still
// succeeds, because the audit entry is the record and the roll-up is a cache of
// it. The live route wraps each in its own try/catch for the same reason.
func recordAgentRollup(ctx context.Context, st *store.Store, key apiauth.KeyInfo, entry store.AuditLog) {
	allowed := entry.Decision == "ALLOW"
	pi := entry.PiDetected != nil && *entry.PiDetected

	if err := st.RecordAgentCall(ctx, store.AgentCall{
		ProjectID:  key.ProjectID,
		AgentID:    entry.AgentID,
		AgentName:  entry.AgentName,
		APIKeyID:   key.KeyID,
		APIKeyName: key.KeyName,
		MatchByKey: true,
		NewRowID:   uuid.NewString(),
		Allowed:    allowed,
		PiDetected: pi,
		At:         entry.CreatedAt,
	}); err != nil {
		logRollup("agent", err)
	}

	if entry.SubAgentID == "" {
		return
	}
	// The composite id is how a sub-agent gets its own row without colliding
	// with another parent's sub-agent of the same name.
	compositeID := entry.AgentID + "::" + entry.SubAgentID
	compositeName := entry.SubAgentName
	if compositeName == "" {
		compositeName = entry.SubAgentID
	}
	if err := st.RecordAgentCall(ctx, store.AgentCall{
		ProjectID:     key.ProjectID,
		AgentID:       compositeID,
		AgentName:     compositeName,
		ParentAgentID: entry.AgentID,
		MatchByKey:    false,
		NewRowID:      uuid.NewString(),
		Allowed:       allowed,
		PiDetected:    pi,
		At:            entry.CreatedAt,
	}); err != nil {
		logRollup("sub-agent", err)
	}
}

var (
	dlpReasonWords       = regexp.MustCompile(`(?i)dlp|data loss|sensitive|secret`)
	rateLimitReasonWords = regexp.MustCompile(`(?i)rate limit|rate-limit|too many`)
)

// recordSessionRollup applies the call to the per-session counters the live
// agent view reads.
//
// The DLP and rate-limit tallies are matched out of the REASON text, which is
// the same indirect evidence audit_signals.go explains: neither is a column on
// the audit row, so a session's counter is the only place a detect-mode event
// is ever totalled.
func recordSessionRollup(ctx context.Context, st *store.Store, key apiauth.KeyInfo, entry store.AuditLog) {
	decision := strings.ToUpper(entry.Decision)
	isDeny := decision == "DENY" || decision == "DENIED"

	delta := store.SessionCounterDelta{Total: 1}
	if isDeny {
		delta.Denied = 1
	} else {
		delta.Allowed = 1
	}
	if dlpReasonWords.MatchString(entry.Reason) {
		delta.DLPEvents = 1
	}
	if rateLimitReasonWords.MatchString(entry.Reason) {
		delta.RateLimitEvents = 1
	}
	if entry.PiDetected != nil && *entry.PiDetected {
		delta.PiDetections = 1
	}
	switch strings.ToUpper(entry.Permission) {
	case "READ":
		delta.Read = 1
	case "WRITE":
		delta.Write = 1
	case "EXECUTE":
		delta.Execute = 1
	case "NETWORK":
		delta.Network = 1
	}

	// Create-then-increment, two statements, because the counters must be
	// applied as a delta: several calls from one agent land at once and a
	// read-modify-write would lose all but the last.
	//
	// UpsertSession does not refresh api_key_id on a row that already exists,
	// where the live route does. A session that outlives a key rotation keeps
	// the id of the key that opened it, which is arguably the truer answer and
	// is noted here so it is a decision rather than a surprise.
	if err := st.UpsertSession(ctx, store.Session{
		ID:         entry.SessionID,
		ProjectID:  key.ProjectID,
		AgentID:    entry.AgentID,
		AgentName:  entry.AgentName,
		APIKeyID:   key.KeyID,
		StartedAt:  entry.CreatedAt,
		LastSeenAt: entry.CreatedAt,
	}); err != nil {
		logRollup("session", err)
		return
	}
	if err := st.BumpSessionCounters(ctx, key.ProjectID, entry.SessionID, delta, entry.CreatedAt); err != nil {
		logRollup("session counters", err)
	}
}

// ── GET ─────────────────────────────────────────────────────────────────────

// auditListEntry is one row of the response, field for field with the live
// route's mapping. The struct exists rather than a map so the field ORDER is
// the live one — a map would emit them alphabetically.
type auditListEntry struct {
	ID               string          `json:"id"`
	RequestID        string          `json:"request_id"`
	SessionID        *string         `json:"session_id"`
	ToolName         string          `json:"tool_name"`
	ServerName       *string         `json:"server_name"`
	Permission       string          `json:"permission"`
	TrustLevel       string          `json:"trust_level"`
	Decision         string          `json:"decision"`
	MatchedRuleID    *string         `json:"matched_rule_id"`
	MatchedRule      json.RawMessage `json:"matched_rule"`
	Reason           *string         `json:"reason"`
	EvaluationTimeMs *float64        `json:"evaluation_time_ms"`
	ArgumentsHash    string          `json:"arguments_hash"`
	ArgumentsSummary json.RawMessage `json:"arguments_summary"`
	DLPMatches       []string        `json:"dlp_matches"`
	RateLimitBurst   bool            `json:"rate_limit_burst"`
	PiDetected       *bool           `json:"pi_detected"`
	PiTrustScore     *float64        `json:"pi_trust_score"`
	PiBlocked        *bool           `json:"pi_blocked"`
	PiCategories     json.RawMessage `json:"pi_categories"`
	PiStageScores    json.RawMessage `json:"pi_stage_scores"`
	AgentID          *string         `json:"agent_id"`
	AgentName        *string         `json:"agent_name"`
	SubAgentID       *string         `json:"sub_agent_id"`
	SubAgentName     *string         `json:"sub_agent_name"`
	APIKeyID         *string         `json:"api_key_id"`
	APIKeyName       *string         `json:"api_key_name"`
	CreatedAt        string          `json:"created_at"`
	// UserID and Who are WHOSE call this was, filled only where the answer is
	// about more than one person — the fleet console. On a single account's
	// audit page they would be the same value on every row.
	UserID string `json:"user_id,omitempty"`
	Who    string `json:"who,omitempty"`
}

const (
	// defaultAuditLimit and maxAuditLimit are the live route's. 10000 is what
	// the dashboard's "export everything" sends.
	defaultAuditLimit = 50
	maxAuditLimit     = 10000

	// signalCandidates is how deep the DLP / rate-limit filters look. Those two
	// filters cannot be expressed in SQL — neither signal is a column — so the
	// route pulls a window and filters it in memory, and the window is what
	// bounds the work. It is the live route's number.
	signalCandidates = 3000

	// maxRuleVersions is how many policy revisions are searched to put a name to
	// a matched rule id. Also the live route's.
	maxRuleVersions = 30
)

func buildAuditLogList(s *server) http.Handler {
	return s.auth.WithAuth(func(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
		ctx := r.Context()
		q := r.URL.Query()

		limit := boundInt(queryIntDefault(q.Get("limit"), defaultAuditLimit), 1, maxAuditLimit)
		offset := queryIntDefault(q.Get("offset"), 0)
		slim := auditSlimRequested(r)
		if offset < 0 {
			offset = 0
		}

		filter := store.AuditFilter{
			ToolLike:  q.Get("tool"),
			AgentName: q.Get("agent_name"),
			SessionID: q.Get("session_id"),
			Search:    q.Get("search"),
			Order:     "created_at",
			Dir:       store.Desc,
		}

		// Only the three decisions the live route accepts reach the query. An
		// unrecognised `filter` is IGNORED rather than refused, which is the
		// original's behaviour and keeps an old dashboard sending `?filter=all`
		// working.
		switch d := q.Get("filter"); d {
		case "ALLOW", "DENY", "DENIED":
			filter.Decision = d
		}
		// `from` and `to` are MILLISECONDS on the wire and SECONDS in the
		// column. drizzle's timestamp mode stores seconds and the dashboard
		// sends Date.now(), so the conversion belongs here; forgetting it asks
		// the database for a range fifty thousand years wide.
		if ms, ok := queryInt(q.Get("from")); ok {
			filter.Since = ms / 1000
		}
		if ms, ok := queryInt(q.Get("to")); ok {
			filter.Until = ms / 1000
		}

		signal := q.Get("signal")
		isSignalFilter := signal == "dlp" || signal == "ratelimit"

		layers := s.store.GetSecurityLayers(ctx, key.ProjectID)
		history := s.store.RateLimitHistory(ctx, key.ProjectID)
		keyNames, err := s.store.AuditKeyNames(ctx, key.ProjectID)
		if err != nil {
			apiauth.Internal(w, "api", err)
			return
		}

		var entries []store.AuditLog
		var total int64

		if isSignalFilter {
			// The signal filters page in memory: fetch a window, decide which
			// rows carry the signal, then apply the caller's offset to the
			// MATCHED rows. `total` is therefore the matched count within the
			// window, not the project's total, which is what the live route
			// reports too.
			candidates, err := s.store.ListAuditLogs(ctx, key.ProjectID, withLimit(filter, signalCandidates, 0))
			if err != nil {
				apiauth.Internal(w, "api", err)
				return
			}
			bursts, err := buildBurstIndex(ctx, s.store, key.ProjectID, layers, history, candidates)
			if err != nil {
				apiauth.Internal(w, "api", err)
				return
			}
			scanner := newDLPScanner(layers)

			matched := []store.AuditLog{}
			for _, e := range candidates {
				if signal == "dlp" {
					if len(scanner.dlpMatchesOf(e.ArgumentsSummary, e.Reason)) > 0 {
						matched = append(matched, e)
					}
					continue
				}
				if bursts.has(e.AgentName, e.CreatedAt) || deniedForRateLimit(e.Decision, e.Reason) {
					matched = append(matched, e)
				}
			}
			total = int64(len(matched))
			entries = pageOf(matched, offset, limit)

			s.writeAuditList(ctx, w, key, entries, total, limit, offset, layers, scanner, bursts, keyNames, slim)
			return
		}

		entries, err = s.store.ListAuditLogs(ctx, key.ProjectID, withLimit(filter, limit, offset))
		if err != nil {
			apiauth.Internal(w, "api", err)
			return
		}
		total, err = s.store.CountAuditLogs(ctx, key.ProjectID, filter)
		if err != nil {
			apiauth.Internal(w, "api", err)
			return
		}
		bursts, err := buildBurstIndex(ctx, s.store, key.ProjectID, layers, history, entries)
		if err != nil {
			apiauth.Internal(w, "api", err)
			return
		}

		s.writeAuditList(ctx, w, key, entries, total, limit, offset, layers,
			newDLPScanner(layers), bursts, keyNames, slim)
	})
}

func (s *server) writeAuditList(ctx context.Context, w http.ResponseWriter, key apiauth.KeyInfo,
	entries []store.AuditLog, total int64, limit, offset int,
	layers store.SecurityLayers, scanner *dlpScanner, bursts *burstIndex, keyNames map[string]string,
	slim bool) {

	out := s.auditEntriesJSON(ctx, key.ProjectID, entries, scanner, bursts, keyNames)
	if slim {
		// The caller aggregates rather than reads. See audit_slim.go: the
		// difference is roughly ten times the response, and at five thousand
		// rows the full shape went past what the dashboard's client will read.
		out = slimAuditEntries(out)
	}

	apiauth.JSON(w, http.StatusOK, map[string]any{
		"entries":               out,
		"total":                 total,
		"limit":                 limit,
		"offset":                offset,
		"rate_limit_per_minute": layers.RateLimit.PerMinute,
	})
}

// auditEntriesJSON maps stored rows onto the wire shape.
//
// Extracted from writeAuditList because the fleet console answers with the SAME
// rows under a different envelope, and a second mapping is a second place for a
// field to go missing — which is how a console ended up with no evaluation
// times, no permission, no DLP hits and no arguments while the audit page a
// click away had all four.
func (s *server) auditEntriesJSON(ctx context.Context, projectID string,
	entries []store.AuditLog, scanner *dlpScanner, bursts *burstIndex,
	keyNames map[string]string) []auditListEntry {

	rules := s.resolveMatchedRules(ctx, projectID, entries)

	out := make([]auditListEntry, 0, len(entries))
	for _, e := range entries {
		row := auditListEntry{
			ID:               e.ID,
			RequestID:        e.RequestID,
			SessionID:        nullable(e.SessionID),
			ToolName:         e.ToolName,
			ServerName:       nullable(e.ServerName),
			Permission:       e.Permission,
			TrustLevel:       e.TrustLevel,
			Decision:         e.Decision,
			MatchedRuleID:    nullable(e.MatchedRuleID),
			Reason:           nullable(e.Reason),
			EvaluationTimeMs: e.EvaluationTimeMs,
			ArgumentsHash:    e.ArgumentsHash,
			ArgumentsSummary: rawOrNull(e.ArgumentsSummary),
			DLPMatches:       scanner.dlpMatchesOf(e.ArgumentsSummary, e.Reason),
			RateLimitBurst:   bursts.has(e.AgentName, e.CreatedAt) || deniedForRateLimit(e.Decision, e.Reason),
			PiDetected:       e.PiDetected,
			PiTrustScore:     e.PiTrustScore,
			PiBlocked:        e.PiBlocked,
			PiCategories:     rawOrNull(e.PiCategories),
			PiStageScores:    rawOrNull(e.PiStageScores),
			AgentID:          nullable(e.AgentID),
			AgentName:        nullable(e.AgentName),
			SubAgentID:       nullable(e.SubAgentID),
			SubAgentName:     nullable(e.SubAgentName),
			APIKeyID:         nullable(e.APIKeyID),
			CreatedAt:        store.ISO(e.CreatedAt),
		}
		if e.APIKeyID != "" {
			row.APIKeyName = nullable(keyNames[e.APIKeyID])
		}
		if id := matchedRuleID(e.MatchedRuleID, e.Reason); id != "" {
			row.MatchedRule = rules[id]
		}
		out = append(out, row)
	}
	return out
}

// ruleFromReason recovers a rule id the guard mentioned in its reason but did
// not store in the column, which is what an older guard did.
var ruleFromReason = regexp.MustCompile(`(?i)rule\s+"?([\w.-]+)"?`)

func matchedRuleID(column, reason string) string {
	if id := strings.TrimSpace(column); id != "" {
		return id
	}
	if m := ruleFromReason.FindStringSubmatch(reason); m != nil {
		return m[1]
	}
	return ""
}

// resolveMatchedRules puts the rule OBJECT next to the rule id, so the audit
// detail view can show what the rule actually said rather than a bare id.
//
// It is best-effort in the strongest sense: an error returns an empty map and
// the page renders with `matched_rule: null`, exactly as the live route's empty
// catch block does. A rule from a policy version that has since been deleted is
// simply not found, which is why the search covers the last thirty revisions
// rather than only the current one.
func (s *server) resolveMatchedRules(ctx context.Context, projectID string, entries []store.AuditLog) map[string]json.RawMessage {
	need := false
	for _, e := range entries {
		if matchedRuleID(e.MatchedRuleID, e.Reason) != "" {
			need = true
			break
		}
	}
	if !need {
		return nil
	}

	// The rules-only history: this reads policy_data and nothing else, and the
	// full one carries a compiled WASM bundle per version. See PolicyRulesHistory.
	versions, err := s.store.PolicyRulesHistory(ctx, projectID, maxRuleVersions)
	if err != nil {
		return nil
	}
	out := map[string]json.RawMessage{}
	for _, v := range versions {
		policy, ok := policyjson.ParseObject(v.PolicyData)
		if !ok {
			continue
		}
		rules, ok := policyjson.Array(policy.Get("rules"))
		if !ok {
			continue
		}
		for _, item := range rules {
			rule, isObject := item.(*policyjson.Object)
			if !isObject {
				continue
			}
			id := policyjson.Str(rule.Get("id"))
			if id == "" {
				continue
			}
			// First writer wins, and the versions arrive newest first, so the
			// newest definition of a rule id is the one described.
			if _, seen := out[id]; !seen {
				out[id] = json.RawMessage(policyjson.Stringify(rule, nil))
			}
		}
	}
	return out
}

// ── small shared helpers ────────────────────────────────────────────────────

func withLimit(f store.AuditFilter, limit, offset int) store.AuditFilter {
	f.Limit = limit
	f.Offset = offset
	return f
}

func pageOf(rows []store.AuditLog, offset, limit int) []store.AuditLog {
	if offset >= len(rows) {
		return []store.AuditLog{}
	}
	end := offset + limit
	if end > len(rows) {
		end = len(rows)
	}
	return rows[offset:end]
}

// parseInt is `queryInt(s)` for a query parameter, reporting whether it was a
// number at all. The live route lets NaN through in places; here an
// unparseable value takes the default, which is the difference between a
// mistyped URL returning a page and returning nothing.
func queryInt(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func queryIntDefault(s string, def int) int {
	n, ok := queryInt(s)
	if !ok {
		return def
	}
	// Bounded before the conversion, not after: a caller sending 10^18 would
	// otherwise wrap to a negative int on a 32-bit build and become an offset
	// SQLite reads as "from the start".
	const intCeiling = 1 << 31
	if n >= intCeiling {
		return intCeiling - 1
	}
	if n < 0 {
		return 0
	}
	return int(n)
}

func boundInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// firstNumber is the `a ?? b ?? null` chain over two numeric fields. A value
// that is present but not a number is treated as absent rather than stored: the
// column is a REAL and SQLite would happily keep a string in it.
func firstNumber(values ...any) *float64 {
	for _, v := range values {
		if v == nil {
			continue
		}
		if f, ok := jsNumber(v); ok {
			n := f
			return &n
		}
	}
	return nil
}

func asBoolPtr(b bool) *bool { return &b }
