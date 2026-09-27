package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/store"
)

// /api/v1/sessions and /api/v1/sessions/{id} — the port of
// src/app/api/v1/sessions/route.ts and sessions/[id]/route.ts.
//
// `solongate sessions` reads the list; the dashboard's session view reads both.
//
// A session id is a string the CLIENT chose. It is the primary key of the
// table, so it is unique across the whole database rather than per project, and
// two tenants can pick the same one. Every read and every delete below therefore
// carries the project id from the API key — including the ones that already have
// an id to match on, because an id alone would let a caller with any valid key
// read another project's calls by naming a session they guessed or reused.
//
// The counters in the response are NOT the columns of the same name. Both
// endpoints recount from audit_logs, and the reason is that dlp_events and
// rate_limit_events cannot be columns at all: a DLP hit is evidence left in a
// stored argument summary, and a rate-limit burst is a property of the MINUTE a
// call landed in rather than of the call. See audit_signals.go, which holds the
// scanner this file borrows.

func init() {
	Register("GET /api/v1/sessions", func(s *server) http.Handler {
		return s.auth.WithAuth(s.listSessions)
	})
	Register("DELETE /api/v1/sessions", func(s *server) http.Handler {
		return s.auth.WithAuth(s.deleteSessions)
	})
	Register("GET /api/v1/sessions/{id}", func(s *server) http.Handler {
		return s.auth.WithAuth(s.getSession)
	})
}

const (
	// The live route's `Math.min(parseInt(limit ?? '50'), 500)`.
	defaultSessionPage = 50
	maxSessionPage     = 500

	// sessionCallsLimit is the ceiling on the audit rows the list route reads to
	// recount a page. It is the live route's 30000.
	sessionCallsLimit = 30000

	// sessionEventLimit is the detail route's, and it is what bounds the whole
	// endpoint: one session's calls, oldest first.
	sessionEventLimit = 5000

	// previewMax is where a call's preview line is cut, with an ellipsis.
	previewMax = 120
)

// ── GET /api/v1/sessions ────────────────────────────────────────────────────

// sessionCard is one row of the list. The field order is the live route's map,
// and `pi_detections` is deliberately absent from it — the column exists and
// this endpoint has never returned it.
type sessionCard struct {
	ID              string  `json:"id"`
	AgentID         *string `json:"agent_id"`
	AgentName       *string `json:"agent_name"`
	APIKeyID        *string `json:"api_key_id"`
	StartedAt       string  `json:"started_at"`
	LastSeenAt      string  `json:"last_seen_at"`
	DurationMs      int64   `json:"duration_ms"`
	Status          string  `json:"status"`
	TotalCalls      int64   `json:"total_calls"`
	AllowedCalls    int64   `json:"allowed_calls"`
	DeniedCalls     int64   `json:"denied_calls"`
	DLPEvents       int64   `json:"dlp_events"`
	RateLimitEvents int64   `json:"rate_limit_events"`
	ReadCalls       int64   `json:"read_calls"`
	WriteCalls      int64   `json:"write_calls"`
	ExecuteCalls    int64   `json:"execute_calls"`
	NetworkCalls    int64   `json:"network_calls"`
}

func (s *server) listSessions(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	ctx := r.Context()
	// `sessions` is one of the tables src/db/index.ts creates at runtime, so a
	// process that came up before the database did has to be able to catch up.
	// The call is a mutex read once it has succeeded.
	if err := s.store.EnsureRuntimeTables(ctx); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	q := r.URL.Query()
	statusFilter := q.Get("status")
	agentID := q.Get("agent_id")
	limit := boundInt(queryIntDefault(q.Get("limit"), defaultSessionPage), 1, maxSessionPage)
	offset := queryIntDefault(q.Get("offset"), 0)

	rows, err := s.store.ListSessionsPage(ctx, key.ProjectID, agentID, limit, offset)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	total, err := s.store.CountSessionsPage(ctx, key.ProjectID, agentID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	nowMS := time.Now().UnixMilli()
	cards := make([]sessionCard, 0, len(rows))
	for _, sess := range rows {
		// The stored counters are the starting point and are overwritten below
		// for every session that has audit rows. A session whose calls have been
		// deleted keeps them, which is the live behaviour.
		cards = append(cards, sessionCard{
			ID:         sess.ID,
			AgentID:    nullable(sess.AgentID),
			AgentName:  nullable(sess.AgentName),
			APIKeyID:   nullable(sess.APIKeyID),
			StartedAt:  store.ISO(sess.StartedAt),
			LastSeenAt: store.ISO(sess.LastSeenAt),
			// Both columns are seconds; the field is milliseconds because the
			// live route subtracts two Dates. MAX(0, …) because a session
			// created by a client with a skewed clock can be seen before it
			// started.
			DurationMs:      max64(0, (sess.LastSeenAt-sess.StartedAt)*1000),
			Status:          livenessOf(sess.LastSeenAt, nowMS),
			TotalCalls:      sess.TotalCalls,
			AllowedCalls:    sess.AllowedCalls,
			DeniedCalls:     sess.DeniedCalls,
			DLPEvents:       sess.DLPEvents,
			RateLimitEvents: sess.RateLimitEvents,
			ReadCalls:       sess.ReadCalls,
			WriteCalls:      sess.WriteCalls,
			ExecuteCalls:    sess.ExecuteCalls,
			NetworkCalls:    sess.NetworkCalls,
		})
	}

	// The filter runs over the PAGE, after the limit and the offset, and `total`
	// stays the unfiltered count. That is the live behaviour and it is visible —
	// asking for the active sessions returns fewer rows than `limit` — but a
	// pager built against it is already counting that way.
	if statusFilter == "active" || statusFilter == "idle" || statusFilter == "deactivated" {
		kept := make([]sessionCard, 0, len(cards))
		for _, c := range cards {
			if c.Status == statusFilter {
				kept = append(kept, c)
			}
		}
		cards = kept
	}

	if err := s.recountSessions(ctx, key.ProjectID, cards); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	apiauth.JSON(w, http.StatusOK, map[string]any{
		"sessions": cards,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
	})
}

// recountSessions replaces the stored counters on a page with what the audit
// rows say, in place.
//
// It is one query for the whole page rather than one per session, and it is
// bounded: past sessionCallsLimit rows the tallies are a lower bound, which is
// the live route's cap too.
func (s *server) recountSessions(ctx context.Context, projectID string, cards []sessionCard) error {
	ids := make([]string, 0, len(cards))
	for _, c := range cards {
		if c.ID != "" {
			ids = append(ids, c.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}

	layers := s.store.GetSecurityLayers(ctx, projectID)
	history := s.store.RateLimitHistory(ctx, projectID)
	calls, err := s.store.SessionCalls(ctx, projectID, ids, sessionCallsLimit)
	if err != nil {
		return err
	}

	scanner := newDLPScanner(layers)
	perMinute := effectivePerMinute(layers, history)

	bySession := map[string][]store.SessionCall{}
	for _, c := range calls {
		if c.SessionID == "" {
			continue
		}
		bySession[c.SessionID] = append(bySession[c.SessionID], c)
	}

	tallies := make(map[string]sessionTally, len(bySession))
	for id, rows := range bySession {
		tallies[id] = tallySessionCalls(rows, scanner, perMinute)
	}

	for i := range cards {
		t, ok := tallies[cards[i].ID]
		if !ok {
			continue
		}
		cards[i].TotalCalls = t.total
		cards[i].AllowedCalls = t.allowed
		cards[i].DeniedCalls = t.denied
		cards[i].DLPEvents = t.dlp
		cards[i].RateLimitEvents = t.rateLimit
	}
	return nil
}

type sessionTally struct {
	total     int64
	allowed   int64
	denied    int64
	dlp       int64
	rateLimit int64
}

// tallySessionCalls is the per-session count the list shows.
//
// A call is counted as ONE of dlp or rate-limit, never both, and dlp wins —
// the live route's `if (hasDlp) … else if (rateBurst) …`. The denial counters
// are independent of that, so a denied call carrying a secret raises both
// denied_calls and dlp_events.
func tallySessionCalls(rows []store.SessionCall, scanner *dlpScanner, perMinute int64) sessionTally {
	burst := burstMinutes(rows, perMinute)

	var t sessionTally
	for _, row := range rows {
		t.total++
		decision := upperDecision(row.Decision)
		if decision == "ALLOW" {
			t.allowed++
		} else {
			t.denied++
		}
		isDeny := decision == "DENY" || decision == "DENIED"
		rateBurst := burst[row.CreatedAt/60] || (isDeny && rateLimitReason.MatchString(row.Reason))

		switch {
		case len(scanner.scan(row.ArgumentsSummary)) > 0:
			t.dlp++
		case rateBurst:
			t.rateLimit++
		}
	}
	return t
}

// burstMinutes marks the minutes in which these rows exceeded the limit.
//
// The bucket is floor(seconds / 60), which is the same bucket the live route's
// floor(milliseconds / 60000) produces. The limit is the CURRENT one — this is
// where the sessions endpoints differ from the audit list, which walks the
// recorded history so that old traffic is not re-judged against a new number.
// Reproducing the difference matters more than reconciling it: the two views
// would otherwise disagree about a session in a way that reads as a bug in
// whichever one somebody opened second.
func burstMinutes(rows []store.SessionCall, perMinute int64) map[int64]bool {
	out := map[int64]bool{}
	if perMinute <= 0 {
		return out
	}
	counts := map[int64]int64{}
	for _, row := range rows {
		counts[row.CreatedAt/60]++
	}
	for minute, n := range counts {
		if n > perMinute {
			out[minute] = true
		}
	}
	return out
}

// effectivePerMinute is the live routes' `layers.rateLimit.mode === 'off' &&
// history.length === 0 ? 0 : layers.rateLimit.perMinute`.
//
// The history clause is what keeps a project that has since turned rate limiting
// off from losing the bursts it already recorded: a zero here means no call can
// be a burst at all.
func effectivePerMinute(layers store.SecurityLayers, history []store.RateLimitChange) int64 {
	if layers.RateLimit.Mode == store.LayerOff && len(history) == 0 {
		return 0
	}
	return layers.RateLimit.PerMinute
}

// upperDecision is `String(decision || 'ALLOW').toUpperCase()`. An empty column
// reads as ALLOW, which is the live default and not a guess: the audit writer
// has always sent one, so a missing value is an old row rather than a denial.
func upperDecision(decision string) string {
	if decision == "" {
		return "ALLOW"
	}
	return strings.ToUpper(decision)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// ── DELETE /api/v1/sessions ─────────────────────────────────────────────────

// deleteSessions clears sessions by explicit id, or every deactivated one.
//
// It never deletes a project's whole list: with no ids and no recognised scope
// the answer is `{"deleted":0}`, which is the live behaviour and is what stops a
// bodyless DELETE from wiping the view.
func (s *server) deleteSessions(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	ctx := r.Context()
	if err := s.store.EnsureRuntimeTables(ctx); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	// `await request.json().catch(() => ({}))`: an unparseable or absent body is
	// an empty object rather than a 400.
	body := map[string]json.RawMessage{}
	_ = json.NewDecoder(r.Body).Decode(&body)

	ids := jsonStringList(body["ids"])
	scope := ""
	if v, ok := jsTruthyString(body["scope"]); ok {
		scope = v
	}

	var deleted int64
	switch {
	case len(ids) > 0:
		n, err := s.deleteSessionIDs(ctx, key.ProjectID, ids)
		if err != nil {
			apiauth.Internal(w, "api", err)
			return
		}
		deleted = n

	case scope == "deactivated":
		stamps, err := s.store.SessionStamps(ctx, key.ProjectID, 0)
		if err != nil {
			apiauth.Internal(w, "api", err)
			return
		}
		nowMS := time.Now().UnixMilli()
		dead := make([]string, 0, len(stamps))
		for _, st := range stamps {
			if livenessOf(st.LastSeenAt, nowMS) == "deactivated" {
				dead = append(dead, st.ID)
			}
		}
		n, err := s.deleteSessionIDs(ctx, key.ProjectID, dead)
		if err != nil {
			apiauth.Internal(w, "api", err)
			return
		}
		deleted = n
	}

	apiauth.JSON(w, http.StatusOK, map[string]any{"deleted": deleted})
}

// deleteSessionIDs deletes in chunks, because SQLite has a ceiling on bound
// parameters and an id list is caller input with no length limit of its own.
// The project id is in every statement; see the file note.
func (s *server) deleteSessionIDs(ctx context.Context, projectID string, ids []string) (int64, error) {
	var deleted int64
	for start := 0; start < len(ids); start += store.MaxDeleteChunk {
		end := min(start+store.MaxDeleteChunk, len(ids))
		n, err := s.store.DeleteSessionsByIDs(ctx, projectID, ids[start:end])
		if err != nil {
			return deleted, err
		}
		deleted += n
	}
	return deleted, nil
}

// jsonStringList is `Array.isArray(x) ? x.filter(v => typeof v === 'string') :
// undefined`. A value that is not an array is nil, which the caller treats as
// absent — and a non-string element is dropped rather than stringified, so a
// caller sending `{"ids":[1,2]}` deletes nothing instead of deleting the rows
// whose ids happen to read as "1".
func jsonStringList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var items []any
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil
	}
	out := []string{}
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ── GET /api/v1/sessions/{id} ───────────────────────────────────────────────

// sessionEvent is one call in the session timeline.
type sessionEvent struct {
	ID               string          `json:"id"`
	ToolName         string          `json:"tool_name"`
	ServerName       *string         `json:"server_name"`
	Permission       string          `json:"permission"`
	TrustLevel       string          `json:"trust_level"`
	Decision         string          `json:"decision"`
	DenyLayer        *string         `json:"deny_layer"`
	EventType        string          `json:"event_type"`
	MatchedRuleID    *string         `json:"matched_rule_id"`
	Reason           *string         `json:"reason"`
	EvaluationTimeMs *float64        `json:"evaluation_time_ms"`
	Preview          string          `json:"preview"`
	ArgumentsSummary json.RawMessage `json:"arguments_summary"`
	DLPMatches       []string        `json:"dlp_matches"`
	RateLimitBurst   bool            `json:"rate_limit_burst"`
	PiDetected       bool            `json:"pi_detected"`
	PiCategories     json.RawMessage `json:"pi_categories"`
	AgentID          *string         `json:"agent_id"`
	AgentName        *string         `json:"agent_name"`
	SubAgentName     *string         `json:"sub_agent_name"`
	Phase            string          `json:"phase"`
	PhaseStart       bool            `json:"phase_start"`
	CreatedAt        string          `json:"created_at"`
}

// sessionDetail is the header above that timeline. Its counters come from the
// events, not from the sessions row, so the two halves of the response cannot
// disagree with each other.
type sessionDetail struct {
	ID                 string  `json:"id"`
	AgentID            *string `json:"agent_id"`
	AgentName          *string `json:"agent_name"`
	StartedAt          string  `json:"started_at"`
	LastSeenAt         string  `json:"last_seen_at"`
	Status             string  `json:"status"`
	TotalCalls         int     `json:"total_calls"`
	AllowedCalls       int     `json:"allowed_calls"`
	DeniedCalls        int     `json:"denied_calls"`
	DLPEvents          int     `json:"dlp_events"`
	RateLimitEvents    int     `json:"rate_limit_events"`
	RateLimitPerMinute int64   `json:"rate_limit_per_minute"`
}

func (s *server) getSession(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	ctx := r.Context()
	if err := s.store.EnsureRuntimeTables(ctx); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	sessionID := r.PathValue("id")
	if sessionID == "" {
		apiauth.BadRequest(w, "Missing session id")
		return
	}

	// Project-scoped, oldest first, bounded. The project half is what makes a
	// guessed session id useless; see the file note.
	rows, err := s.store.ListAuditLogs(ctx, key.ProjectID, store.AuditFilter{
		SessionID: sessionID,
		Order:     "created_at",
		Dir:       store.Asc,
		Limit:     sessionEventLimit,
	})
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	if len(rows) == 0 {
		// A session with no calls and a session belonging to somebody else are
		// the same answer, which is the point: the alternative tells a caller
		// which session ids another project uses.
		apiauth.NotFound(w, "Session not found or has no calls")
		return
	}

	layers := s.store.GetSecurityLayers(ctx, key.ProjectID)
	history := s.store.RateLimitHistory(ctx, key.ProjectID)
	scanner := newDLPScanner(layers)
	perMinute := effectivePerMinute(layers, history)

	burst := map[int64]bool{}
	if perMinute > 0 {
		counts := map[int64]int64{}
		for _, row := range rows {
			counts[row.CreatedAt/60]++
		}
		for minute, n := range counts {
			if n > perMinute {
				burst[minute] = true
			}
		}
	}

	events := make([]sessionEvent, 0, len(rows))
	lastPhase := ""
	var allowed, denied, dlpEvents, rateLimitEvents int

	for _, row := range rows {
		decision := upperDecision(row.Decision)
		isDeny := decision == "DENY" || decision == "DENIED"

		// The detail view's DLP evidence is a re-scan first and the redactor's
		// marker second. It deliberately does NOT fall back to the denial reason
		// the audit list uses — that third source is not in this route, and
		// adding it would put a badge here that the list does not show.
		matches := scanner.scan(row.ArgumentsSummary)
		if len(matches) == 0 {
			matches = dlpFromRedaction(row.ArgumentsSummary)
		}
		if matches == nil {
			matches = []string{}
		}

		rateBurst := burst[row.CreatedAt/60] || (isDeny && rateLimitReason.MatchString(row.Reason))

		eventType := "allow"
		switch {
		case len(matches) > 0:
			eventType = "dlp"
		case rateBurst:
			eventType = "ratelimit"
		case isDeny:
			eventType = "deny"
		}

		var denyLayer *string
		if isDeny {
			denyLayer = nullable(classifyDenyLayer(row.Reason))
		}

		phase := phaseOf(row.Permission)
		phaseStart := phase != lastPhase
		lastPhase = phase

		if decision == "ALLOW" {
			allowed++
		} else {
			denied++
		}
		switch eventType {
		case "dlp":
			dlpEvents++
		case "ratelimit":
			rateLimitEvents++
		}

		events = append(events, sessionEvent{
			ID:               row.ID,
			ToolName:         row.ToolName,
			ServerName:       nullable(row.ServerName),
			Permission:       row.Permission,
			TrustLevel:       row.TrustLevel,
			Decision:         decision,
			DenyLayer:        denyLayer,
			EventType:        eventType,
			MatchedRuleID:    nullable(row.MatchedRuleID),
			Reason:           nullable(row.Reason),
			EvaluationTimeMs: row.EvaluationTimeMs,
			Preview:          callPreview(row.ArgumentsSummary, row.ToolName),
			ArgumentsSummary: rawOrNull(row.ArgumentsSummary),
			DLPMatches:       matches,
			RateLimitBurst:   rateBurst,
			// `entry.piDetected === true`: a NULL column means the scanner never
			// ran, and this field reports it as false rather than as null,
			// because that is what the live route's strict comparison produces.
			PiDetected:   row.PiDetected != nil && *row.PiDetected,
			PiCategories: rawOrNull(row.PiCategories),
			AgentID:      nullable(row.AgentID),
			AgentName:    nullable(row.AgentName),
			SubAgentName: nullable(row.SubAgentName),
			Phase:        phase,
			PhaseStart:   phaseStart,
			CreatedAt:    store.ISO(row.CreatedAt),
		})
	}

	// The sessions row is the preferred source for the header, and the first and
	// last audit rows are the fallback — for a session that was never upserted,
	// or whose row carries no agent. `??` falls through on null as well as on a
	// missing row, which is why an empty column falls back here too.
	first, last := rows[0], rows[len(rows)-1]
	meta := sessionDetail{
		ID:                 sessionID,
		AgentID:            nullable(first.AgentID),
		AgentName:          nullable(first.AgentName),
		StartedAt:          store.ISO(first.CreatedAt),
		LastSeenAt:         store.ISO(last.CreatedAt),
		Status:             livenessOf(last.CreatedAt, time.Now().UnixMilli()),
		TotalCalls:         len(events),
		AllowedCalls:       allowed,
		DeniedCalls:        denied,
		DLPEvents:          dlpEvents,
		RateLimitEvents:    rateLimitEvents,
		RateLimitPerMinute: perMinute,
	}

	sess, err := s.store.SessionByID(ctx, key.ProjectID, sessionID)
	switch {
	case err == nil:
		if sess.AgentID != "" {
			meta.AgentID = nullable(sess.AgentID)
		}
		if sess.AgentName != "" {
			meta.AgentName = nullable(sess.AgentName)
		}
		meta.StartedAt = store.ISO(sess.StartedAt)
		meta.LastSeenAt = store.ISO(sess.LastSeenAt)
		meta.Status = livenessOf(sess.LastSeenAt, time.Now().UnixMilli())
	case errors.Is(err, store.ErrNotFound):
		// The audit rows are the whole record; the header stays as built above.
	default:
		apiauth.Internal(w, "api", err)
		return
	}

	apiauth.JSON(w, http.StatusOK, map[string]any{"session": meta, "events": events})
}

// phaseOf labels a call by what it did, so the timeline can group consecutive
// calls of one kind. The four names are the dashboard's headings.
func phaseOf(permission string) string {
	switch strings.ToUpper(permission) {
	case "READ":
		return "Exploration"
	case "WRITE":
		return "Modification"
	case "EXECUTE":
		return "Execution"
	case "NETWORK":
		return "Network"
	default:
		return "Other"
	}
}

// previewKeys are the argument names worth showing, in the live route's order.
// The order is the whole design: a Bash call's `command` says more than its
// `timeout`, so the first key that carries a string wins.
var previewKeys = []string{
	"command", "cmd", "script", "file_path", "path", "notebook_path",
	"url", "pattern", "query",
}

// callPreview is one line describing a call, falling back to the tool name.
//
// The summary is truncated on write, so a fragment that will not parse is an
// expected state of that column and is answered with the tool name rather than
// an error.
func callPreview(summary, tool string) string {
	if summary == "" {
		return tool
	}
	var parsed any
	if err := json.Unmarshal([]byte(summary), &parsed); err != nil {
		return tool
	}
	args, isObj := parsed.(map[string]any)
	if !isObj {
		return tool
	}
	for _, k := range previewKeys {
		v, isStr := args[k].(string)
		if !isStr {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		line, _, _ := strings.Cut(v, "\n")
		if len([]rune(line)) > previewMax {
			// store.Clip cuts on a rune boundary; the live route's slice() counts
			// UTF-16 code units and would split a surrogate pair here.
			return store.Clip(line, previewMax) + "…"
		}
		return line
	}
	return tool
}
