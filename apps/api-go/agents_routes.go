package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/codeyevsky/solongate/api/internal/apiauth"
	"github.com/codeyevsky/solongate/api/internal/store"
)

// /api/v1/agents/live, /api/v1/agents/{id} and /api/v1/agents/{id}/anomalies.
//
// An agent id is a string the CLIENT chose — "claude-code" is one — so it is
// neither unique across the database nor unguessable. Every read here is keyed
// on the PAIR (project, agent id) and the project half always comes from the
// API key. That is not defence in depth, it is the only defence: a caller with
// a valid key who could name an agent id alone would be reading another
// tenant's tool history.

func init() {
	Register("GET /api/v1/agents/live", buildAgentsLive)
	Register("GET /api/v1/agents/{id}", buildAgentDetail)
	Register("GET /api/v1/agents/{id}/anomalies", buildAgentAnomalies)
}

// ── GET /agents/live ────────────────────────────────────────────────────────

// liveAgentCard is one card. It is built from a SESSION rather than from the
// agents table, and that is the point of the endpoint: the agents table is a
// lifetime roll-up, and "live" is a question about the last five minutes.
type liveAgentCard struct {
	SessionID       string  `json:"session_id"`
	AgentID         *string `json:"agent_id"`
	AgentName       *string `json:"agent_name"`
	Status          string  `json:"status"`
	StartedAt       string  `json:"started_at"`
	LastSeenAt      string  `json:"last_seen_at"`
	TotalCalls      int64   `json:"total_calls"`
	AllowedCalls    int64   `json:"allowed_calls"`
	DeniedCalls     int64   `json:"denied_calls"`
	DLPEvents       int64   `json:"dlp_events"`
	RateLimitEvents int64   `json:"rate_limit_events"`
	PiDetections    int64   `json:"pi_detections"`
	ToolMix         toolMix `json:"tool_mix"`
	Character       string  `json:"character"`
	TrustScore      int     `json:"trust_score"`
	RecentAnomalies int64   `json:"recent_anomalies"`
}

type toolMix struct {
	Read    int64 `json:"read"`
	Write   int64 `json:"write"`
	Execute int64 `json:"execute"`
	Network int64 `json:"network"`
}

const (
	defaultLiveAgents = 60
	maxLiveAgents     = 300

	// anomalyLookback is the window the "recent anomalies" badge counts over.
	// A day, as the live route's `Date.now() - 86_400_000`.
	anomalyLookback = 24 * time.Hour
)

func buildAgentsLive(s *server) http.Handler {
	return s.auth.WithAuth(func(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
		ctx := r.Context()
		q := r.URL.Query()

		includeDeactivated := q.Get("include_deactivated") == "1"
		limit := boundInt(queryIntDefault(q.Get("limit"), defaultLiveAgents), 1, maxLiveAgents)

		sessions, err := s.store.ListSessions(ctx, key.ProjectID, 0, "last_seen_at", store.Desc, limit)
		if err != nil {
			apiauth.Internal(w, "api", err)
			return
		}

		since := time.Now().Add(-anomalyLookback).Unix()
		anomalyCounts, err := s.store.AnomalyCountsByAgent(ctx, key.ProjectID, since)
		if err != nil {
			apiauth.Internal(w, "api", err)
			return
		}

		nowMS := time.Now().UnixMilli()
		cards := make([]liveAgentCard, 0, len(sessions))
		counts := map[string]int{"active": 0, "idle": 0, "deactivated": 0}

		for _, sess := range sessions {
			status := livenessOf(sess.LastSeenAt, nowMS)
			counts[status]++

			character, trust := quickCharacter(sess.ReadCalls, sess.WriteCalls, sess.ExecuteCalls,
				sess.NetworkCalls, sess.DeniedCalls, sess.TotalCalls, sess.PiDetections)

			cards = append(cards, liveAgentCard{
				SessionID:       sess.ID,
				AgentID:         nullable(sess.AgentID),
				AgentName:       nullable(sess.AgentName),
				Status:          status,
				StartedAt:       store.ISO(sess.StartedAt),
				LastSeenAt:      store.ISO(sess.LastSeenAt),
				TotalCalls:      sess.TotalCalls,
				AllowedCalls:    sess.AllowedCalls,
				DeniedCalls:     sess.DeniedCalls,
				DLPEvents:       sess.DLPEvents,
				RateLimitEvents: sess.RateLimitEvents,
				PiDetections:    sess.PiDetections,
				ToolMix: toolMix{
					Read: sess.ReadCalls, Write: sess.WriteCalls,
					Execute: sess.ExecuteCalls, Network: sess.NetworkCalls,
				},
				Character:       character,
				TrustScore:      trust,
				RecentAnomalies: anomalyCounts[sess.AgentID],
			})
		}

		// The counts are over EVERY card and the list is the filtered one. That
		// asymmetry is deliberate and is what lets the panel say "3 deactivated"
		// next to a control that reveals them.
		visible := cards
		if !includeDeactivated {
			visible = make([]liveAgentCard, 0, len(cards))
			for _, c := range cards {
				if c.Status != "deactivated" {
					visible = append(visible, c)
				}
			}
		}

		apiauth.JSON(w, http.StatusOK, map[string]any{
			"agents": visible,
			"counts": counts,
		})
	})
}

// ── GET /agents/{id} ────────────────────────────────────────────────────────

const (
	// baselineSample is how far back a baseline is computed from, and
	// recentWindow is what it is compared against. Both are the live route's.
	baselineSample = 1000
	recentWindow   = 60
	recentFeedSize = 25

	maxTrustMapTools     = 40
	maxTrustMapResources = 60
	maxAgentSessions     = 20

	// scanDedupeWindow is how far back a `?scan=1` looks for an anomaly it has
	// already recorded, so repeatedly opening the page does not fill the table
	// with the same finding.
	scanDedupeWindow = 6 * time.Hour
	maxPersistedAnom = 50
)

type trustMapTool struct {
	Name       string `json:"name"`
	Count      int64  `json:"count"`
	Permission string `json:"permission"`
	Anomalous  bool   `json:"anomalous"`
}

type trustMapResource struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Count     int64  `json:"count"`
	Anomalous bool   `json:"anomalous"`
}

type trustMapCentre struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Character  string `json:"character"`
	TrustScore int    `json:"trust_score"`
}

type trustMapSubAgent struct {
	ID   string  `json:"id"`
	Name *string `json:"name"`
}

type trustMap struct {
	Center    trustMapCentre     `json:"center"`
	Tools     []trustMapTool     `json:"tools"`
	Resources []trustMapResource `json:"resources"`
	SubAgents []trustMapSubAgent `json:"sub_agents"`
}

type agentSessionCard struct {
	ID              string `json:"id"`
	Status          string `json:"status"`
	StartedAt       string `json:"started_at"`
	LastSeenAt      string `json:"last_seen_at"`
	TotalCalls      int64  `json:"total_calls"`
	AllowedCalls    int64  `json:"allowed_calls"`
	DeniedCalls     int64  `json:"denied_calls"`
	RateLimitEvents int64  `json:"rate_limit_events"`
}

type agentFeedEntry struct {
	ID            string  `json:"id"`
	Tool          string  `json:"tool"`
	Permission    string  `json:"permission"`
	Decision      string  `json:"decision"`
	Reason        *string `json:"reason"`
	MatchedRuleID *string `json:"matched_rule_id"`
	SessionID     *string `json:"session_id"`
	CreatedAt     string  `json:"created_at"`
}

func buildAgentDetail(s *server) http.Handler {
	return s.auth.WithAuth(func(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
		ctx := r.Context()
		agentID := r.PathValue("id")
		if agentID == "" {
			apiauth.BadRequest(w, "Missing agent id")
			return
		}
		scan := r.URL.Query().Get("scan") == "1"

		rows, err := s.store.ListAuditLogs(ctx, key.ProjectID, store.AuditFilter{
			AgentID: agentID,
			Order:   "created_at",
			Dir:     store.Desc,
			Limit:   baselineSample,
		})
		if err != nil {
			apiauth.Internal(w, "api", err)
			return
		}
		if len(rows) == 0 {
			// An agent with no calls is indistinguishable from an agent that
			// does not exist, and answering differently would tell a caller
			// which agent ids another project uses.
			apiauth.NotFound(w, "Agent not found or has no calls")
			return
		}

		calls := make([]baselineCall, 0, len(rows))
		for _, row := range rows {
			calls = append(calls, callFromAuditRow(row))
		}

		base := computeBaseline(calls)
		recent := calls
		if len(recent) > recentWindow {
			recent = recent[:recentWindow]
		}
		anomalies := detectAnomalies(base, recent)

		tm, err := s.buildTrustMap(ctx, key.ProjectID, agentID, base, anomalies, calls)
		if err != nil {
			apiauth.Internal(w, "api", err)
			return
		}

		sessions, err := s.store.SessionsForAgent(ctx, key.ProjectID, agentID, maxAgentSessions)
		if err != nil {
			apiauth.Internal(w, "api", err)
			return
		}
		nowMS := time.Now().UnixMilli()
		sessionCards := make([]agentSessionCard, 0, len(sessions))
		overall := "deactivated"
		sawIdle := false
		for _, sess := range sessions {
			status := livenessOf(sess.LastSeenAt, nowMS)
			if status == "active" && overall != "active" {
				overall = "active"
			}
			if status == "idle" {
				sawIdle = true
			}
			sessionCards = append(sessionCards, agentSessionCard{
				ID:              sess.ID,
				Status:          status,
				StartedAt:       store.ISO(sess.StartedAt),
				LastSeenAt:      store.ISO(sess.LastSeenAt),
				TotalCalls:      sess.TotalCalls,
				AllowedCalls:    sess.AllowedCalls,
				DeniedCalls:     sess.DeniedCalls,
				RateLimitEvents: sess.RateLimitEvents,
			})
		}
		if overall != "active" && sawIdle {
			overall = "idle"
		}

		feedRows := rows
		if len(feedRows) > recentFeedSize {
			feedRows = feedRows[:recentFeedSize]
		}
		feed := make([]agentFeedEntry, 0, len(feedRows))
		for _, row := range feedRows {
			feed = append(feed, agentFeedEntry{
				ID:            row.ID,
				Tool:          row.ToolName,
				Permission:    row.Permission,
				Decision:      row.Decision,
				Reason:        nullable(row.Reason),
				MatchedRuleID: nullable(row.MatchedRuleID),
				SessionID:     nullable(row.SessionID),
				CreatedAt:     store.ISO(row.CreatedAt),
			})
		}

		if scan {
			// Persisting is best-effort and deliberately does not fail the
			// request: the page is a read, and a caller who asked it to also
			// remember what it saw still wants to see it.
			s.persistScan(ctx, key.ProjectID, agentID, base, anomalies)
		}

		apiauth.JSON(w, http.StatusOK, map[string]any{
			"agent_id":    agentID,
			"status":      overall,
			"baseline":    base,
			"anomalies":   anomalies,
			"trust_map":   tm,
			"sessions":    sessionCards,
			"recent_feed": feed,
		})
	})
}

// callFromAuditRow reduces a stored row to the shape the baseline reads.
//
// The arguments are parsed here and nowhere else, and a failure is a nil map
// rather than an error: arguments_summary is truncated on write, so a fragment
// in that column is an expected state and not a reason to fail the page.
func callFromAuditRow(row store.AuditLog) baselineCall {
	var args map[string]any
	if row.ArgumentsSummary != "" {
		if json.Unmarshal([]byte(row.ArgumentsSummary), &args) != nil {
			args = nil
		}
	}
	permission := row.Permission
	if permission == "" {
		permission = "EXECUTE"
	}
	return baselineCall{
		id:         row.ID,
		sessionID:  row.SessionID,
		tool:       row.ToolName,
		permission: permission,
		decision:   row.Decision,
		args:       args,
		piDetected: row.PiDetected != nil && *row.PiDetected,
		// The baseline works in milliseconds because the live app reads a
		// JavaScript Date; the column is seconds.
		createdAt: row.CreatedAt * 1000,
	}
}

// buildTrustMap is the graph the agent page draws: the tools this agent uses,
// the places it reaches, and the sub-agents it delegates to, with the ones the
// anomaly pass flagged marked.
func (s *server) buildTrustMap(ctx context.Context, projectID, agentID string,
	base agentBaseline, anomalies []anomaly, calls []baselineCall) (trustMap, error) {

	// Flagged VALUES rather than flagged anomalies: the map marks a tool or a
	// path, and an anomaly names one of the three in its detail.
	flagged := map[string]bool{}
	for _, a := range anomalies {
		for _, k := range []string{"path", "domain", "tool"} {
			if v, ok := a.Detail[k]; ok {
				flagged[jsString(v)] = true
				break
			}
		}
	}

	type toolStat struct {
		count      int64
		permission string
	}
	toolOrder := []string{}
	toolStats := map[string]*toolStat{}
	pathOrder, pathCounts := []string{}, map[string]int64{}
	domainOrder, domainCounts := []string{}, map[string]int64{}

	for _, c := range calls {
		st, seen := toolStats[c.tool]
		if !seen {
			st = &toolStat{permission: c.permission}
			toolStats[c.tool] = st
			toolOrder = append(toolOrder, c.tool)
		}
		st.count++

		for _, p := range collectArgs(c.args, pathArgKeys) {
			d := dirOf(p)
			if _, seen := pathCounts[d]; !seen {
				pathOrder = append(pathOrder, d)
			}
			pathCounts[d]++
		}
		for _, u := range collectArgs(c.args, urlArgKeys) {
			if h := hostOf(u); h != "" {
				if _, seen := domainCounts[h]; !seen {
					domainOrder = append(domainOrder, h)
				}
				domainCounts[h]++
			}
		}
	}

	tools := make([]trustMapTool, 0, len(toolOrder))
	for _, name := range toolOrder {
		tools = append(tools, trustMapTool{
			Name: name, Count: toolStats[name].count,
			Permission: toolStats[name].permission, Anomalous: flagged[name],
		})
	}
	// A STABLE sort, because the live app's Array.prototype.sort is stable and
	// first-seen order is what breaks ties there. An unstable sort would shuffle
	// equally-used tools between two loads of the same page.
	sort.SliceStable(tools, func(i, j int) bool { return tools[i].Count > tools[j].Count })
	if len(tools) > maxTrustMapTools {
		tools = tools[:maxTrustMapTools]
	}

	resources := make([]trustMapResource, 0, len(pathOrder)+len(domainOrder))
	for _, p := range pathOrder {
		resources = append(resources, trustMapResource{
			Type: "path", Value: p, Count: pathCounts[p], Anomalous: flagged[p],
		})
	}
	for _, d := range domainOrder {
		resources = append(resources, trustMapResource{
			Type: "domain", Value: d, Count: domainCounts[d], Anomalous: flagged[d],
		})
	}
	sort.SliceStable(resources, func(i, j int) bool { return resources[i].Count > resources[j].Count })
	if len(resources) > maxTrustMapResources {
		resources = resources[:maxTrustMapResources]
	}

	subAgentRows, err := s.store.SubAgents(ctx, projectID, agentID)
	if err != nil {
		return trustMap{}, err
	}
	subAgents := make([]trustMapSubAgent, 0, len(subAgentRows))
	for _, sub := range subAgentRows {
		subAgents = append(subAgents, trustMapSubAgent{ID: sub.AgentID, Name: nullable(sub.AgentName)})
	}

	return trustMap{
		Center: trustMapCentre{
			ID: agentID, Name: agentID,
			Character: base.Character, TrustScore: base.TrustScore,
		},
		Tools:     tools,
		Resources: resources,
		SubAgents: subAgents,
	}, nil
}

// persistScan stores the baseline and the anomalies that are new.
//
// The dedupe is on (kind, description) within the last six hours, which is what
// stops a page refresh from writing the same finding again. It is not a unique
// constraint and cannot be: two genuinely separate first-uses of the same tool
// six hours apart are two anomalies, and the description is the only thing that
// distinguishes one finding from another.
func (s *server) persistScan(ctx context.Context, projectID, agentID string,
	base agentBaseline, anomalies []anomaly) {

	if err := s.store.EnsureRuntimeTables(ctx); err != nil {
		log.Printf("[API:agents] scan persist skipped, runtime tables not ready: %v", err)
		return
	}

	toolDist, _ := marshalNoEscape(base.ToolDistribution)
	permMix, _ := marshalNoEscape(base.PermissionMix)
	knownPaths, _ := marshalNoEscape(base.KnownPaths)
	knownDomains, _ := marshalNoEscape(base.KnownDomains)
	knownTools, _ := marshalNoEscape(base.KnownTools)

	if err := s.store.UpsertBaseline(ctx, store.AgentBaseline{
		ID:               uuid.NewString(),
		ProjectID:        projectID,
		AgentID:          agentID,
		ToolDistribution: toolDist,
		PermissionMix:    permMix,
		KnownPaths:       knownPaths,
		KnownDomains:     knownDomains,
		KnownTools:       knownTools,
		AvgCallsPerHour:  base.AvgCallsPerHour,
		DenyRate:         base.DenyRate,
		SampleSize:       int64(base.SampleSize),
		Character:        base.Character,
		TrustScore:       float64(base.TrustScore),
		ComputedAt:       store.Now(),
	}); err != nil {
		log.Printf("[API:agents] baseline persist failed: %v", err)
	}

	since := time.Now().Add(-scanDedupeWindow).Unix()
	existing, err := s.store.ListAnomalies(ctx, projectID, agentID, since, maxPersistedAnom*2)
	if err != nil {
		log.Printf("[API:agents] anomaly dedupe read failed: %v", err)
		return
	}
	seen := map[string]bool{}
	for _, a := range existing {
		seen[a.Kind+"|"+a.Description] = true
	}

	for i, a := range anomalies {
		if i >= maxPersistedAnom {
			break
		}
		fingerprint := a.Kind + "|" + a.Description
		if seen[fingerprint] {
			continue
		}
		detail, err := marshalNoEscape(a.Detail)
		if err != nil {
			continue
		}
		if err := s.store.InsertAnomaly(ctx, store.AnomalyEvent{
			ID:          uuid.NewString(),
			ProjectID:   projectID,
			AgentID:     agentID,
			SessionID:   a.SessionID,
			AuditLogID:  a.AuditLogID,
			Kind:        a.Kind,
			Severity:    a.Severity,
			Score:       a.Score,
			Description: a.Description,
			Detail:      detail,
			CreatedAt:   store.Now(),
		}); err != nil {
			log.Printf("[API:agents] anomaly persist failed: %v", err)
			continue
		}
		seen[fingerprint] = true
	}
}

// ── GET /agents/{id}/anomalies ──────────────────────────────────────────────

type anomalyRecord struct {
	ID          string          `json:"id"`
	Kind        string          `json:"kind"`
	Severity    string          `json:"severity"`
	Score       float64         `json:"score"`
	Description *string         `json:"description"`
	Detail      json.RawMessage `json:"detail"`
	SessionID   *string         `json:"session_id"`
	AuditLogID  *string         `json:"audit_log_id"`
	CreatedAt   string          `json:"created_at"`
}

const (
	defaultAnomalyLimit = 100
	maxAnomalyLimit     = 500
)

func buildAgentAnomalies(s *server) http.Handler {
	return s.auth.WithAuth(func(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
		agentID := r.PathValue("id")
		if agentID == "" {
			apiauth.BadRequest(w, "Missing agent id")
			return
		}
		limit := boundInt(queryIntDefault(r.URL.Query().Get("limit"), defaultAnomalyLimit), 1, maxAnomalyLimit)

		rows, err := s.store.ListAnomalies(r.Context(), key.ProjectID, agentID, 0, limit)
		if err != nil {
			apiauth.Internal(w, "api", err)
			return
		}

		out := make([]anomalyRecord, 0, len(rows))
		for _, a := range rows {
			out = append(out, anomalyRecord{
				ID:          a.ID,
				Kind:        a.Kind,
				Severity:    a.Severity,
				Score:       a.Score,
				Description: nullable(a.Description),
				Detail:      a.Detail,
				SessionID:   nullable(a.SessionID),
				AuditLogID:  nullable(a.AuditLogID),
				CreatedAt:   store.ISO(a.CreatedAt),
			})
		}
		apiauth.JSON(w, http.StatusOK, map[string]any{"anomalies": out})
	})
}
