// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Audit struct{ c *Client }

// MaxAuditPage is the largest page Audit.List returns; a larger Limit is clamped
// to it. Callers that need every row (export, bulk delete) must walk the pages
// instead of asking for one oversized page and assuming they got everything.
const MaxAuditPage = 1000

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

// Matches reports whether one entry falls inside the query's filter set. Limit,
// Offset and the paging window are deliberately ignored: they scope the page a
// caller shows, not the set a filter selects, so callers that act on "everything
// currently shown" (delete, export) can reuse this predicate on the raw log
// instead of re-implementing the filter and drifting away from the view.
func (q AuditQuery) Matches(e AuditEntry) bool {
	decision := q.Filter
	if decision == "DENIED" {
		decision = "DENY"
	}
	lower := strings.ToLower
	if decision != "" && e.Decision != decision {
		return false
	}
	if q.Tool != "" && !strings.Contains(lower(e.ToolName), lower(q.Tool)) {
		return false
	}
	if q.AgentName != "" {
		name := ""
		if e.AgentName != nil {
			name = *e.AgentName
		}
		if !strings.Contains(lower(name), lower(q.AgentName)) {
			return false
		}
	}
	if q.SessionID != "" && (e.SessionID == nil || *e.SessionID != q.SessionID) {
		return false
	}
	reason := ""
	if e.Reason != nil {
		reason = *e.Reason
	}
	if q.Signal == "dlp" && len(e.DLPMatches) == 0 && !strings.Contains(lower(reason), "dlp") {
		return false
	}
	if q.Signal == "ratelimit" && !e.RateLimitBurst && !strings.Contains(lower(reason), "rate limit") {
		return false
	}
	if q.Search != "" {
		needle := lower(q.Search)
		if !strings.Contains(lower(e.ToolName), needle) &&
			!strings.Contains(lower(reason), needle) &&
			!strings.Contains(lower(string(e.ArgumentsSummary)), needle) {
			return false
		}
	}
	if q.From > 0 || q.To > 0 {
		at := int64(0)
		if t, err := time.Parse(time.RFC3339Nano, e.CreatedAt); err == nil {
			at = t.UnixMilli()
		}
		if at <= 0 {
			return false
		}
		if q.From > 0 && at < q.From {
			return false
		}
		if q.To > 0 && at > q.To {
			return false
		}
	}
	return true
}

func (a Audit) List(ctx context.Context, q AuditQuery) (AuditList, error) {
	limit := q.Limit
	if limit < 1 {
		limit = 50
	}
	if limit > MaxAuditPage {
		limit = MaxAuditPage
	}
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}

	rows := []AuditEntry{}
	for _, l := range readLog() {
		e := toAuditEntry(l)
		if !q.Matches(e) {
			continue
		}
		rows = append(rows, e)
	}

	st, _ := readStore()
	out := AuditList{
		Entries:            []AuditEntry{},
		Total:              len(rows),
		Limit:              limit,
		Offset:             offset,
		RateLimitPerMinute: toLayers(st.Security).RateLimit.PerMinute,
	}
	if offset < len(rows) {
		end := offset + limit
		if end > len(rows) {
			end = len(rows)
		}
		out.Entries = rows[offset:end]
	}
	return out, nil
}

func ruleFromEntry(ctx context.Context, p Policies, id, scope, effect string) (RuleMutation, error) {
	if scope == "" {
		scope = "exact"
	}
	var found *logLine
	for _, l := range readLog() {
		if l.id == id {
			copy := l
			found = &copy
			break
		}
	}
	if found == nil {
		return RuleMutation{}, fmt.Errorf("no entry %s in this machine's audit log. `solongate audit` lists them.", id)
	}
	spec, err := RuleSpecFor(found.Tool, found.Arguments, scope, effect)
	if err != nil {
		return RuleMutation{}, fmt.Errorf("entry %s: %w", id, err)
	}
	return p.AddRule(ctx, "local", spec)
}

func RuleSpecFor(tool string, arguments json.RawMessage, scope, effect string) (RuleSpec, error) {
	if strings.TrimSpace(tool) == "" {
		return RuleSpec{}, errors.New("names no tool, so there is nothing to scope a rule to")
	}
	spec := RuleSpec{ToolPattern: tool, Effect: effect}
	if scope != "exact" {
		return spec, nil
	}
	var args map[string]any
	_ = json.Unmarshal(arguments, &args)

	for _, pick := range []struct {
		kind string
		keys []string
	}{
		{"command", []string{"command", "cmd", "script"}},
		{"url", []string{"url", "uri"}},
		{"path", []string{"file_path", "path", "filePath", "notebook_path"}},
		{"filename", []string{"filename", "pattern"}},
	} {
		for _, k := range pick.keys {
			if v, ok := args[k].(string); ok && strings.TrimSpace(v) != "" {
				spec.Kind, spec.Value = pick.kind, v
				break
			}
		}
		if spec.Kind != "" {
			break
		}
	}
	if spec.Kind == "" {

		return RuleSpec{}, fmt.Errorf(
			"records no command, path or URL to narrow on. Pass --scope tool to cover the %s tool as a whole",
			tool)
	}
	return spec, nil
}

func (a Audit) Whitelist(ctx context.Context, id, scope string) (RuleMutation, error) {
	return ruleFromEntry(ctx, Policies{a.c}, id, scope, "ALLOW")
}

func (a Audit) Block(ctx context.Context, id, scope string) (RuleMutation, error) {
	return ruleFromEntry(ctx, Policies{a.c}, id, scope, "DENY")
}