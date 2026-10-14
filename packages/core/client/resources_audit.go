// SPDX-License-Identifier: Apache-2.0

package client

// Split from resources.go: the /audit-logs namespace. See resources_policy.go
// for the file-level rationale.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ── /audit-logs ────────────────────────────────────────────────────────────

type Audit struct{ c *Client }

// AuditQuery is every filter the audit list accepts. Signal is derived from the
// reason plus the detect-mode observation rather than stored as a column, which
// is why it is a filter here and not a field on AuditEntry.
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

func (a Audit) List(ctx context.Context, q AuditQuery) (AuditList, error) {
	limit := q.Limit
	if limit < 1 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}

	decision := q.Filter
	if decision == "DENIED" {
		decision = "DENY"
	}
	lower := strings.ToLower
	rows := []AuditEntry{}
	for _, l := range readLog() {
		e := toAuditEntry(l)
		if decision != "" && e.Decision != decision {
			continue
		}
		if q.Tool != "" && !strings.Contains(lower(e.ToolName), lower(q.Tool)) {
			continue
		}
		if q.AgentName != "" {
			name := ""
			if e.AgentName != nil {
				name = *e.AgentName
			}
			if !strings.Contains(lower(name), lower(q.AgentName)) {
				continue
			}
		}
		if q.SessionID != "" && (e.SessionID == nil || *e.SessionID != q.SessionID) {
			continue
		}
		reason := ""
		if e.Reason != nil {
			reason = *e.Reason
		}
		if q.Signal == "dlp" && len(e.DLPMatches) == 0 && !strings.Contains(lower(reason), "dlp") {
			continue
		}
		if q.Signal == "ratelimit" && !e.RateLimitBurst && !strings.Contains(lower(reason), "rate limit") {
			continue
		}
		if q.Search != "" {
			needle := lower(q.Search)
			if !strings.Contains(lower(e.ToolName), needle) &&
				!strings.Contains(lower(reason), needle) &&
				!strings.Contains(lower(string(e.ArgumentsSummary)), needle) {
				continue
			}
		}
		if q.From > 0 || q.To > 0 {
			at := l.at
			if at <= 0 {
				continue
			}
			if q.From > 0 && at < q.From {
				continue
			}
			if q.To > 0 && at > q.To {
				continue
			}
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

/*
 * There is no Remove and no RemoveAll. Both used to call DELETE /audit-logs;
 * the endpoint is gone, and an audit log the audited party can clear is not a
 * record of anything. On a machine the file is the record, somebody who owns
 * the machine can always delete it, and the CLI does not have to help.
 */

// ruleFromEntry turns one recorded call into a rule.
//
// `exact` narrows to what that call actually did, the command, the path, the URL
// the entry carries. `tool` covers the tool as a whole, which is the wider and
// more dangerous of the two, so it is never the default.
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

// RuleSpecFor turns ONE RECORDED CALL into the rule that would have stopped it.
//
// Exported, and the only implementation, because the Live panel's `w`/`b` keys ask the
// same question of an entry they are holding in memory rather than by id. They used to
// answer it themselves, with a second extractor that differed in two ways that matter:
// it did not look for a url at all, and for a path it took the BASENAME, so
// whitelisting the same denial from the stream and from the audit browser produced two
// different rules. Whichever a person happened to use decided how wide their policy got.
//
// scope "exact" narrows to what the call actually did. Anything else covers the tool.
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
	// The argument names the guard records, in the order it prefers to match on: a
	// command is more specific than the file it touched.
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
		// Nothing in the entry to narrow on. WIDENING SILENTLY TO THE WHOLE TOOL is
		// exactly the surprise this refuses to be: `w` on one unremarkable denial
		// would otherwise allow every call to that tool forever.
		return RuleSpec{}, fmt.Errorf(
			"records no command, path or URL to narrow on. Pass --scope tool to cover the %s tool as a whole",
			tool)
	}
	return spec, nil
}

// Whitelist turns a denial into an ALLOW rule.
func (a Audit) Whitelist(ctx context.Context, id, scope string) (RuleMutation, error) {
	return ruleFromEntry(ctx, Policies{a.c}, id, scope, "ALLOW")
}

// Block is the inverse: turn a call that was allowed into a DENY rule.
func (a Audit) Block(ctx context.Context, id, scope string) (RuleMutation, error) {
	return ruleFromEntry(ctx, Policies{a.c}, id, scope, "DENY")
}