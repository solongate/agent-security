package store

import (
	"context"
	"database/sql"
)

// The aggregates behind /v1/stats, /v1/stats/timeseries, /v1/stats/drift and
// /v1/stats/security-insights.
//
// Every one of them reads audit_logs, which is the largest table here, so two
// rules hold throughout and neither is negotiable.
//
// The project clause is on every statement. These endpoints answer with counts,
// tool names, agent names and denial reasons — a summary of another tenant's
// history is still that tenant's history, and an aggregate that forgets the
// scope leaks it in a shape nobody thinks to audit.
//
// Nothing here is unbounded. The grouped queries return one row per bucket and
// the bucket count is fixed by the caller's window; the one query that returns
// raw rows takes a limit and binds it. `days` and `period` arrive from a query
// string, and a range a caller chooses with no ceiling on it is a way to ask
// this service to read the whole table with a valid API key attached.

// DecisionCount is one row of the decision histogram GET /v1/stats opens with.
type DecisionCount struct {
	Decision string
	Count    int64
}

// RecentCall is the "recent activity" projection: six columns out of
// twenty-five, because that list shows six fields and selecting the row would
// move every stored argument summary to render them.
type RecentCall struct {
	ID               string
	ToolName         string
	Decision         string
	TrustLevel       string
	EvaluationTimeMs *float64
	CreatedAt        int64
}

// StatsOverview is the whole of GET /v1/stats in one value.
type StatsOverview struct {
	Decisions []DecisionCount
	Policies  int64
	Tools     int64
	Recent    []RecentCall
}

// StatsOverview runs the four reads at once, as the live route's Promise.all
// does. In series against Turso they are four network round trips for one
// dashboard panel; the pool ceiling in Open is what stops that concurrency from
// starving every other route.
func (s *Store) StatsOverview(ctx context.Context, projectID string, recentLimit int) (StatsOverview, error) {
	var out StatsOverview
	err := parallel(
		func() (err error) { out.Decisions, err = s.auditDecisionCounts(ctx, projectID); return },
		func() (err error) { out.Policies, err = s.countDistinctPolicies(ctx, projectID); return },
		func() (err error) { out.Tools, err = s.countTools(ctx, projectID); return },
		func() (err error) { out.Recent, err = s.recentAuditActivity(ctx, projectID, recentLimit); return },
	)
	return out, err
}

func (s *Store) auditDecisionCounts(ctx context.Context, projectID string) ([]DecisionCount, error) {
	rows, err := s.query(ctx,
		`SELECT decision, COUNT(*) FROM audit_logs WHERE project_id = ? GROUP BY decision`,
		projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []DecisionCount{}
	for rows.Next() {
		var d DecisionCount
		if err := rows.Scan(&d.Decision, &d.Count); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// countDistinctPolicies counts LOGICAL policies, not rows.
//
// policy_versions is append-only, so a project that has saved one policy forty
// times has forty rows and one policy — which is why the live query counts
// distinct `$.id` inside policy_data rather than the rows. COUNT(DISTINCT)
// skips NULLs, so a malformed policy with no id is not counted, and that too is
// the original's behaviour.
func (s *Store) countDistinctPolicies(ctx context.Context, projectID string) (int64, error) {
	var n int64
	err := s.queryRow(ctx,
		`SELECT COUNT(DISTINCT `+s.jsonField("policy_data", "id")+`) FROM policy_versions
		 WHERE project_id = ?`, projectID).Scan(&n)
	return n, err
}

func (s *Store) countTools(ctx context.Context, projectID string) (int64, error) {
	var n int64
	err := s.queryRow(ctx,
		`SELECT COUNT(*) FROM tools WHERE project_id = ?`, projectID).Scan(&n)
	return n, err
}

func (s *Store) recentAuditActivity(ctx context.Context, projectID string, limit int) ([]RecentCall, error) {
	rows, err := s.query(ctx, `
		SELECT id, tool_name, decision, trust_level, evaluation_time_ms, created_at
		FROM audit_logs WHERE project_id = ?
		ORDER BY created_at DESC LIMIT ?`, projectID, ClampLimit(limit, 10, 100))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []RecentCall{}
	for rows.Next() {
		var c RecentCall
		var evalMs sql.NullFloat64
		if err := rows.Scan(&c.ID, &c.ToolName, &c.Decision, &c.TrustLevel, &evalMs, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.EvaluationTimeMs = numPtr(evalMs)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ── the timeseries ──────────────────────────────────────────────────────────

// TimeBucket is one interval of GET /v1/stats/timeseries.
//
// AvgEvalMs is a pointer because AVG over a bucket whose rows all have a NULL
// evaluation_time_ms is NULL, not zero. The route renders both as 0, but it has
// to be able to tell them apart to do the rounding the live app does.
type TimeBucket struct {
	Bucket    string
	Total     int64
	Allowed   int64
	Denied    int64
	AvgEvalMs *float64
}

// EarliestAuditAt is MIN(created_at), for `?period=all`. ok=false means the
// project has no audit history at all, which the route turns into a thirty-day
// window rather than a window starting at the epoch.
func (s *Store) EarliestAuditAt(ctx context.Context, projectID string) (int64, bool, error) {
	var v sql.NullInt64
	err := s.queryRow(ctx,
		`SELECT MIN(created_at) FROM audit_logs WHERE project_id = ?`, projectID).Scan(&v)
	if err != nil {
		return 0, false, err
	}
	return intVal(v), v.Valid, nil
}

// AuditTimeSeries buckets a project's calls by hour, day or month.
//
// The granularity is a Bucket rather than a format string. The two dialects
// spell their date formats differently, so a format chosen by the route and
// bound as a parameter would have to be translated per value; a closed set of
// three constants is translated once, in dialect.go, and cannot be widened
// into a query parameter later.
//
// The expression is computed once in a subquery and grouped by its alias, so
// the SELECT, the GROUP BY and the ORDER BY cannot drift apart into three
// slightly different bucket keys — the live app repeats the same SQL template
// three times and relies on it being identical.
//
// The bucket keys are UTC: datetime(x, 'unixepoch') renders UTC and takes no
// notice of the server's zone. The route's zero-fill has to agree, which is why
// it formats in UTC too — a fill in local time produces keys that miss every
// row the database returned and a chart that reads as all zeroes.
func (s *Store) AuditTimeSeries(ctx context.Context, projectID string, bucket Bucket, since int64) ([]TimeBucket, error) {
	rows, err := s.query(ctx, `
		SELECT bucket,
		       COUNT(*),
		       SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END),
		       SUM(CASE WHEN decision IN ('DENY', 'DENIED') THEN 1 ELSE 0 END),
		       AVG(evaluation_time_ms)
		FROM (
			SELECT `+s.timeBucket("created_at", bucket)+` AS bucket,
			       decision, evaluation_time_ms
			FROM audit_logs
			WHERE project_id = ? AND created_at >= ?
		) AS bucketed
		GROUP BY bucket ORDER BY bucket`, projectID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []TimeBucket{}
	for rows.Next() {
		var b TimeBucket
		var bucket sql.NullString
		var avg sql.NullFloat64
		if err := rows.Scan(&bucket, &b.Total, &b.Allowed, &b.Denied, &avg); err != nil {
			return nil, err
		}
		b.Bucket = text(bucket)
		b.AvgEvalMs = numPtr(avg)
		out = append(out, b)
	}
	return out, rows.Err()
}

// ── drift ───────────────────────────────────────────────────────────────────

// DeniedRuleGroup is one rule's denials in one window.
//
// RuleID is a pointer because a denial with no matched rule is a REAL group —
// the default deny — and the route keys it as `__default__` while still
// answering with a null rule_id. Collapsing NULL to "" here would merge it with
// a rule genuinely named the empty string.
//
// Reason is a pointer for the same reason: MAX over a column that is NULL in
// every row of the group is NULL, and the live response carries that null
// through.
type DeniedRuleGroup struct {
	RuleID   *string
	Count    int64
	Reason   *string
	LastTool string
}

// DriftWindows is the two halves GET /v1/stats/drift compares.
//
// The totals are counted separately rather than summed from the groups, because
// the group lists are CAPPED (see maxDriftGroups) and a total derived from a
// truncated list would quietly under-report the denial count the panel leads
// with.
type DriftWindows struct {
	Current       []DeniedRuleGroup
	Previous      []DeniedRuleGroup
	TotalCurrent  int64
	TotalPrevious int64
}

// maxDriftGroups bounds the number of rules a drift response can describe.
//
// matched_rule_id is written by whatever reported the call, so the number of
// distinct values in ninety days is not a property of this project's policy —
// it is a property of what a client chose to send. The live route groups
// without a limit and serialises every group, which is a response a caller can
// make arbitrarily large. The cap is far above any real policy's rule count, so
// a genuine project sees the same answer it always did.
//
// The busiest groups are the ones kept, in both windows. A project that really
// does have more than five hundred distinct rules firing can therefore see a
// rule marked `is_new` because its earlier traffic fell outside the previous
// window's top five hundred. The totals do not drift with it — they are counted
// separately, which is why they are.
const maxDriftGroups = 500

// AuditDriftWindows counts denials per rule in the current window and in the
// window immediately before it, plus the totals for each.
//
// `previous` is half-open on purpose — [prevFrom, currentFrom) — so a call on
// the boundary is counted once rather than in both halves, which would show as
// a rule whose traffic never changes.
func (s *Store) AuditDriftWindows(ctx context.Context, projectID string, currentFrom, prevFrom int64) (DriftWindows, error) {
	var out DriftWindows
	err := parallel(
		func() (err error) {
			out.Current, err = s.deniedRuleGroups(ctx, projectID,
				`created_at >= ?`, currentFrom)
			return
		},
		func() (err error) {
			out.Previous, err = s.deniedRuleGroups(ctx, projectID,
				`created_at >= ? AND created_at < ?`, prevFrom, currentFrom)
			return
		},
		func() (err error) {
			out.TotalCurrent, err = s.countDenials(ctx, projectID,
				`created_at >= ?`, currentFrom)
			return
		},
		func() (err error) {
			out.TotalPrevious, err = s.countDenials(ctx, projectID,
				`created_at >= ? AND created_at < ?`, prevFrom, currentFrom)
			return
		},
	)
	return out, err
}

// deniedRuleGroups is the grouped read. `window` is a fragment written HERE and
// chosen by AuditDriftWindows; the timestamps behind it are bound.
func (s *Store) deniedRuleGroups(ctx context.Context, projectID, window string, bounds ...any) ([]DeniedRuleGroup, error) {
	args := append([]any{projectID}, bounds...)
	args = append(args, maxDriftGroups)

	rows, err := s.query(ctx, `
		SELECT matched_rule_id, COUNT(*) AS n, MAX(reason), MAX(tool_name)
		FROM audit_logs
		WHERE project_id = ? AND decision IN ('DENY', 'DENIED') AND `+window+`
		GROUP BY matched_rule_id
		ORDER BY n DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []DeniedRuleGroup{}
	for rows.Next() {
		var g DeniedRuleGroup
		var ruleID, reason, lastTool sql.NullString
		if err := rows.Scan(&ruleID, &g.Count, &reason, &lastTool); err != nil {
			return nil, err
		}
		if ruleID.Valid {
			v := ruleID.String
			g.RuleID = &v
		}
		if reason.Valid {
			v := reason.String
			g.Reason = &v
		}
		g.LastTool = text(lastTool)
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) countDenials(ctx context.Context, projectID, window string, bounds ...any) (int64, error) {
	args := append([]any{projectID}, bounds...)
	var n int64
	err := s.queryRow(ctx, `
		SELECT COUNT(*) FROM audit_logs
		WHERE project_id = ? AND decision IN ('DENY', 'DENIED') AND `+window, args...).Scan(&n)
	return n, err
}

// ── the security-insights scan ──────────────────────────────────────────────

// SecurityScanRow is the six columns /v1/stats/security-insights walks in
// process: it counts bursts per agent per minute and runs the DLP patterns over
// the argument summaries, and neither can be expressed as an aggregate.
type SecurityScanRow struct {
	ToolName         string
	AgentName        string
	Decision         string
	Reason           string
	ArgumentsSummary string
	CreatedAt        int64
}

// SecurityInsightScan reads the window newest-first, bounded.
//
// The live route's limit is five thousand and it is kept, not raised: this is
// the one endpoint here that pulls raw rows into memory, every row carries an
// arguments_summary, and the regular expressions then run over each of them.
// The response reports how many rows were scanned so a caller can see it was
// capped.
func (s *Store) SecurityInsightScan(ctx context.Context, projectID string, since int64, limit int) ([]SecurityScanRow, error) {
	rows, err := s.query(ctx, `
		SELECT tool_name, agent_name, decision, reason, arguments_summary, created_at
		FROM audit_logs
		WHERE project_id = ? AND created_at >= ?
		ORDER BY created_at DESC LIMIT ?`,
		projectID, since, ClampLimit(limit, 5000, 5000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SecurityScanRow{}
	for rows.Next() {
		var r SecurityScanRow
		var agent, reason, summary sql.NullString
		if err := rows.Scan(&r.ToolName, &agent, &r.Decision, &reason, &summary, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.AgentName = text(agent)
		r.Reason = text(reason)
		r.ArgumentsSummary = text(summary)
		out = append(out, r)
	}
	return out, rows.Err()
}
