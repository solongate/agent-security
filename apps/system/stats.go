package main

import (
	"math"
	"net/http"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/store"
)

// The statistics endpoints: src/app/api/v1/stats/**.
//
// All four aggregate audit_logs and all four are read by the dashboard, so the
// field names below are the live app's exactly — including the fact that
// /stats, /stats/timeseries and /stats/drift answer in snake_case while
// /stats/security-insights answers in camelCase. That inconsistency is a
// contract, not an oversight to tidy: a panel reading `dlpHits` does not find
// `dlp_hits`.
//
// Three things decide whether a port of these is right, and none of them shows
// up in a response that merely parses:
//
//   - The BUCKETS are UTC. SQLite's datetime(x,'unixepoch') renders UTC, so the
//     zero-fill has to build its keys in UTC too. A fill in the server's local
//     zone produces labels that match no row the database returned, and the
//     chart is silently all zeroes — worse on a machine an hour off than on one
//     twelve hours off, because it looks nearly right.
//   - The WINDOW is bounded. `days` is clamped to 1..90 and `period` is chosen
//     from four literals, because a range a caller picks with no ceiling is a
//     request to read the whole of the largest table here, and any valid key can
//     make it.
//   - The SCAN is bounded. security-insights walks raw rows in this process, so
//     its read is capped and it reports the cap back as `scanned`.

func init() {
	Register("GET /api/v1/stats", buildStatsHandler((*server).statsOverview))
	Register("GET /api/v1/stats/timeseries", buildStatsHandler((*server).statsTimeseries))
	Register("GET /api/v1/stats/drift", buildStatsHandler((*server).statsDrift))
	Register("GET /api/v1/stats/security-insights", buildStatsHandler((*server).statsSecurityInsights))
}

// buildStatsHandler wraps a method in withAuth at the standard limit, which is
// what every one of these routes does in the live app. There is no anonymous
// read here: these responses are a summary of a project's whole history, and
// the project comes from the KEY — nothing below reads a project id out of the
// request.
func buildStatsHandler(fn func(*server, http.ResponseWriter, *http.Request, apiauth.KeyInfo)) func(*server) http.Handler {
	return func(s *server) http.Handler {
		return s.auth.WithAuth(func(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
			fn(s, w, r, key)
		})
	}
}

// ── GET /api/v1/stats ───────────────────────────────────────────────────────

type statsRecentEntry struct {
	ID               string   `json:"id"`
	ToolName         string   `json:"tool_name"`
	Decision         string   `json:"decision"`
	TrustLevel       string   `json:"trust_level"`
	EvaluationTimeMs *float64 `json:"evaluation_time_ms"`
	CreatedAt        string   `json:"created_at"`
}

type statsOverviewResponse struct {
	TotalCalls      int64              `json:"total_calls"`
	Allowed         int64              `json:"allowed"`
	Denied          int64              `json:"denied"`
	ActivePolicies  int64              `json:"active_policies"`
	RegisteredTools int64              `json:"registered_tools"`
	RecentActivity  []statsRecentEntry `json:"recent_activity"`
}

// recentActivityLimit is the live route's ten. It is the dashboard's activity
// strip, not a log viewer; /v1/audit-logs is the paged read.
const recentActivityLimit = 10

func (s *server) statsOverview(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	data, err := s.store.StatsOverview(r.Context(), key.ProjectID, recentActivityLimit)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	out := statsOverviewResponse{
		ActivePolicies:  data.Policies,
		RegisteredTools: data.Tools,
		RecentActivity:  make([]statsRecentEntry, 0, len(data.Recent)),
	}
	for _, row := range data.Decisions {
		out.TotalCalls += row.Count
		switch row.Decision {
		case "ALLOW":
			// ASSIGNED, not accumulated, exactly as the live route does. There is
			// one ALLOW group per project so the two are the same number — but
			// `denied` really does accumulate, because DENY and DENIED are both
			// stored and both mean denied. Two spellings of one decision is the
			// scar of an older guard version and every count here has to know it.
			out.Allowed = row.Count
		case "DENY", "DENIED":
			out.Denied += row.Count
		}
	}
	for _, c := range data.Recent {
		out.RecentActivity = append(out.RecentActivity, statsRecentEntry{
			ID:               c.ID,
			ToolName:         c.ToolName,
			Decision:         c.Decision,
			TrustLevel:       c.TrustLevel,
			EvaluationTimeMs: c.EvaluationTimeMs,
			CreatedAt:        store.ISO(c.CreatedAt),
		})
	}
	apiauth.JSON(w, http.StatusOK, out)
}

// ── GET /api/v1/stats/timeseries ────────────────────────────────────────────

type timeseriesPoint struct {
	Timestamp     string  `json:"timestamp"`
	Total         int64   `json:"total"`
	Allowed       int64   `json:"allowed"`
	Denied        int64   `json:"denied"`
	AvgEvalTimeMs float64 `json:"avg_eval_time_ms"`
}

type timeseriesResponse struct {
	Timeseries  []timeseriesPoint `json:"timeseries"`
	Period      string            `json:"period"`
	Granularity string            `json:"granularity"`
}

const (
	msPerHour = int64(3_600_000)
	msPerDay  = int64(86_400_000)
)

// maxSeriesBuckets caps how many points the zero-fill will emit.
//
// The largest legitimate answer is `?period=30d&granularity=1h`, at 721 points.
// The cap exists for `period=all`, whose window starts at MIN(created_at) — a
// value written by whatever reported the call, so a single row with a bogus
// timestamp in 1970 turns a month-bucketed fill into tens of thousands of
// points this process builds and serialises. The live route has no such bound.
const maxSeriesBuckets = 2000

func (s *server) statsTimeseries(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	ctx := r.Context()
	q := r.URL.Query()
	period := q.Get("period")
	if period == "" {
		period = "24h"
	}
	granularity := q.Get("granularity")
	if granularity == "" {
		granularity = "1h"
	}

	// One clock for the whole request. Reading time.Now() again for the fill
	// would let the last bucket of a slow request be one the query never
	// covered.
	nowMS := time.Now().UnixMilli()

	var startMS int64
	switch period {
	case "all":
		earliest, ok, err := s.store.EarliestAuditAt(ctx, key.ProjectID)
		if err != nil {
			apiauth.Internal(w, "api", err)
			return
		}
		if ok {
			// MIN(created_at) is stored in SECONDS; everything from here on is
			// milliseconds. Getting this multiplication wrong gives a window
			// starting in January 1970 and a chart of empty buckets.
			startMS = earliest * 1000
		} else {
			startMS = nowMS - 30*msPerDay
		}
	case "7d":
		startMS = nowMS - 7*msPerDay
	case "30d":
		startMS = nowMS - 30*msPerDay
	default:
		// Anything unrecognised is 24h, as the live switch's default is. The
		// caller's spelling is still echoed back below, unvalidated, because
		// that is what the original answers with.
		startMS = nowMS - msPerDay
	}

	var unit string
	if period == "all" {
		spanDays := float64(nowMS-startMS) / float64(msPerDay)
		var minSpanMS int64
		switch {
		case spanDays <= 2:
			unit, minSpanMS = "hour", 24*msPerHour
		case spanDays <= 90:
			unit, minSpanMS = "day", 14*msPerDay
		default:
			unit, minSpanMS = "month", 6*30*msPerDay
		}
		// A project one hour old still gets a full day of buckets: a chart with
		// two points reads as an outage rather than as a new project.
		if nowMS-minSpanMS < startMS {
			startMS = nowMS - minSpanMS
		}
	} else if granularity == "1d" {
		unit = "day"
	} else {
		unit = "hour"
	}

	// The bucket granularity. The keys it renders ARE what the zero-fill below
	// matches against, character for character — an hour key ends in ":00" and
	// not ":00:00", and a month key keeps its "-01".
	bucket := store.BucketHour
	switch unit {
	case "day":
		bucket = store.BucketDay
	case "month":
		bucket = store.BucketMonth
	}

	// Seconds, floored, because that is what drizzle binds a Date as against an
	// integer({mode:'timestamp'}) column. Truncating toward zero instead would
	// shift the boundary by a second for a pre-1970 window.
	rows, err := s.store.AuditTimeSeries(ctx, key.ProjectID, bucket, floorDiv(startMS, 1000))
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	byBucket := make(map[string]store.TimeBucket, len(rows))
	for _, row := range rows {
		byBucket[row.Bucket] = row
	}

	// Every bucket in the window is emitted, present in the database or not. A
	// series with holes is a line chart that draws straight through a period of
	// silence, which is the opposite of what silence means here.
	series := make([]timeseriesPoint, 0, 64)
	push := func(bucket string) {
		if len(series) >= maxSeriesBuckets {
			return
		}
		row, ok := byBucket[bucket]
		p := timeseriesPoint{Timestamp: bucket}
		if ok {
			p.Total, p.Allowed, p.Denied = row.Total, row.Allowed, row.Denied
			// `avg ? Number(avg.toFixed(2)) : 0` — a NULL average and an average
			// of zero both render as 0, and the rounding is to two decimals
			// because the panel prints the number as it arrives.
			if row.AvgEvalMs != nil && *row.AvgEvalMs != 0 {
				p.AvgEvalTimeMs = math.Round(*row.AvgEvalMs*100) / 100
			}
		}
		series = append(series, p)
	}

	if unit == "month" {
		start := time.UnixMilli(startMS).UTC()
		end := time.UnixMilli(nowMS).UTC()
		y, m := start.Year(), start.Month()
		for y < end.Year() || (y == end.Year() && m <= end.Month()) {
			push(time.Date(y, m, 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02"))
			if m == time.December {
				y, m = y+1, time.January
			} else {
				m++
			}
		}
	} else {
		bucketMS := msPerHour
		layout := "2006-01-02 15:00"
		if unit == "day" {
			bucketMS, layout = msPerDay, "2006-01-02"
		}
		// Aligned to the bucket, so the first label is the hour the window
		// started IN rather than the odd minute it started at — which is also
		// what the database's own truncation produced.
		alignedEnd := floorDiv(nowMS, bucketMS) * bucketMS
		for t := floorDiv(startMS, bucketMS) * bucketMS; t <= alignedEnd; t += bucketMS {
			push(time.UnixMilli(t).UTC().Format(layout))
		}
	}

	apiauth.JSON(w, http.StatusOK, timeseriesResponse{
		Timeseries: series,
		Period:     period,
		// The unit, not the caller's `granularity`: for period=all the server
		// chooses it, and a client that drew hourly labels over monthly buckets
		// would be drawing three years of data as three years of hours.
		Granularity: unit,
	})
}

// ── GET /api/v1/stats/drift ─────────────────────────────────────────────────

type driftRule struct {
	RuleID   *string `json:"rule_id"`
	Reason   *string `json:"reason"`
	LastTool string  `json:"last_tool"`
	Current  int64   `json:"current"`
	Previous int64   `json:"previous"`
	Delta    int64   `json:"delta"`
	DeltaPct *int64  `json:"delta_pct"`
	IsNew    bool    `json:"is_new"`
	Spike    bool    `json:"spike"`
}

type driftResponse struct {
	Days          int         `json:"days"`
	TotalCurrent  int64       `json:"total_current"`
	TotalPrevious int64       `json:"total_previous"`
	Rules         []driftRule `json:"rules"`
}

// noRuleKey is the live route's `__default__`: denials with no matched rule are
// one group, and the group has to be keyed by something that cannot collide
// with a real rule id. The response still carries a null rule_id for it.
const noRuleKey = "__default__"

func (s *server) statsDrift(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	days := statsDays(r)

	// Two adjacent windows of the same length: [now-d, now) against
	// [now-2d, now-d). Comparing against a fixed period instead would make every
	// rule look like it spiked the day after a busy week.
	nowMS := time.Now().UnixMilli()
	windowMS := int64(days) * msPerDay
	currentFrom := nowMS - windowMS
	prevFrom := nowMS - 2*windowMS

	windows, err := s.store.AuditDriftWindows(r.Context(), key.ProjectID,
		floorDiv(currentFrom, 1000), floorDiv(prevFrom, 1000))
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	previous := make(map[string]int64, len(windows.Previous))
	for _, g := range windows.Previous {
		previous[driftKey(g.RuleID)] = g.Count
	}

	rules := make([]driftRule, 0, len(windows.Current))
	for _, g := range windows.Current {
		prev := previous[driftKey(g.RuleID)]
		delta := g.Count - prev
		rule := driftRule{
			RuleID:   g.RuleID,
			Reason:   g.Reason,
			LastTool: g.LastTool,
			Current:  g.Count,
			Previous: prev,
			Delta:    delta,
			IsNew:    prev == 0,
			// A spike is a doubling that is also worth looking at: five denials
			// is the floor, so a rule that went from one to two is not an alert.
			Spike: prev > 0 && g.Count >= prev*2 && g.Count >= 5,
		}
		if prev > 0 {
			// null rather than a percentage when there is nothing to compare
			// against — a rule that appeared this week has not grown by infinity
			// per cent, and the panel branches on the null to say "new".
			pct := jsRound(float64(delta) / float64(prev) * 100)
			rule.DeltaPct = &pct
		}
		rules = append(rules, rule)
	}
	// Already ordered by count in the query; sorted again, stably, because the
	// order is part of the answer and must not depend on the plan SQLite picks.
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Current > rules[j].Current })

	apiauth.JSON(w, http.StatusOK, driftResponse{
		Days:          days,
		TotalCurrent:  windows.TotalCurrent,
		TotalPrevious: windows.TotalPrevious,
		Rules:         rules,
	})
}

func driftKey(ruleID *string) string {
	if ruleID == nil {
		return noRuleKey
	}
	return *ruleID
}

// ── GET /api/v1/stats/security-insights ─────────────────────────────────────

type insightAnomaly struct {
	Agent   string `json:"agent"`
	Minute  string `json:"minute"`
	Count   int64  `json:"count"`
	Limit   int64  `json:"limit"`
	Blocked bool   `json:"blocked"`
}

type insightDLPHit struct {
	Tool    string `json:"tool"`
	Agent   string `json:"agent"`
	Pattern string `json:"pattern"`
	Preview string `json:"preview"`
	At      string `json:"at"`
	Blocked bool   `json:"blocked"`
}

type dayCount struct {
	Day   string `json:"day"`
	Count int64  `json:"count"`
}

type agentCount struct {
	Agent string `json:"agent"`
	Count int64  `json:"count"`
}

type patternCount struct {
	Pattern string `json:"pattern"`
	Count   int64  `json:"count"`
}

type activityPoint struct {
	T     int64 `json:"t"`
	Count int64 `json:"count"`
}

type insightPeaks struct {
	Minute int64 `json:"minute"`
	Hour   int64 `json:"hour"`
	Day    int64 `json:"day"`
}

type insightActivity struct {
	Minute []activityPoint `json:"minute"`
	Hour   []activityPoint `json:"hour"`
	Day    []activityPoint `json:"day"`
}

// The response is camelCase where the rest of this file is snake_case. That is
// the live shape; see the file note.
type insightsResponse struct {
	Days             int                     `json:"days"`
	Layers           store.SecurityLayers    `json:"layers"`
	Anomalies        []insightAnomaly        `json:"anomalies"`
	AnomalyThreshold int64                   `json:"anomalyThreshold"`
	DLPHits          []insightDLPHit         `json:"dlpHits"`
	Scanned          int                     `json:"scanned"`
	TotalCalls       int                     `json:"totalCalls"`
	CallsPerDay      []dayCount              `json:"callsPerDay"`
	TopAgents        []agentCount            `json:"topAgents"`
	DLPByPattern     []patternCount          `json:"dlpByPattern"`
	Peaks            insightPeaks            `json:"peaks"`
	Activity         insightActivity         `json:"activity"`
	LimitHistory     []store.RateLimitChange `json:"limitHistory"`
}

const (
	// insightScanLimit is the live route's 5000. This is the one endpoint here
	// that pulls raw rows into this process and runs regular expressions over
	// each of their argument summaries, so the number is a memory and CPU bound
	// as much as a database one. `scanned` in the response is how a caller sees
	// it was hit.
	insightScanLimit = 5000
	maxAnomalies     = 100
	maxTopAgents     = 6

	// maxInsightDLPHits is this endpoint's own cap and is deliberately not the
	// audit list's maxDLPHits: that one bounds how many pattern names one row's
	// badge shows, this one bounds how many rows the whole scan reports.
	maxInsightDLPHits = 200
)

func (s *server) statsSecurityInsights(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	ctx := r.Context()
	days := statsDays(r)

	layers := s.store.GetSecurityLayers(ctx, key.ProjectID)
	limitHistory := s.store.RateLimitHistory(ctx, key.ProjectID)

	nowMS := time.Now().UnixMilli()
	sinceMS := nowMS - int64(days)*msPerDay
	rows, err := s.store.SecurityInsightScan(ctx, key.ProjectID, floorDiv(sinceMS, 1000), insightScanLimit)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	out := insightsResponse{
		Days:             days,
		Layers:           layers,
		AnomalyThreshold: layers.RateLimit.PerMinute,
		Scanned:          len(rows),
		TotalCalls:       len(rows),
		LimitHistory:     limitHistory,
		Anomalies:        []insightAnomaly{},
		DLPHits:          []insightDLPHit{},
		CallsPerDay:      []dayCount{},
		TopAgents:        []agentCount{},
		DLPByPattern:     []patternCount{},
	}

	out.Anomalies = rateLimitAnomalies(rows, layers, limitHistory)
	out.DLPHits = dlpHits(rows, layers)
	out.DLPByPattern = countPatterns(out.DLPHits)
	out.CallsPerDay, out.TopAgents = callVolume(rows)
	out.Peaks = insightPeaks{
		Minute: peakPerAgent(rows, 60_000),
		Hour:   peakPerAgent(rows, msPerHour),
		Day:    peakPerAgent(rows, msPerDay),
	}
	out.Activity = insightActivity{
		Minute: activitySeries(rows, nowMS, 60_000, 60),
		Hour:   activitySeries(rows, nowMS, msPerHour, 24),
		Day:    activitySeries(rows, nowMS, msPerDay, days),
	}

	apiauth.JSON(w, http.StatusOK, out)
}

// minuteBucket identifies one agent's calls in one minute.
//
// It is a struct rather than the live route's `agent + "|" + minute` string,
// which that route then splits back apart on the first "|" — an agent whose
// name contains a pipe comes out of the split with a truncated name and a
// minute that is not a date, and the limit lookup for it silently falls back to
// the default. Agent names are reported by the client, so that input is
// reachable.
type minuteBucket struct {
	agent    string
	minuteMS int64
}

// rateLimitAnomalies finds the minutes in which an agent went over the limit
// that was configured AT THE TIME, plus every minute the guard actually
// refused a call for rate limiting.
//
// The second half is why the denial scan exists at all: a project that has
// since raised its limit would otherwise show no anomaly for the hour it spent
// being throttled, because the current number is not the number that applied.
func rateLimitAnomalies(rows []store.SecurityScanRow, layers store.SecurityLayers, history []store.RateLimitChange) []insightAnomaly {
	// The history is walked forwards to find the last change at or before a
	// minute, so it has to be in order. It is stored append-only and should
	// already be, but a copy is sorted rather than trusting that — and it is a
	// COPY because the same slice is serialised into the response.
	asc := append([]store.RateLimitChange(nil), history...)
	sort.SliceStable(asc, func(i, j int) bool { return asc[i].TS < asc[j].TS })

	counts := newCounter[minuteBucket]()
	denied := map[minuteBucket]bool{}
	for _, row := range rows {
		bucket := minuteBucket{
			agent:    agentOrUnknown(row.AgentName),
			minuteMS: floorDiv(row.CreatedAt*1000, 60_000) * 60_000,
		}
		counts.add(bucket, 1)
		// deniedForRateLimit is the audit list's own test, reused rather than
		// rewritten: "DENY" and a reason that mentions a rate limit. Two
		// spellings of that rule would show a burst on one screen and not on the
		// other.
		if deniedForRateLimit(row.Decision, row.Reason) {
			denied[bucket] = true
		}
	}

	out := []insightAnomaly{}
	for _, bucket := range counts.order {
		count := counts.count[bucket]
		// The limit that applied in that MINUTE, from the recorded history —
		// the same function the audit list's burst badge uses.
		limit := limitAt(bucket.minuteMS, asc, layers)
		if (limit > 0 && count > limit) || denied[bucket] {
			out = append(out, insightAnomaly{
				Agent:   bucket.agent,
				Minute:  store.ISOms(bucket.minuteMS),
				Count:   count,
				Limit:   limit,
				Blocked: denied[bucket],
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > maxAnomalies {
		out = out[:maxAnomalies]
	}
	return out
}

// dlpBlockReason is this route's probe for "the guard stopped this call because
// of a secret". The signals are not columns — see the note in
// internal/store/auditlogs.go — so the denial text is all there is.
//
// It is NOT audit_signals.go's dlpReasonPrefix, which requires the closing
// parenthesis of "(DLP)". This one is the live route's `/security layer \(dlp/i`
// and matches "(DLP:" too, so a reason written with a colon still counts as
// blocked here. Unifying them would change one screen or the other.
var dlpBlockReason = regexp.MustCompile(`(?i)security layer \(dlp`)

// dlpHits runs the enabled secret detectors over the stored argument summaries.
//
// It runs them whatever the DLP layer's mode is, including `off`: this endpoint
// reports what WOULD have been caught, which is how somebody decides to turn
// blocking on. `blocked` is the separate question of whether the guard actually
// stopped that call.
func dlpHits(rows []store.SecurityScanRow, layers store.SecurityLayers) []insightDLPHit {
	matchers := dlpMatchers(layers)
	if len(matchers) == 0 {
		return []insightDLPHit{}
	}

	out := []insightDLPHit{}
	for _, row := range rows {
		if row.ArgumentsSummary == "" {
			continue
		}
		for _, m := range matchers {
			hit := m.re.FindString(row.ArgumentsSummary)
			if hit == "" {
				continue
			}
			out = append(out, insightDLPHit{
				Tool:    row.ToolName,
				Agent:   agentOrUnknown(row.AgentName),
				Pattern: m.name,
				Preview: dlpPreview(hit),
				At:      store.ISOms(row.CreatedAt * 1000),
				Blocked: row.Decision == "DENY" && dlpBlockReason.MatchString(row.Reason),
			})
			// One hit per row: the first pattern that matches wins and the rest
			// are not tried, so a summary carrying two kinds of secret is one
			// finding. That is the live behaviour and it keeps the list a list
			// of calls rather than of matches.
			break
		}
		if len(out) >= maxInsightDLPHits {
			break
		}
	}
	return out
}

// dlpPreview is the redaction: enough of a secret to recognise which one it is,
// never enough to use.
//
// A short match is replaced entirely, because four characters of an eight
// character secret is half of it.
func dlpPreview(hit string) string {
	r := []rune(hit)
	if len(r) > 8 {
		return string(r[:4]) + "…" + string(r[len(r)-2:])
	}
	return "••••"
}

type dlpMatcher struct {
	name string
	re   *regexp.Regexp
}

var (
	dlpBuiltinOnce sync.Once
	dlpBuiltin     []dlpMatcher
)

// dlpMatchers compiles the detectors this project has enabled, built-ins first
// and in the canonical order, then the project's own patterns.
//
// The built-ins are compiled once for the process: they are constants, and
// recompiling fourteen expressions on every request to this endpoint is work
// nobody asked for. A pattern that does not compile is DROPPED rather than
// fatal — the live route's `try { } catch { skip }` — so a bad custom regex
// disables one detector instead of the endpoint, and a bad built-in cannot take
// the service down at startup.
//
// Go's regexp is RE2, which is also why a custom pattern cannot be a denial of
// service here: there is no backtracking to blow up on. The cost is that a
// pattern using a backreference or a lookahead does not compile at all, and is
// therefore skipped rather than silently matching nothing.
func dlpMatchers(layers store.SecurityLayers) []dlpMatcher {
	dlpBuiltinOnce.Do(func() {
		for _, p := range store.DLPPatterns {
			expr := p.Re
			if p.CI {
				expr = "(?i)" + expr
			}
			re, err := regexp.Compile(expr)
			if err != nil {
				continue
			}
			dlpBuiltin = append(dlpBuiltin, dlpMatcher{name: p.Name, re: re})
		}
	})

	enabled := make(map[string]bool, len(layers.DLP.Patterns))
	for _, name := range layers.DLP.Patterns {
		enabled[name] = true
	}

	out := make([]dlpMatcher, 0, len(dlpBuiltin)+len(layers.DLP.Custom))
	for _, m := range dlpBuiltin {
		if enabled[m.name] {
			out = append(out, m)
		}
	}
	for _, c := range layers.DLP.Custom {
		re, err := regexp.Compile(c.Re)
		if err != nil {
			continue
		}
		out = append(out, dlpMatcher{name: c.Name, re: re})
	}
	return out
}

func countPatterns(hits []insightDLPHit) []patternCount {
	counts := newCounter[string]()
	for _, h := range hits {
		counts.add(h.Pattern, 1)
	}
	out := make([]patternCount, 0, len(counts.order))
	for _, name := range counts.order {
		out = append(out, patternCount{Pattern: name, Count: counts.count[name]})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// callVolume is calls per UTC day and the busiest agents.
//
// The day key is the ISO date, which is UTC — the same convention the buckets
// in /stats/timeseries use, so the two panels agree about which day a call
// happened on.
func callVolume(rows []store.SecurityScanRow) ([]dayCount, []agentCount) {
	perDay := newCounter[string]()
	perAgent := newCounter[string]()
	for _, row := range rows {
		perDay.add(store.ISO(row.CreatedAt)[:10], 1)
		perAgent.add(agentOrUnknown(row.AgentName), 1)
	}

	days := make([]dayCount, 0, len(perDay.order))
	for _, day := range perDay.order {
		days = append(days, dayCount{Day: day, Count: perDay.count[day]})
	}
	sort.SliceStable(days, func(i, j int) bool { return days[i].Day < days[j].Day })

	agents := make([]agentCount, 0, len(perAgent.order))
	for _, name := range perAgent.order {
		agents = append(agents, agentCount{Agent: name, Count: perAgent.count[name]})
	}
	sort.SliceStable(agents, func(i, j int) bool { return agents[i].Count > agents[j].Count })
	if len(agents) > maxTopAgents {
		agents = agents[:maxTopAgents]
	}
	return days, agents
}

// peakPerAgent is the busiest single bucket any one agent had.
//
// Per agent rather than per project on purpose: it is the number the rate-limit
// panel compares against a per-agent limit, and a project total would make
// every busy project look like it was about to be throttled.
func peakPerAgent(rows []store.SecurityScanRow, bucketMS int64) int64 {
	type agentBucket struct {
		agent  string
		bucket int64
	}
	counts := map[agentBucket]int64{}
	var peak int64
	for _, row := range rows {
		k := agentBucket{agentOrUnknown(row.AgentName), floorDiv(row.CreatedAt*1000, bucketMS)}
		counts[k]++
		if counts[k] > peak {
			peak = counts[k]
		}
	}
	return peak
}

// activitySeries is a fixed-length histogram ending at now: `buckets` slots of
// `bucketMS` each, zero where nothing happened.
//
// The length is fixed by the caller and not by the data, so the sparkline the
// dashboard draws has the same x-axis every refresh.
func activitySeries(rows []store.SecurityScanRow, nowMS, bucketMS int64, buckets int) []activityPoint {
	if buckets < 0 {
		buckets = 0
	}
	start := nowMS - int64(buckets)*bucketMS
	counts := make([]int64, buckets)
	for _, row := range rows {
		t := row.CreatedAt * 1000
		if t < start {
			continue
		}
		idx := (t - start) / bucketMS
		// A row stamped in the future lands past the end. It is dropped rather
		// than folded into the last bucket: created_at is reported by the
		// client, and a clock an hour ahead should not invent a spike.
		if idx >= 0 && idx < int64(buckets) {
			counts[idx]++
		}
	}
	out := make([]activityPoint, 0, buckets)
	for i, c := range counts {
		out = append(out, activityPoint{T: start + int64(i)*bucketMS, Count: c})
	}
	return out
}

// ── shared helpers ──────────────────────────────────────────────────────────

// counter counts by key while remembering the order keys were first seen.
//
// The order is not cosmetic. The live route counts into a JavaScript Map, which
// iterates in insertion order, and then sorts with Array.prototype.sort, which
// is stable — so two agents with the same number of calls come back in the
// order their first call was scanned. Counting into a bare Go map would give
// them a different order on every request and the panel would reshuffle itself
// while somebody was reading it.
type counter[K comparable] struct {
	order []K
	count map[K]int64
}

func newCounter[K comparable]() *counter[K] {
	return &counter[K]{count: map[K]int64{}}
}

func (c *counter[K]) add(key K, n int64) {
	if _, seen := c.count[key]; !seen {
		c.order = append(c.order, key)
	}
	c.count[key] += n
}

// agentOrUnknown is the live route's `r.agent || 'unknown'`. An audit row can
// have no agent name — the hook that wrote it predates agent identity — and
// those calls are still somebody's traffic, so they are counted under one
// bucket rather than dropped.
func agentOrUnknown(name string) string {
	if name == "" {
		return unknownAgent
	}
	return name
}

// statsDays reads `?days=`, as /stats/drift and /stats/security-insights both
// do: an integer, clamped to 1..90.
//
// The clamp is the DoS ceiling on these two routes and the reason the number is
// not simply trusted: 90 days is the widest scan of audit_logs this service
// will perform for one request.
//
// The live routes reach `parseInt('abc')` as NaN and hand that to the query,
// which fails somewhere below and answers 500. That is not reproduced: an
// unparseable value takes the default of seven, because a 500 for a typo in a
// query string sends the caller looking for a fault in this service.
func statsDays(r *http.Request) int {
	return boundInt(queryIntDefault(r.URL.Query().Get("days"), defaultStatsDays), 1, maxStatsDays)
}

const (
	defaultStatsDays = 7
	maxStatsDays     = 90
)

// floorDiv divides toward negative infinity, which is what Math.floor does and
// what Go's `/` does not.
//
// It matters at exactly one place per caller and it is always the same place: a
// timestamp before 1970 is negative, and truncation toward zero would put it in
// the bucket AFTER the one it belongs to. Those timestamps are reachable —
// created_at is a number the reporting client chose.
func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}

// jsRound is Math.round: halves go UP, towards positive infinity. Go's
// math.Round takes them AWAY from zero, so the two disagree on every negative
// half — and delta_pct is negative every time a rule fires less than it used
// to, which is the case somebody is usually looking at.
func jsRound(v float64) int64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return int64(math.Floor(v + 0.5))
}
