package api

// The rest of the fleet: groups, the policies they run, the people in them, and
// the reports the whole arrangement produces.
//
// FleetAPI in resources.go is the original half — invitations, seats, accept
// and decline — which was the whole feature when a fleet was a list of people
// pinned to a variant. It is not any more: a host lays out groups, gives a
// group a policy, and excepts one person from it, and none of that had a call
// here at all.
//
// Nothing in this file computes. Which policy somebody enforces is resolved on
// the server, by the same endpoint the guard on their laptop polls, and a
// second implementation of that resolution in a terminal is a second answer
// that can disagree with the one actually in force.

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// FleetGroup is one label a host has put on their fleet.
type FleetGroup struct {
	Name    string `json:"name"`
	Members int    `json:"members"`
	Color   string `json:"color"`
	// PolicyID is what this group's members run. Empty means the group names
	// none and they fall back to the project's own choice.
	//
	// This is what a fleet is for. Everything else about a group is filing.
	PolicyID string `json:"policy_id"`
}

// FleetPerson is one row of the fleet's leaderboard.
type FleetPerson struct {
	GuestUserID string `json:"guest_user_id"`
	Email       string `json:"email"`
	// Role is what this person is TO THIS PROJECT: "host" for the reader,
	// "guest" for everybody holding a grant.
	Role string `json:"role"`
	// IsHost is whether they run a fleet of their OWN, which is a different
	// question and the one a tag on a roster is answering.
	IsHost   bool   `json:"is_host"`
	Group    string `json:"group"`
	Calls    int64  `json:"calls"`
	Denied   int64  `json:"denied"`
	Sessions int64  `json:"sessions"`
	// Tokens is what they spent, and TokenTurns how many turns that was. Both
	// absent means their client does not report — NOT that they spent nothing.
	Tokens     int64  `json:"tokens"`
	TokenTurns int64  `json:"token_turns"`
	LastAt     string `json:"last_at"`
}

// FleetCount is one named row of a breakdown.
type FleetCount struct {
	Name   string `json:"name"`
	Calls  int64  `json:"calls"`
	Denied int64  `json:"denied"`
}

// FleetTokens is what a fleet SPENT, beside what it did.
//
// Reported is what keeps a zero honest: a fleet whose clients cannot report
// tokens has spent nothing MEASURED, which is not the same as having spent
// nothing.
type FleetTokens struct {
	Total    int64 `json:"total"`
	Input    int64 `json:"input"`
	Output   int64 `json:"output"`
	Cache    int64 `json:"cache"`
	Turns    int64 `json:"turns"`
	Reported bool  `json:"reported"`
}

// FleetSummary is everybody's numbers at once.
type FleetSummary struct {
	Developers int `json:"developers"`
	Totals     struct {
		Calls    int64 `json:"calls"`
		Allowed  int64 `json:"allowed"`
		Denied   int64 `json:"denied"`
		Sessions int64 `json:"sessions"`
	} `json:"totals"`
	Agents []FleetCount  `json:"agents"`
	Tools  []FleetCount  `json:"tools"`
	People []FleetPerson `json:"people"`
	Groups []FleetGroup  `json:"groups"`
	Tokens FleetTokens   `json:"tokens"`
	Range  string        `json:"range"`
}

// FleetReport is a span of the fleet's history, summarised.
type FleetReport struct {
	Span     string `json:"span"`
	Title    string `json:"title"`
	Headline string `json:"headline"`
	From     int64  `json:"from"`
	To       int64  `json:"to"`
	Totals   struct {
		Calls      int64 `json:"calls"`
		Allowed    int64 `json:"allowed"`
		Denied     int64 `json:"denied"`
		Sessions   int64 `json:"sessions"`
		Agents     int64 `json:"agents"`
		Tools      int64 `json:"tools"`
		PrevCalls  int64 `json:"prev_calls"`
		PrevDenied int64 `json:"prev_denied"`
	} `json:"totals"`
	TopDenies []FleetCount `json:"top_denies"`
	TopTools  []FleetCount `json:"top_tools"`
	TopAgents []FleetCount `json:"top_agents"`
	People    []struct {
		Label  string `json:"label"`
		Calls  int64  `json:"calls"`
		Denied int64  `json:"denied"`
	} `json:"people"`
}

// ReportSchedule is what is left to configure: one instant.
//
// Reports are not delivered any more — they are FILED when their period closes
// and read off the shelf — so there are no addresses here. EndMinute is where a
// day ends, in minutes past midnight UTC, and it decides which instant divides
// one report from the next.
type ReportSchedule struct {
	EndMinute int `json:"endMinute"`
}

// FleetStreamRow is one call, in full, with the person it belongs to.
//
// It is the SAME shape /audit-logs answers with — every field, not a summary of
// them. The first version of this carried seven columns, and the console built
// on it had no evaluation times, no permission, no DLP hits, no bursts, no
// arguments and no matched rule, while the audit page one key away had all of
// them. A console that shows less than the log it is a view of is a console
// nobody can work from.
type FleetStreamRow struct {
	ID         string  `json:"id"`
	RequestID  string  `json:"request_id"`
	SessionID  *string `json:"session_id"`
	ToolName   string  `json:"tool_name"`
	ServerName *string `json:"server_name"`
	Permission string  `json:"permission"`
	TrustLevel string  `json:"trust_level"`
	Decision   string  `json:"decision"`

	MatchedRuleID *string `json:"matched_rule_id"`
	Reason        *string `json:"reason"`
	// EvaluationTimeMs is how long the guard took to decide. It is the number a
	// host looks for when an agent feels slow, and the one the console was
	// missing entirely.
	EvaluationTimeMs *float64        `json:"evaluation_time_ms"`
	ArgumentsSummary json.RawMessage `json:"arguments_summary"`
	// DLPMatches and RateLimitBurst are DERIVED on the server rather than
	// stored — see the API's audit_signals.go — so they arrive only because the
	// route computes them.
	DLPMatches     []string `json:"dlp_matches"`
	RateLimitBurst bool     `json:"rate_limit_burst"`

	AgentName    *string `json:"agent_name"`
	SubAgentName *string `json:"sub_agent_name"`
	APIKeyName   *string `json:"api_key_name"`

	// CreatedAt is an ISO string on the wire, as everywhere else in this API.
	CreatedAt string `json:"created_at"`

	// UserID and Who are whose call this was. UserID is the account, or the
	// "self" sentinel for the host — whose oldest keys carry no account at all.
	UserID string `json:"user_id"`
	Who    string `json:"who"`
}

// Str reads an optional string field without a nil check at every call site.
func Str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (r FleetStreamRow) Session() string    { return Str(r.SessionID) }
func (r FleetStreamRow) Agent() string      { return Str(r.AgentName) }
func (r FleetStreamRow) ReasonText() string { return Str(r.Reason) }
func (r FleetStreamRow) RuleID() string     { return Str(r.MatchedRuleID) }

// FleetSessionCall is one call inside a session.
type FleetSessionCall struct {
	ID            string          `json:"id"`
	Tool          string          `json:"tool"`
	Decision      string          `json:"decision"`
	Reason        string          `json:"reason"`
	Permission    string          `json:"permission"`
	Agent         string          `json:"agent"`
	Arguments     json.RawMessage `json:"arguments"`
	EvalMs        *float64        `json:"eval_ms"`
	MatchedRuleID string          `json:"matched_rule_id"`
	TrustLevel    string          `json:"trust_level"`
	CreatedAt     string          `json:"created_at"`
}

// FleetTurn is one thing that was SAID in a session — the conversation record.
//
// Redacted and Truncated are not decoration: a transcript that silently dropped
// a secret and one that was cut for length are different records, and a reader
// who cannot tell which they are holding cannot rely on either.
type FleetTurn struct {
	Role      string `json:"role"`
	Body      string `json:"body"`
	Agent     string `json:"agent"`
	Redacted  bool   `json:"redacted"`
	Truncated bool   `json:"truncated"`
	CreatedAt string `json:"created_at"`
}

// FleetSession is one sitting: what was called, and what was said while it ran.
type FleetSession struct {
	GuestUserID string             `json:"guest_user_id"`
	SessionID   string             `json:"session_id"`
	Calls       []FleetSessionCall `json:"calls"`
	// Turns is the transcript. The server's key is `turns`; a field tagged
	// `said` decoded every conversation as empty — a transcript screen that
	// works perfectly and shows nothing.
	Turns []FleetTurn `json:"turns"`
	// Tokens is what each exchange COST, in the same timeline as the words. A
	// conversation is where "why did this cost so much" is actually asked.
	Tokens []FleetSpend `json:"tokens"`
	// Spend is the whole sitting. Reported keeps a zero honest.
	Spend struct {
		Total    int64 `json:"total"`
		Turns    int   `json:"turns"`
		Reported bool  `json:"reported"`
	} `json:"spend"`
}

// FleetSpend is one exchange's cost.
type FleetSpend struct {
	Total     int64  `json:"total"`
	Input     int64  `json:"input"`
	Output    int64  `json:"output"`
	Cache     int64  `json:"cache"`
	Source    string `json:"source"`
	CreatedAt string `json:"created_at"`
}

// FiledReport is one report already on the shelf: written when its period
// closed and kept as it was.
type FiledReport struct {
	ID       string `json:"id"`
	Span     string `json:"span"`
	From     int64  `json:"from"`
	To       int64  `json:"to"`
	Title    string `json:"title"`
	Headline string `json:"headline"`
	Calls    int64  `json:"calls"`
	Denied   int64  `json:"denied"`
	People   int64  `json:"people"`
	Tokens   int64  `json:"tokens"`
	FiledAt  int64  `json:"filed_at"`
}

// FiledReports is this project's shelf, newest first.
func (f FleetAPI) FiledReports(ctx context.Context) ([]FiledReport, error) {
	var out struct {
		Reports []FiledReport `json:"reports"`
	}
	return out.Reports, f.c.get(ctx, "/fleet/reports/filed", nil, &out)
}

// FiledReportFile is one of them, exactly as it was filed — not rebuilt, which
// is the whole point of keeping it.
func (f FleetAPI) FiledReportFile(ctx context.Context, id, format string) ([]byte, error) {
	var out []byte
	err := f.c.Do(ctx, "GET", "/fleet/reports/filed/download",
		RequestOptions{Query: url.Values{"id": {id}, "format": {format}}, Raw: true}, &out)
	return out, err
}

// SessionFile is one sitting as a document: the whole timeline, kept.
func (f FleetAPI) SessionFile(ctx context.Context, guest, session, format string) ([]byte, error) {
	var out []byte
	err := f.c.Do(ctx, "GET", "/fleet/session/download", RequestOptions{
		Query: url.Values{"guest": {guest}, "session": {session}, "format": {format}},
		Raw:   true,
	}, &out)
	return out, err
}

// Summary is the whole fleet's numbers over a range.
func (f FleetAPI) Summary(ctx context.Context, rng string) (FleetSummary, error) {
	q := url.Values{}
	if rng != "" {
		q.Set("range", rng)
	}
	var out FleetSummary
	return out, f.c.get(ctx, "/fleet/summary", q, &out)
}

// Groups is every label, INCLUDING the empty ones.
//
// An empty group cannot be derived from its members, and it is exactly the
// group a host has just created and is about to fill.
func (f FleetAPI) Groups(ctx context.Context) ([]FleetGroup, error) {
	var out struct {
		Groups []FleetGroup `json:"groups"`
	}
	if err := f.c.get(ctx, "/fleet/groups", nil, &out); err != nil {
		return nil, err
	}
	return out.Groups, nil
}

// HostGroup is the reader's own label. It is not on any invitation row: they
// hold no grant, so it arrives beside the list rather than in it.
func (f FleetAPI) HostGroup(ctx context.Context) (string, error) {
	var out struct {
		HostGroup string `json:"host_group"`
	}
	return out.HostGroup, f.c.get(ctx, "/fleet", nil, &out)
}

func (f FleetAPI) CreateGroup(ctx context.Context, name, color string) error {
	return f.c.post(ctx, "/fleet/groups", map[string]string{"name": name, "color": color}, nil)
}

func (f FleetAPI) RenameGroup(ctx context.Context, name, newName string) error {
	return f.c.post(ctx, "/fleet/groups/rename", map[string]string{"name": name, "new_name": newName}, nil)
}

func (f FleetAPI) SetGroupColor(ctx context.Context, name, color string) error {
	return f.c.post(ctx, "/fleet/groups/color", map[string]string{"name": name, "color": color}, nil)
}

func (f FleetAPI) DeleteGroup(ctx context.Context, name string) error {
	return f.c.post(ctx, "/fleet/groups/delete", map[string]string{"name": name}, nil)
}

// SetGroupPolicy names the policy a whole group runs.
//
// It also clears the per-person exceptions inside that group, which is the
// server's behaviour and is deliberate: naming a policy for a group is the one
// action that means "all of you, this one".
func (f FleetAPI) SetGroupPolicy(ctx context.Context, name, policyID string) error {
	return f.c.post(ctx, "/fleet/groups/policy",
		map[string]string{"name": name, "policy_id": policyID}, nil)
}

// SetUserPolicy is the exception to a group's rule. An empty id takes it back
// off — to their group's policy, not to a permissive one.
func (f FleetAPI) SetUserPolicy(ctx context.Context, ids []string, policyID string) error {
	return f.c.post(ctx, "/fleet/policy",
		map[string]any{"ids": ids, "policy_id": policyID}, nil)
}

// AssignGroup files people under a label. An empty group unfiles them, which is
// the only way back to uncategorized.
func (f FleetAPI) AssignGroup(ctx context.Context, ids []string, group string) error {
	return f.c.post(ctx, "/fleet/group",
		map[string]any{"ids": ids, "group": group}, nil)
}

// FleetSessionRow is one sitting on somebody's profile.
type FleetSessionRow struct {
	ID        string `json:"id"`
	Agent     string `json:"agent"`
	StartedAt string `json:"started_at"`
	EndedAt   string `json:"ended_at"`
	Calls     int64  `json:"calls"`
	Denied    int64  `json:"denied"`
	Tools     int64  `json:"tools"`
}

// FleetDayCount is one bar of the day strip.
type FleetDayCount struct {
	Day    string `json:"day"`
	Calls  int64  `json:"calls"`
	Denied int64  `json:"denied"`
}

// FleetTokenDay is one day's spend, in the same day keys as FleetDayCount.
type FleetTokenDay struct {
	Day    string `json:"day"`
	Tokens int64  `json:"tokens"`
	Turns  int64  `json:"turns"`
}

// FleetAnalytics is one person, in full — the same answer the dashboard's
// developer page is drawn from.
//
// It used to be decoded as map[string]any and had no caller at all, which is
// why the terminal could show a roster of people and nothing whatsoever about
// any of them.
type FleetAnalytics struct {
	GuestUserID string `json:"guest_user_id"`
	Totals      struct {
		Calls    int64  `json:"calls"`
		Allowed  int64  `json:"allowed"`
		Denied   int64  `json:"denied"`
		Sessions int64  `json:"sessions"`
		Tools    int64  `json:"tools"`
		Agents   int64  `json:"agents"`
		FirstAt  string `json:"first_at"`
		LastAt   string `json:"last_at"`
	} `json:"totals"`
	Agents      []FleetCount      `json:"agents"`
	Tools       []FleetCount      `json:"tools"`
	Permissions []FleetCount      `json:"permissions"`
	Denies      []FleetCount      `json:"denies"`
	ByHour      []int64           `json:"by_hour"`
	ByDay       []FleetDayCount   `json:"by_day"`
	Sessions    []FleetSessionRow `json:"sessions"`
	// Signals are the layers that have stopped this person. The DLP and
	// rate-limit counts are derived from denial reasons on the server; the
	// injection ones are stored columns.
	Signals struct {
		DLPDenials       int64 `json:"dlp_denials"`
		RateLimitDenials int64 `json:"ratelimit_denials"`
		InjectionSeen    int64 `json:"injection_seen"`
		InjectionBlocked int64 `json:"injection_blocked"`
	} `json:"signals"`
	// What their work cost, in total and per day.
	Tokens          FleetTokens     `json:"tokens"`
	TokensByDay     []FleetTokenDay `json:"tokens_by_day"`
	DaysActive      int64           `json:"days_active"`
	LongestSessionS int64           `json:"longest_session_sec"`
	AvgCallsPerSes  float64         `json:"avg_calls_session"`
	HoursTimezone   string          `json:"hours_timezone"`
	Range           string          `json:"range"`
}

// Analytics is one person in full. guest is an account id, or "self" for the
// host — who holds no grant and so cannot be scoped the way a guest is.
func (f FleetAPI) Analytics(ctx context.Context, guest, rng string) (FleetAnalytics, error) {
	q := url.Values{"guest": {guest}}
	if rng != "" {
		q.Set("range", rng)
	}
	var out FleetAnalytics
	return out, f.c.get(ctx, "/fleet/analytics", q, &out)
}

// Report is a span of the fleet's history.
func (f FleetAPI) Report(ctx context.Context, span string) (FleetReport, error) {
	if span == "" {
		span = "day"
	}
	var out FleetReport
	return out, f.c.get(ctx, "/fleet/report", url.Values{"span": {span}}, &out)
}

// ReportFile is the same report as the document the dashboard downloads.
func (f FleetAPI) ReportFile(ctx context.Context, span, format, me string) ([]byte, error) {
	var out []byte
	err := f.c.Do(ctx, "GET", "/fleet/report/download",
		RequestOptions{Query: reportFileQuery(span, format, "", me), Raw: true}, &out)
	return out, err
}

// reportFileQuery is what every downloaded document is asked for by.
//
// `me` is the host'"'"'s own address. The API holds keys and grants rather than
// addresses, so a document it builds unaided calls this person "You (host)" —
// right on a screen, wrong in a file kept for a year beside twenty named after
// people. Every other surface reads that name locally, so every one of them
// passes it here.
func reportFileQuery(span, format, who, me string) url.Values {
	q := url.Values{"span": {span}}
	if format != "" {
		q.Set("format", format)
	}
	if who != "" {
		q.Set("who", who)
	}
	if me = strings.TrimSpace(me); me != "" {
		q.Set("me", me)
	}
	return q
}

// PersonReportFile is ONE account's report, in full.
//
// The guest id is the API's own, and the API resolves it against the roster
// before it builds anything — so a stale id from a console that has not
// refreshed reads as "not on this fleet" rather than as an empty report.
func (f FleetAPI) PersonReportFile(ctx context.Context, guest, span, format, me string) ([]byte, error) {
	var out []byte
	err := f.c.Do(ctx, "GET", "/fleet/report/download", RequestOptions{
		Query: reportFileQuery(span, format, guest, me),
		Raw:   true,
	}, &out)
	return out, err
}

// ReportBundle is everybody's report and the fleet's, as one zip.
//
// It is one request rather than a loop over the roster because the archive is
// assembled server-side: a console that fetched thirty reports and zipped them
// would be a second implementation of the same document, and the two would
// drift the first time either side changed.
func (f FleetAPI) ReportBundle(ctx context.Context, span, me string) ([]byte, error) {
	var out []byte
	q := reportFileQuery(span, "", "", me)
	q.Set("bundle", "1")
	err := f.c.Do(ctx, "GET", "/fleet/report/download", RequestOptions{Query: q, Raw: true}, &out)
	return out, err
}

func (f FleetAPI) ReportSchedule(ctx context.Context) (ReportSchedule, int64, error) {
	var out struct {
		Schedule ReportSchedule `json:"schedule"`
		Next     int64          `json:"next"`
	}
	err := f.c.get(ctx, "/settings/reports", nil, &out)
	return out.Schedule, out.Next, err
}

// SetReportSchedule sends only the fields given, because the server treats an
// absent key as "leave it alone" — so toggling one span cannot silently reset
// the addresses beside it.
func (f FleetAPI) SetReportSchedule(ctx context.Context, patch map[string]any) error {
	return f.c.put(ctx, "/settings/reports", patch, nil)
}

// FleetStreamQuery is how a console narrows the stream ON THE SERVER.
//
// Filtering only what a console has already seen answers a smaller question
// than the one asked: "every Bash call" becomes "every Bash call since I opened
// this". Every field here is one the store has always been able to apply and
// the route was not forwarding.
type FleetStreamQuery struct {
	Limit int
	// Guest is an account id, or "self" for the host — who is scoped by
	// elimination on the server, because their oldest keys carry no account.
	Guest    string
	Session  string
	Tool     string
	Agent    string
	Decision string
	Search   string
	// From and To bound the window. Zero means unbounded on that side.
	From, To time.Time
	Offset   int
}

// Values is the query as the wire carries it. Exported so a caller can assert
// what it is about to send — which filters reach the server is the difference
// between narrowing a record and narrowing a screenful.
func (q FleetStreamQuery) Values() url.Values {
	v := url.Values{}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	if q.Guest != "" {
		v.Set("guest", q.Guest)
	}
	if q.Session != "" {
		v.Set("session_id", q.Session)
	}
	if q.Tool != "" {
		v.Set("tool", q.Tool)
	}
	if q.Agent != "" {
		v.Set("agent_name", q.Agent)
	}
	if q.Decision != "" {
		v.Set("filter", q.Decision)
	}
	if q.Search != "" {
		v.Set("search", q.Search)
	}
	if !q.From.IsZero() {
		v.Set("from", strconv.FormatInt(q.From.UnixMilli(), 10))
	}
	if !q.To.IsZero() {
		v.Set("to", strconv.FormatInt(q.To.UnixMilli(), 10))
	}
	if q.Offset > 0 {
		v.Set("offset", strconv.Itoa(q.Offset))
	}
	return v
}

// Stream is the fleet's recent calls, newest first, each with the person it
// belongs to, narrowed by whatever the query names.
func (f FleetAPI) Stream(ctx context.Context, q FleetStreamQuery) ([]FleetStreamRow, error) {
	var out struct {
		Calls []FleetStreamRow `json:"calls"`
	}
	if err := f.c.get(ctx, "/fleet/stream", q.Values(), &out); err != nil {
		return nil, err
	}
	return out.Calls, nil
}

// History is the same stream over a WINDOW rather than the tail.
//
// The live console accumulates while it is open and knows nothing about what
// happened before that; this is how it answers "what happened at nine". The
// narrowing rides along, so widening the window does not also widen the
// question.
func (f FleetAPI) History(ctx context.Context, q FleetStreamQuery, from time.Time) ([]FleetStreamRow, error) {
	q.From = from
	return f.Stream(ctx, q)
}

// Session is one sitting in full: its calls in order, and the transcript of
// what was said while they ran.
//
// This is the conversation record. It is best-effort on the server — turns
// expire on a schedule and a session from before the record existed has none —
// so an empty transcript is a normal answer and not an error.
func (f FleetAPI) Session(ctx context.Context, guest, session string) (FleetSession, error) {
	var out FleetSession
	return out, f.c.get(ctx, "/fleet/session",
		url.Values{"guest": {guest}, "session": {session}}, &out)
}
