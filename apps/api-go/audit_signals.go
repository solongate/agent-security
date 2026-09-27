package main

import (
	"context"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/codeyevsky/solongate/api/internal/store"
)

// The two signals the audit list shows that are NOT columns.
//
// `dlp_matches` and `rate_limit_burst` are derived on every read, and the
// reason is worth stating because it looks like a missing migration: when DLP
// is in BLOCK mode the guard stops the call before the secret is ever sent
// here, and when it is in DETECT mode the value that reaches us is already
// masked. There is no moment at which this service holds the secret to record a
// flag about it. So the evidence is indirect, and there are three kinds of it,
// tried in order — a re-scan of what was stored, the redactor's own marker, and
// the denial reason the guard wrote.
//
// The rate-limit signal is the same shape of problem from the other end: a
// burst is a property of the MINUTE a call landed in, not of the call, so it
// cannot be a column on the row either.

// ── DLP ─────────────────────────────────────────────────────────────────────

// dlpScanner is a project's enabled patterns, compiled once per request.
type dlpScanner struct {
	patterns []compiledPattern
}

type compiledPattern struct {
	name string
	re   *regexp.Regexp
}

// maxDLPHits is the live route's cap. Five names is what the badge has room
// for, and a summary that matches fourteen patterns is a secret dump, not a
// list to enumerate.
const maxDLPHits = 5

// newDLPScanner compiles the built-ins a project has enabled, then its custom
// patterns.
//
// A pattern that will not compile is SKIPPED, not fatal. The custom ones are
// typed by a user into a settings form and a broken one must cost that one
// detector, not the whole audit page. Go's RE2 also refuses some expressions
// JavaScript accepts — lookahead, backreferences — so a custom pattern that
// works in the guard can land here and not compile; that is the same outcome as
// the live app's try/catch and the same visible result.
func newDLPScanner(layers store.SecurityLayers) *dlpScanner {
	enabled := map[string]bool{}
	for _, n := range layers.DLP.Patterns {
		enabled[n] = true
	}

	s := &dlpScanner{}
	for _, p := range store.DLPPatterns {
		if !enabled[p.Name] {
			continue
		}
		expr := p.Re
		if p.CI {
			expr = "(?i)" + expr
		}
		if re, err := regexp.Compile(expr); err == nil {
			s.patterns = append(s.patterns, compiledPattern{name: p.Name, re: re})
		}
	}
	for _, c := range layers.DLP.Custom {
		if re, err := regexp.Compile(c.Re); err == nil {
			s.patterns = append(s.patterns, compiledPattern{name: c.Name, re: re})
		}
	}
	return s
}

// scan re-runs the patterns over what was stored.
//
// This finds a secret only when nothing removed it first, which is the
// detect-mode-with-no-redaction case. It is tried first because it is the only
// one that names the pattern with certainty.
func (s *dlpScanner) scan(summary string) []string {
	if summary == "" || len(s.patterns) == 0 {
		return nil
	}
	var hits []string
	for _, p := range s.patterns {
		if !p.re.MatchString(summary) {
			continue
		}
		if !slices.Contains(hits, p.name) {
			hits = append(hits, p.name)
			if len(hits) >= maxDLPHits {
				break
			}
		}
	}
	return hits
}

// redactionMarker is what the redactor leaves behind: `[REDACTED:Anthropic key]`.
var redactionMarker = regexp.MustCompile(`\[REDACTED:([^\]]*)\]`)

// dlpFromRedaction reads the marker.
//
// This is the case that used to read as clean and was the worst one to lose: a
// REDACTED hit leaves no secret to re-scan and no denial to quote, because the
// call was allowed and the value was masked. The one mode where DLP does its
// job silently was the one mode nothing recorded. The marker carries the
// pattern name, so it is the evidence.
func dlpFromRedaction(summary string) []string {
	if summary == "" {
		return nil
	}
	var names []string
	for _, m := range redactionMarker.FindAllStringSubmatch(summary, -1) {
		n := strings.TrimSpace(m[1])
		if n == "" || slices.Contains(names, n) {
			continue
		}
		names = append(names, n)
		if len(names) >= maxDLPHits {
			break
		}
	}
	return names
}

var (
	dlpReasonPrefix = regexp.MustCompile(`(?i)security layer \(dlp\)`)
	dlpReasonName   = regexp.MustCompile(`(?i)contain(?:s)? (?:a |an )?(.+?)(?:\.|$)`)
)

// dlpFromReason is the last resort: the guard BLOCKED the call, so the value
// never arrived, and the reason it wrote is the only record that a secret was
// involved — "Security layer (DLP): blocked - arguments contain a Anthropic
// key". The pattern name is pulled back out of that sentence.
func dlpFromReason(reason string) []string {
	if reason == "" || !dlpReasonPrefix.MatchString(reason) {
		return nil
	}
	if m := dlpReasonName.FindStringSubmatch(reason); m != nil {
		return []string{strings.TrimSpace(m[1])}
	}
	return []string{"DLP"}
}

// dlpMatchesOf is the three sources in order. The first that finds anything
// wins; a row with no evidence gets an empty array rather than null, because
// the dashboard maps over it.
func (s *dlpScanner) dlpMatchesOf(summary, reason string) []string {
	if hits := s.scan(summary); len(hits) > 0 {
		return hits
	}
	if hits := dlpFromRedaction(summary); len(hits) > 0 {
		return hits
	}
	if hits := dlpFromReason(reason); len(hits) > 0 {
		return hits
	}
	return []string{}
}

// ── rate-limit bursts ───────────────────────────────────────────────────────

// burstIndex is the set of (agent, minute) buckets that went over the limit.
type burstIndex struct {
	keys map[string]bool
}

// unknownAgent is the bucket an entry with no agent name falls into. It is the
// live app's literal and it is shared by every anonymous caller, which is
// deliberate: a client that reports no identity should not get an unlimited
// budget by omitting one.
const unknownAgent = "unknown"

func burstKey(agentName string, createdAtSec int64) string {
	if agentName == "" {
		agentName = unknownAgent
	}
	// The minute is floor(ms / 60000) in the live app, over a millisecond
	// timestamp. Stored seconds divide to the same bucket.
	return agentName + "|" + strconv.FormatInt(createdAtSec/60, 10)
}

func (b *burstIndex) has(agentName string, createdAtSec int64) bool {
	if b == nil || len(b.keys) == 0 {
		return false
	}
	return b.keys[burstKey(agentName, createdAtSec)]
}

// buildBurstIndex counts calls per agent per minute across the time span the
// given rows cover, and marks the minutes that exceeded the limit in force AT
// THE TIME.
//
// The span is re-queried rather than counted from the rows in hand, because the
// rows in hand are a FILTERED page: a page showing one tool's three calls in a
// minute that actually carried three hundred would show no burst at all. That
// is also why this is a second query and not something the page query can do.
//
// The limit is historical. A project that lowered its limit yesterday must not
// have last week's traffic re-judged against today's number, or every old row
// lights up red — hence limitAt, walking the recorded changes.
func buildBurstIndex(ctx context.Context, st *store.Store, projectID string,
	layers store.SecurityLayers, history []store.RateLimitChange, rows []store.AuditLog) (*burstIndex, error) {

	empty := &burstIndex{keys: map[string]bool{}}
	if len(rows) == 0 {
		return empty, nil
	}
	// No limit configured and none ever recorded means there is nothing a burst
	// could be measured against.
	if layers.RateLimit.Mode == store.LayerOff && len(history) == 0 {
		return empty, nil
	}

	lo, hi := rows[0].CreatedAt, rows[0].CreatedAt
	for _, r := range rows[1:] {
		if r.CreatedAt < lo {
			lo = r.CreatedAt
		}
		if r.CreatedAt > hi {
			hi = r.CreatedAt
		}
	}

	// Grouped in SQL. This used to pull every row in the window — up to fifty
	// thousand of them — across the wire to count them here, which was the whole
	// cost of a request that returns fifty entries.
	window, err := st.AuditBurstCounts(ctx, projectID, lo, hi)
	if err != nil {
		return nil, err
	}

	counts := map[string]int64{}
	minuteOf := map[string]int64{}
	for _, w := range window {
		// burstKey buckets by created_at/60, and Minute IS that bucket, so any
		// second inside it produces the same key.
		k := burstKey(w.AgentName, w.Minute*60)
		counts[k] += w.Count
		minuteOf[k] = w.Minute
	}

	histAsc := append([]store.RateLimitChange(nil), history...)
	sort.SliceStable(histAsc, func(i, j int) bool { return histAsc[i].TS < histAsc[j].TS })

	out := &burstIndex{keys: map[string]bool{}}
	for k, n := range counts {
		lim := limitAt(minuteOf[k]*60_000, histAsc, layers)
		if lim > 0 && n > lim {
			out.keys[k] = true
		}
	}
	return out, nil
}

// limitAt is the per-minute limit that was in force at a moment.
//
// The history entries carry MILLISECOND timestamps — they are written for a
// dashboard chart that feeds them to `new Date(ts)` — so the argument is in
// milliseconds too, and the conversion happens at the one call site above
// rather than being assumed here.
func limitAt(atMS int64, histAsc []store.RateLimitChange, layers store.SecurityLayers) int64 {
	found := false
	var lim int64
	for _, h := range histAsc {
		if h.TS > atMS {
			break
		}
		lim, found = h.Minute, true
	}
	if found {
		return lim
	}
	if layers.RateLimit.Mode == store.LayerOff {
		return 0
	}
	return layers.RateLimit.PerMinute
}

var rateLimitReason = regexp.MustCompile(`(?i)rate limit`)

// deniedForRateLimit is the second half of the burst flag: a call the guard
// already refused for rate limiting is a burst whatever the counting says,
// because the calls that would have proved it were never made.
func deniedForRateLimit(decision, reason string) bool {
	return decision == "DENY" && rateLimitReason.MatchString(reason)
}
