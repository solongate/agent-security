package main

// A lighter audit row, for the callers that aggregate rather than read.
//
// WHY THIS EXISTS, AND IT IS NOT AN OPTIMISATION.
//
// The home page builds its breakdowns — the busiest tools, the hour heatmap,
// the recent list, the trend against the period before — by reading a WINDOW of
// rows and counting them in Go. It needs six fields per row. The route hands it
// twenty-nine, four of which are raw JSON with no small bound: arguments_summary
// alone is capped at sixteen kilobytes.
//
// Five thousand of those rows, twice per page load, went past the eight
// megabyte ceiling the dashboard's HTTP client reads to. io.LimitReader does
// not fail when a body is longer than the limit, it just stops, so the client
// got a truncated document, json.Unmarshal refused it, and the page rendered
// "The API sent a response this page could not read." on a project with a
// month of ordinary traffic in it.
//
// The honest fix is not a bigger ceiling. It is not sending fields nobody asked
// for: a caller that says what it needs gets a row about ten times smaller, and
// the ceiling stops being reachable at all.
//
// WHAT slim DROPS, and why each one is safe to drop for an aggregating reader:
//
//	matched_rule        the resolved rule document, fetched per row.
//	pi_categories       prompt-injection detail, two raw JSON blobs.
//	pi_stage_scores
//	arguments_summary   the payload, and the big one — but ONLY on calls that
//	                    were ALLOWED. See below.
//
// Everything a count is grouped by stays: the tool, the decision, the
// permission, the agent, the time, the reason, the DLP hit names and the burst
// flag.
//
// THE ARGUMENTS ARE KEPT ON REFUSALS, and that is not a hedge.
//
// The page reads an argument for exactly one purpose: to say WHAT was refused,
// the command or the path or the URL, on the list of what is being blocked.
// Dropping the field outright would have emptied that column silently, which is
// the failure this whole file is a fix for wearing different clothes.
//
// Refusals are a small fraction of any healthy fleet — a real project here is
// 705 denials in 29,502 calls — so keeping the payload on them costs a couple
// of percent of the rows and preserves the one thing the page does with it.

import (
	"net/http"
	"strings"
)

// auditSlimRequested reports whether this caller asked for the light shape.
//
// Opt-IN rather than opt-out, deliberately. Deployed clients read these fields,
// and a route that quietly stopped sending them would break an audit page
// somewhere with no error anywhere: the fields would simply be empty. So the
// caller that can do without them says so.
func auditSlimRequested(r *http.Request) bool {
	v := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("slim")))
	return v == "1" || v == "true" || v == "yes"
}

// slimAuditEntries strips the heavy fields from rows already built.
//
// It runs after the rows are assembled rather than instead of assembling them,
// which costs a little work that is then thrown away and buys one mapping of a
// row instead of two. Two mappings is how a field ends up present in one shape
// and missing from the other, which is the bug the shared builder exists to
// prevent.
func slimAuditEntries(in []auditListEntry) []auditListEntry {
	for i := range in {
		in[i].MatchedRule = nil
		in[i].PiCategories = nil
		in[i].PiStageScores = nil
		if strings.EqualFold(in[i].Decision, "ALLOW") {
			in[i].ArgumentsSummary = nil
		}
	}
	return in
}
