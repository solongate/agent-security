package main

import (
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/policyeval"
	"github.com/codeyevsky/solongate/system/internal/policyjson"
)

// POST /api/v1/policies/dry-run and POST /api/v1/policies/backtest.
//
// Both replay this project's own audit history against a set of candidate rules
// and report what would have changed. They are the "what will this break"
// button in the rule editor, and they are the only routes in this group that
// read audit_logs.
//
// Two things about them are security-relevant rather than cosmetic. The sample
// is bounded — five thousand rows, the live ceiling — because an unbounded
// replay is a way to ask this service to stream a million rows out of Turso
// with a valid key. And nothing in the request names a project: the rows come
// from the key's project and the `from`/`to` window is the only filter a caller
// controls.

// policyReplayRequest is the shared body. `rules` stays a decoded JSON value
// rather than a typed rule, because the dashboard posts partial rules while the
// editor is open and a strict decode would reject a draft.
type policyReplayRequest struct {
	rules []policyeval.Rule
	mode  string
	limit int
	since int64
	until int64
	test  *policyjson.Object
}

func (s *server) policyDryRun(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	req, ok := policyReadReplayRequest(w, r)
	if !ok {
		return
	}

	inputs, err := s.policyReplayInputs(r, key, req)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	result := policyeval.RunDryRun(req.rules, req.mode, inputs)

	// `{...result, mode, sampled, limit}`: the three trailing fields describe
	// the SAMPLE, not the policy, and the dashboard shows them as "evaluated
	// against N of the last M calls".
	apiauth.JSON(w, http.StatusOK, struct {
		policyeval.DryRunResult
		Mode    string `json:"mode"`
		Sampled int    `json:"sampled"`
		Limit   int    `json:"limit"`
	}{result, req.mode, len(inputs), req.limit})
}

func (s *server) policyBacktest(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	req, ok := policyReadReplayRequest(w, r)
	if !ok {
		return
	}

	// A `test` object short-circuits the whole replay: one hypothetical call,
	// no history read at all. It is what the rule editor's "try it" field
	// posts, and it answers with `mode: "single"` — a DIFFERENT meaning of
	// `mode` from the denylist/whitelist one in every other response here, and
	// one the CLI branches on.
	if req.test != nil {
		in := policyeval.Input{
			ID:         "manual",
			Tool:       policyjson.Str(req.test.Get("tool")),
			Permission: policyFirstNonEmpty(policyjson.Str(req.test.Get("permission")), "EXECUTE"),
			// Both spellings are accepted because both are in front of
			// deployed clients: the dashboard sends trustLevel and the CLI
			// sends trust_level.
			TrustLevel: policyFirstNonEmpty(
				policyjson.Str(req.test.Get("trustLevel")),
				policyjson.Str(req.test.Get("trust_level")),
				"UNTRUSTED"),
			// The hypothetical call is treated as previously ALLOWED, so a
			// rule that denies it reads as "newly blocked".
			Decision: "ALLOW",
		}
		if args, isObj := req.test.Get("args").(*policyjson.Object); isObj {
			in.Args = args
		}
		single := policyeval.EvaluateSingle(req.rules, req.mode, in)
		apiauth.JSON(w, http.StatusOK, struct {
			Mode string `json:"mode"`
			policyeval.SingleResult
		}{"single", single})
		return
	}

	inputs, err := s.policyReplayInputs(r, key, req)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	result := policyeval.RunBacktest(req.rules, req.mode, inputs)
	apiauth.JSON(w, http.StatusOK, struct {
		Mode    string `json:"mode"`
		Engine  string `json:"engine"`
		Sampled int    `json:"sampled"`
		Limit   int    `json:"limit"`
		policyeval.BacktestResult
	}{"bulk", "estimate", len(inputs), req.limit, result})
}

// policyReadReplayRequest parses the body both routes share. It writes the
// error and returns false on a bad one.
func policyReadReplayRequest(w http.ResponseWriter, r *http.Request) (policyReplayRequest, bool) {
	var req policyReplayRequest

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return req, false
	}
	parsed, err := policyjson.Parse(raw)
	if err != nil {
		// `await request.json()` with no catch, so a malformed body is a 500
		// here rather than a 400: the caller sent nothing wrong.
		apiauth.Internal(w, "api", err)
		return req, false
	}
	body, _ := parsed.(*policyjson.Object)

	rules, isArr := policyeval.ParseRules(body.Get("rules"))
	if !isArr {
		// VALIDATION_ERROR, not the default ERROR code: the dashboard's form
		// branches on it to highlight the field rather than showing a toast.
		apiauth.ValidationError(w, "Missing required field: rules (array)")
		return req, false
	}
	req.rules = rules
	req.mode = policyeval.ParseMode(body.Get("mode"))

	// `Math.min(Math.max(Number(body.limit) || 1000, 1), 5000)`. The `|| 1000`
	// swallows both NaN and zero, so `limit: 0` samples a thousand rows.
	req.limit = 1000
	if n, ok := policyJSNumber(body.Get("limit")); ok && n != 0 && !math.IsNaN(n) {
		req.limit = int(math.Min(math.Max(n, 1), 5000))
	}

	// from/to are MILLISECONDS on the wire and SECONDS in the column: drizzle
	// stores a timestamp as Math.floor(getTime()/1000), so the boundary has to
	// be floored the same way or a window that starts mid-second selects one
	// row too many.
	req.since = policyMillisToSeconds(body.Get("from"))
	req.until = policyMillisToSeconds(body.Get("to"))

	if t, isObj := body.Get("test").(*policyjson.Object); isObj {
		req.test = t
	}
	return req, true
}

// policyReplayInputs is the sample both routes evaluate: this project's newest
// calls inside the window, bounded.
func (s *server) policyReplayInputs(r *http.Request, key apiauth.KeyInfo, req policyReplayRequest) ([]policyeval.Input, error) {
	rows, err := s.store.PolicyReplaySample(r.Context(), key.ProjectID, req.since, req.until, req.limit)
	if err != nil {
		return nil, err
	}

	inputs := make([]policyeval.Input, 0, len(rows))
	for _, row := range rows {
		in := policyeval.Input{
			ID:         row.ID,
			Tool:       row.ToolName,
			Permission: policyFirstNonEmpty(row.Permission, "EXECUTE"),
			TrustLevel: policyFirstNonEmpty(row.TrustLevel, "UNTRUSTED"),
			Decision:   row.Decision,
			Agent:      row.AgentName,
			HasAgent:   row.AgentName != "",
			// The column is seconds; everything downstream works in
			// milliseconds because that is what `new Date(x).getTime()` gives.
			CreatedAtMS: row.CreatedAt * 1000,
		}
		// A summary that will not parse is NULL args, not an error:
		// `try { JSON.parse(...) } catch { args = null }`. Rows written by
		// older hooks carry a plain string there.
		if row.ArgumentsSummary != "" {
			if args, isObj := policyjson.ParseObject([]byte(row.ArgumentsSummary)); isObj {
				in.Args = args
			}
		}
		inputs = append(inputs, in)
	}
	return inputs, nil
}

// policyJSNumber is JavaScript's Number() for the values a JSON body can carry.
//
// A numeric STRING converts, because the dashboard's number inputs post text
// and "1000" has to mean a thousand here as it does there. The conversion is
// WHOLE-string: Number("120abc") is NaN, and a parser that stopped at the first
// non-digit would read a typo as a limit.
func policyJSNumber(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			// Number("") is 0, not NaN.
			return 0, true
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

// policyMillisToSeconds turns a `from`/`to` bound into the column's unit, or 0
// for "no bound".
//
// The guard is `if (body.from)` — a truthiness test, so an explicit 0 is no
// bound at all rather than the epoch. A value that is not a finite number is
// also no bound: the original would build a query around `new Date(NaN)` and
// get nothing, and refusing to filter is the reading that returns the sample
// the caller was asking about.
func policyMillisToSeconds(v any) int64 {
	if !policyjson.Truthy(v) {
		return 0
	}
	ms, ok := policyJSNumber(v)
	if !ok || math.IsNaN(ms) || math.IsInf(ms, 0) {
		return 0
	}
	return int64(math.Floor(ms / 1000))
}
