package policyeval

import (
	"sort"

	"github.com/codeyevsky/solongate/api/internal/store"
)

// The two result shapes, and they are wire contracts rather than internal
// types: the dashboard's Policy Dry Run page reads every field below by name
// and the CLI's `policy backtest` renders the three breakdowns as tables. The
// json tags are the response, so a renamed field is a blank column somewhere.
//
// Every slice is initialised rather than left nil. A nil slice marshals as
// `null` and the pages iterate these without a guard, so an empty history would
// be a crash rather than an empty table.

// Change is one call whose verdict would move. `matched_rule_id` is a pointer
// because null means "no rule matched, the mode decided" and the dashboard
// shows that differently from a rule id.
type Change struct {
	ID            string  `json:"id"`
	Tool          string  `json:"tool"`
	Preview       string  `json:"preview"`
	Original      string  `json:"original"`
	Predicted     string  `json:"predicted"`
	MatchedRuleID *string `json:"matched_rule_id"`
	CreatedAt     string  `json:"created_at"`
}

// DryRunResult is runDryRun's return, plus nothing. The route appends mode,
// sampled and limit around it.
type DryRunResult struct {
	Evaluated     int `json:"evaluated"`
	WouldAllow    int `json:"would_allow"`
	WouldDeny     int `json:"would_deny"`
	NewlyBlocked  int `json:"newly_blocked"`
	NewlyAllowed  int `json:"newly_allowed"`
	Unchanged     int `json:"unchanged"`
	TruncatedArgs int `json:"truncated_args"`

	SampleNewlyBlocked []Change `json:"sample_newly_blocked"`
	SampleNewlyAllowed []Change `json:"sample_newly_allowed"`
}

// dryRunSampleCap and backtestSampleCap are the originals'. They exist because
// a 5000-row replay with every row changed would otherwise put 5000 argument
// previews in one response.
const (
	dryRunSampleCap   = 50
	backtestSampleCap = 200
)

// RunDryRun is src/lib/dry-run.ts's runDryRun.
//
// truncated_args is reported and never incremented, exactly as in the original.
// It is a field the response has always carried; computing something for it
// here would be inventing a number the dashboard has never displayed.
func RunDryRun(rules []Rule, mode string, inputs []Input) DryRunResult {
	res := DryRunResult{
		Evaluated:          len(inputs),
		SampleNewlyBlocked: []Change{},
		SampleNewlyAllowed: []Change{},
	}
	for _, in := range inputs {
		v := EvaluateCandidate(rules, mode, in)
		if v.Effect == "ALLOW" {
			res.WouldAllow++
		} else {
			res.WouldDeny++
		}
		// Note the EXACT comparison. The backtest upper-cases the recorded
		// decision first and this does not, so a row written as "allow" by some
		// older client counts as a denial here and as an allow there. Both
		// behaviours are live and neither is safe to quietly align.
		wasAllow := in.Decision == "ALLOW"
		isAllow := v.Effect == "ALLOW"

		change := Change{
			ID:            in.ID,
			Tool:          in.Tool,
			Preview:       DryRunPreview(in.Tool, in.Args),
			Original:      in.Decision,
			Predicted:     v.Effect,
			MatchedRuleID: ruleIDPtr(v.RuleID),
			CreatedAt:     store.ISOms(in.CreatedAtMS),
		}

		switch {
		case wasAllow && !isAllow:
			res.NewlyBlocked++
			if len(res.SampleNewlyBlocked) < dryRunSampleCap {
				res.SampleNewlyBlocked = append(res.SampleNewlyBlocked, change)
			}
		case !wasAllow && isAllow:
			res.NewlyAllowed++
			if len(res.SampleNewlyAllowed) < dryRunSampleCap {
				res.SampleNewlyAllowed = append(res.SampleNewlyAllowed, change)
			}
		default:
			res.Unchanged++
		}
	}
	return res
}

// ── backtest ────────────────────────────────────────────────────────────────

type BacktestSummary struct {
	Evaluated    int `json:"evaluated"`
	WouldAllow   int `json:"would_allow"`
	WouldDeny    int `json:"would_deny"`
	NewlyBlocked int `json:"newly_blocked"`
	NewlyAllowed int `json:"newly_allowed"`
	Unchanged    int `json:"unchanged"`
}

type PerRule struct {
	RuleID       string `json:"rule_id"`
	Matched      int    `json:"matched"`
	NewlyBlocked int    `json:"newly_blocked"`
	NewlyAllowed int    `json:"newly_allowed"`
}

type PerTool struct {
	Tool         string `json:"tool"`
	Evaluated    int    `json:"evaluated"`
	Changed      int    `json:"changed"`
	NewlyBlocked int    `json:"newly_blocked"`
	NewlyAllowed int    `json:"newly_allowed"`
}

type PerAgent struct {
	Agent        string `json:"agent"`
	Evaluated    int    `json:"evaluated"`
	Changed      int    `json:"changed"`
	NewlyBlocked int    `json:"newly_blocked"`
	NewlyAllowed int    `json:"newly_allowed"`
}

// Bucket's `bucket` is a UNIX timestamp in MILLISECONDS, truncated to a day.
// The page feeds it straight to `new Date(bucket)`, so seconds here would draw
// every point in 1970.
type Bucket struct {
	Bucket       int64 `json:"bucket"`
	Evaluated    int   `json:"evaluated"`
	NewlyBlocked int   `json:"newly_blocked"`
	NewlyAllowed int   `json:"newly_allowed"`
}

// BacktestSample carries `agent` as a pointer: an audit row with no agent name
// is null here, while the per-agent breakdown buckets it under "unknown". The
// original makes exactly that distinction in the same loop.
type BacktestSample struct {
	ID            string  `json:"id"`
	Tool          string  `json:"tool"`
	Agent         *string `json:"agent"`
	Preview       string  `json:"preview"`
	Original      string  `json:"original"`
	Predicted     string  `json:"predicted"`
	MatchedRuleID *string `json:"matched_rule_id"`
	CreatedAt     string  `json:"created_at"`
}

type BacktestResult struct {
	Summary    BacktestSummary  `json:"summary"`
	PerRule    []PerRule        `json:"per_rule"`
	PerTool    []PerTool        `json:"per_tool"`
	PerAgent   []PerAgent       `json:"per_agent"`
	Timeseries []Bucket         `json:"timeseries"`
	Samples    []BacktestSample `json:"samples"`
}

const dayMS = 86_400_000

// RunBacktest is src/lib/backtest.ts's runBacktest.
//
// The three breakdowns are accumulated in INSERTION order and sorted with a
// stable sort, because that is what a JavaScript Map plus Array.sort does. The
// order is visible: it decides which of two equally-affected tools the page
// puts at the top of the list.
func RunBacktest(rules []Rule, mode string, inputs []Input) BacktestResult {
	res := BacktestResult{
		Summary:    BacktestSummary{Evaluated: len(inputs)},
		PerRule:    []PerRule{},
		PerTool:    []PerTool{},
		PerAgent:   []PerAgent{},
		Timeseries: []Bucket{},
		Samples:    []BacktestSample{},
	}

	ruleAgg := newOrdered[PerRule]()
	toolAgg := newOrdered[PerTool]()
	agentAgg := newOrdered[PerAgent]()
	tsAgg := newOrdered[Bucket]()

	for _, in := range inputs {
		v := EvaluateCandidate(rules, mode, in)
		if v.Effect == "ALLOW" {
			res.Summary.WouldAllow++
		} else {
			res.Summary.WouldDeny++
		}

		wasAllow := upper(in.Decision) == "ALLOW"
		isAllow := v.Effect == "ALLOW"
		newlyBlocked := wasAllow && !isAllow
		newlyAllowed := !wasAllow && isAllow
		changed := newlyBlocked || newlyAllowed

		switch {
		case newlyBlocked:
			res.Summary.NewlyBlocked++
		case newlyAllowed:
			res.Summary.NewlyAllowed++
		default:
			res.Summary.Unchanged++
		}

		if v.RuleID != "" {
			e := ruleAgg.get(v.RuleID, func() PerRule { return PerRule{RuleID: v.RuleID} })
			e.Matched++
			bumpFlags(&e.NewlyBlocked, &e.NewlyAllowed, newlyBlocked, newlyAllowed)
			ruleAgg.set(v.RuleID, e)
		}

		tool := in.Tool
		if tool == "" {
			tool = "unknown"
		}
		t := toolAgg.get(tool, func() PerTool { return PerTool{Tool: tool} })
		t.Evaluated++
		if changed {
			t.Changed++
		}
		bumpFlags(&t.NewlyBlocked, &t.NewlyAllowed, newlyBlocked, newlyAllowed)
		toolAgg.set(tool, t)

		agent := in.Agent
		if agent == "" {
			agent = "unknown"
		}
		a := agentAgg.get(agent, func() PerAgent { return PerAgent{Agent: agent} })
		a.Evaluated++
		if changed {
			a.Changed++
		}
		bumpFlags(&a.NewlyBlocked, &a.NewlyAllowed, newlyBlocked, newlyAllowed)
		agentAgg.set(agent, a)

		// Math.floor, so a timestamp before the epoch rounds DOWN into the
		// previous day rather than towards zero. Go's integer division
		// truncates towards zero, which is why this is spelled out.
		bucket := floorDiv(in.CreatedAtMS, dayMS) * dayMS
		key := bucketKey(bucket)
		b := tsAgg.get(key, func() Bucket { return Bucket{Bucket: bucket} })
		b.Evaluated++
		bumpFlags(&b.NewlyBlocked, &b.NewlyAllowed, newlyBlocked, newlyAllowed)
		tsAgg.set(key, b)

		if changed && len(res.Samples) < backtestSampleCap {
			res.Samples = append(res.Samples, BacktestSample{
				ID:            in.ID,
				Tool:          tool,
				Agent:         agentPtr(in),
				Preview:       BacktestPreview(tool, in.Args),
				Original:      in.Decision,
				Predicted:     v.Effect,
				MatchedRuleID: ruleIDPtr(v.RuleID),
				CreatedAt:     store.ISOms(in.CreatedAtMS),
			})
		}
	}

	res.PerRule = ruleAgg.values()
	sort.SliceStable(res.PerRule, func(i, j int) bool {
		a, b := res.PerRule[i], res.PerRule[j]
		if x, y := a.NewlyBlocked+a.NewlyAllowed, b.NewlyBlocked+b.NewlyAllowed; x != y {
			return x > y
		}
		return a.Matched > b.Matched
	})
	res.PerTool = toolAgg.values()
	sort.SliceStable(res.PerTool, func(i, j int) bool {
		a, b := res.PerTool[i], res.PerTool[j]
		if a.Changed != b.Changed {
			return a.Changed > b.Changed
		}
		return a.Evaluated > b.Evaluated
	})
	res.PerAgent = agentAgg.values()
	sort.SliceStable(res.PerAgent, func(i, j int) bool {
		a, b := res.PerAgent[i], res.PerAgent[j]
		if a.Changed != b.Changed {
			return a.Changed > b.Changed
		}
		return a.Evaluated > b.Evaluated
	})
	res.Timeseries = tsAgg.values()
	sort.SliceStable(res.Timeseries, func(i, j int) bool {
		return res.Timeseries[i].Bucket < res.Timeseries[j].Bucket
	})

	return res
}

// EvaluateSingle is backtest.ts's evaluateSingle: one hypothetical call, no
// history. `engine` says which evaluator answered, and it says `js-evaluator`
// because that is the string the dashboard displays and this is the same
// estimator ported, not the real engine.
type SingleResult struct {
	Effect string  `json:"effect"`
	RuleID *string `json:"ruleId"`
	Engine string  `json:"engine"`
}

func EvaluateSingle(rules []Rule, mode string, in Input) SingleResult {
	v := EvaluateCandidate(rules, mode, in)
	return SingleResult{Effect: v.Effect, RuleID: ruleIDPtr(v.RuleID), Engine: "js-evaluator"}
}

// ── small helpers ───────────────────────────────────────────────────────────

func bumpFlags(blocked, allowed *int, newlyBlocked, newlyAllowed bool) {
	if newlyBlocked {
		*blocked++
	}
	if newlyAllowed {
		*allowed++
	}
}

func ruleIDPtr(id string) *string {
	if id == "" {
		return nil
	}
	return &id
}

func agentPtr(in Input) *string {
	if !in.HasAgent {
		return nil
	}
	a := in.Agent
	return &a
}

func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}

func bucketKey(ms int64) string {
	// A string key so one ordered container serves all four aggregations. The
	// value carries the number; this only has to be unique per bucket.
	const digits = "0123456789"
	neg := ms < 0
	if neg {
		ms = -ms
	}
	var buf [24]byte
	i := len(buf)
	for {
		i--
		buf[i] = digits[ms%10]
		ms /= 10
		if ms == 0 {
			break
		}
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ordered is a map that remembers insertion order, which is what a JavaScript
// Map does and what the sorts above rely on for their tie-breaks.
type ordered[T any] struct {
	keys []string
	vals map[string]T
}

func newOrdered[T any]() *ordered[T] { return &ordered[T]{vals: map[string]T{}} }

func (o *ordered[T]) get(key string, zero func() T) T {
	if v, ok := o.vals[key]; ok {
		return v
	}
	return zero()
}

func (o *ordered[T]) set(key string, v T) {
	if _, ok := o.vals[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = v
}

func (o *ordered[T]) values() []T {
	out := make([]T, 0, len(o.keys))
	for _, k := range o.keys {
		out = append(out, o.vals[k])
	}
	return out
}
