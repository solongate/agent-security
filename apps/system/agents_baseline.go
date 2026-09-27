package main

import (
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
)

// The port of src/lib/baselining.ts and src/lib/liveness.ts: what "normal"
// means for one agent, and what counts as a departure from it.
//
// None of this is stored on the audit row. A baseline is recomputed from the
// last thousand calls every time the agent page is opened, and the anomalies
// are the difference between that baseline and the newest sixty. The numbers
// therefore have to be reproduced exactly rather than approximated: they are
// persisted into agent_baselines on a `?scan=1`, compared against on the next
// scan, and a drifting formula would report anomalies that are only the port.
//
// Two ordering rules run through this file. Sets keep INSERTION order, because
// knownTools and knownPaths are stored and a set iterated in Go's map order
// would rewrite the same baseline differently on every scan. And ties in the
// character assignment resolve the way the original's if/else chain resolves
// them, which is not the way a "pick the largest" would.

// The argument keys a path or a URL can hide behind. They are the live app's
// two lists, and they are read in order — the first key present wins.
var (
	pathArgKeys = []string{"file_path", "path", "notebook_path", "dir", "directory"}
	urlArgKeys  = []string{"url", "uri", "endpoint", "href"}
)

func collectArgs(args map[string]any, keys []string) []string {
	if args == nil {
		return nil
	}
	var out []string
	for _, k := range keys {
		s, ok := args[k].(string)
		if !ok {
			continue
		}
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// dirOf is the containing directory, with Windows separators normalised.
//
// A leading-slash path with one segment ("/etc") keeps the whole string rather
// than becoming "": the live app's `idx <= 0` test, and it matters because ""
// would collapse every root-level path into one known location.
func dirOf(p string) string {
	norm := strings.ReplaceAll(p, `\`, "/")
	i := strings.LastIndex(norm, "/")
	if i <= 0 {
		return norm
	}
	return norm[:i]
}

// hostOf is `new URL(u).host` — host and port, no scheme.
//
// A value that is not an absolute URL is nil, which is what `new URL` throwing
// means in the original. Go's url.Parse is far more permissive and would accept
// a bare file path as a URL with no host, so the scheme and host are both
// required here or a Read of "/etc/passwd" would register as a domain.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Host
}

// baselineCall is one call, reduced to what the baseline reads.
type baselineCall struct {
	id         string
	sessionID  string
	tool       string
	permission string
	decision   string
	args       map[string]any
	piDetected bool
	createdAt  int64 // milliseconds, as the original works in
}

type radarProfile struct {
	Read     float64 `json:"read"`
	Write    float64 `json:"write"`
	Execute  float64 `json:"execute"`
	Network  float64 `json:"network"`
	Complian float64 `json:"compliance"`
}

// agentBaseline is the response shape as well as the computation's result, so
// the json tags are the wire format the dashboard reads.
type agentBaseline struct {
	ToolDistribution map[string]int64 `json:"toolDistribution"`
	PermissionMix    map[string]int64 `json:"permissionMix"`
	KnownPaths       []string         `json:"knownPaths"`
	KnownDomains     []string         `json:"knownDomains"`
	KnownTools       []string         `json:"knownTools"`
	AvgCallsPerHour  float64          `json:"avgCallsPerHour"`
	DenyRate         float64          `json:"denyRate"`
	PiRate           float64          `json:"piRate"`
	SampleSize       int              `json:"sampleSize"`
	Character        string           `json:"character"`
	CharacterBlurb   string           `json:"characterBlurb"`
	TrustScore       int              `json:"trustScore"`
	Radar            radarProfile     `json:"radar"`
}

// The caps on what a baseline remembers. They are the live app's, and they are
// what stops a baseline row from growing without limit: an agent that touches a
// new directory every call would otherwise store a list as long as its history.
const (
	maxKnownPaths   = 200
	maxKnownDomains = 100
)

func computeBaseline(calls []baselineCall) agentBaseline {
	toolDistribution := map[string]int64{}
	permissionMix := map[string]int64{"READ": 0, "WRITE": 0, "EXECUTE": 0, "NETWORK": 0}
	paths := newOrderedSet()
	domains := newOrderedSet()
	tools := newOrderedSet()

	var denies, pis int64
	minT, maxT := int64(math.MaxInt64), int64(math.MinInt64)

	for _, c := range calls {
		toolDistribution[c.tool]++
		tools.add(c.tool)

		perm := strings.ToUpper(c.permission)
		if perm == "" {
			perm = "EXECUTE"
		}
		permissionMix[perm]++

		if strings.ToUpper(c.decision) != "ALLOW" {
			denies++
		}
		if c.piDetected {
			pis++
		}
		for _, p := range collectArgs(c.args, pathArgKeys) {
			paths.add(dirOf(p))
		}
		for _, u := range collectArgs(c.args, urlArgKeys) {
			if h := hostOf(u); h != "" {
				domains.add(h)
			}
		}
		if c.createdAt < minT {
			minT = c.createdAt
		}
		if c.createdAt > maxT {
			maxT = c.createdAt
		}
	}

	n := len(calls)
	// A single call has no span to measure a rate over, so the original calls it
	// one hour; a burst inside one minute is floored at a minute, so a rate is
	// never divided by zero and never becomes infinite.
	spanHours := 1.0
	if n > 1 {
		spanHours = math.Max(float64(maxT-minT)/3_600_000, 1.0/60.0)
	}
	var avgCallsPerHour, denyRate, piRate float64
	if n > 0 {
		avgCallsPerHour = float64(n) / spanHours
		denyRate = float64(denies) / float64(n)
		piRate = float64(pis) / float64(n)
	}

	total := float64(max(1, n))
	radar := radarProfile{
		Read:    float64(permissionMix["READ"]) / total,
		Write:   float64(permissionMix["WRITE"]) / total,
		Execute: float64(permissionMix["EXECUTE"]) / total,
		Network: float64(permissionMix["NETWORK"]) / total,
		// Higher is better here, unlike every other axis: it is the share of
		// calls that were NOT denied.
		Complian: 1 - denyRate,
	}

	character, blurb := assignCharacter(permissionMix, denyRate, piRate, total)

	return agentBaseline{
		ToolDistribution: toolDistribution,
		PermissionMix:    permissionMix,
		KnownPaths:       paths.take(maxKnownPaths),
		KnownDomains:     domains.take(maxKnownDomains),
		KnownTools:       tools.all(),
		AvgCallsPerHour:  avgCallsPerHour,
		DenyRate:         denyRate,
		PiRate:           piRate,
		SampleSize:       n,
		Character:        character,
		CharacterBlurb:   blurb,
		TrustScore:       trustScoreOf(permissionMix, denyRate, piRate, total),
		Radar:            radar,
	}
}

// trustScoreOf is the 0..100 headline number.
//
// The weights say what this product considers risky: a prompt injection costs
// more than a denial, and a habit of executing and reaching the network costs
// something even when nothing has gone wrong.
func trustScoreOf(permissionMix map[string]int64, denyRate, piRate, total float64) int {
	risky := float64(permissionMix["EXECUTE"]+permissionMix["NETWORK"]) / total
	score := 100 - denyRate*50 - piRate*80 - risky*20
	return int(math.Round(math.Max(0, math.Min(100, score))))
}

// assignCharacter names the agent's habit and its temperament.
//
// The archetype chain is a sequence of `>=` tests rather than an argmax, so a
// tie goes to whichever branch is written first: an agent with equal writes and
// executes is a Builder. That is the live behaviour and the label is stored, so
// changing the tie-break would rename agents that had not changed.
func assignCharacter(permissionMix map[string]int64, denyRate, piRate, total float64) (string, string) {
	read := float64(permissionMix["READ"]) / total
	write := float64(permissionMix["WRITE"]) / total
	exec := float64(permissionMix["EXECUTE"]) / total
	net := float64(permissionMix["NETWORK"]) / total

	arch := "Explorer"
	switch {
	case write >= read && write >= exec && write >= net:
		arch = "Builder"
	case exec >= read && exec >= write && exec >= net:
		arch = "Operator"
	case net >= read && net >= write && net >= exec:
		arch = "Networker"
	}

	temper := "Cautious"
	switch {
	case denyRate > 0.25 || piRate > 0.1:
		temper = "Reckless"
	case denyRate > 0.08:
		temper = "Assertive"
	}

	blurbs := map[string]string{
		"Explorer":  "mostly reads and inspects, rarely mutates state",
		"Builder":   "writes and edits files heavily",
		"Operator":  "runs commands and executes processes frequently",
		"Networker": "makes network/fetch calls often",
	}
	temperBlurb := "with very few policy denials"
	switch temper {
	case "Reckless":
		temperBlurb = "with a high rate of blocked or flagged actions"
	case "Assertive":
		temperBlurb = "occasionally hitting policy denials"
	}

	return temper + " " + arch, "This agent " + blurbs[arch] + ", " + temperBlurb + "."
}

// quickCharacter is the same judgement from a session's counters, without the
// call history. It is what the live-agents cards show, where re-reading a
// thousand audit rows per card is not on.
func quickCharacter(read, write, execute, network, denied, total, pi int64) (string, int) {
	t := float64(max(1, int(total)))
	mix := map[string]int64{"READ": read, "WRITE": write, "EXECUTE": execute, "NETWORK": network}
	denyRate := float64(denied) / t
	piRate := float64(pi) / t
	character, _ := assignCharacter(mix, denyRate, piRate, t)
	return character, trustScoreOf(mix, denyRate, piRate, t)
}

// ── anomalies ───────────────────────────────────────────────────────────────

// anomaly is one departure from the baseline.
//
// AuditLogID and SessionID are omitted rather than null when the anomaly is not
// about a single call — a rate spike belongs to a window, not to a row — which
// is what the live route's object literal does by leaving the keys undefined.
type anomaly struct {
	Kind        string         `json:"kind"`
	Severity    string         `json:"severity"`
	Score       float64        `json:"score"`
	Description string         `json:"description"`
	Detail      map[string]any `json:"detail"`
	AuditLogID  string         `json:"auditLogId,omitempty"`
	SessionID   string         `json:"sessionId,omitempty"`
}

// detectAnomalies compares a recent window against the baseline.
//
// Every "first time" test is guarded by the baseline having seen something at
// all: a new tool is only notable once there are known tools, a new path only
// once there are known paths. Without those guards a brand-new agent's first
// call would be reported as an anomaly against a baseline computed from that
// same call.
func detectAnomalies(base agentBaseline, recent []baselineCall) []anomaly {
	out := []anomaly{}
	knownTools := setOf(base.KnownTools)
	knownPaths := setOf(base.KnownPaths)
	knownDomains := setOf(base.KnownDomains)

	var recentDenies, recentPis int
	for _, c := range recent {
		if !knownTools[c.tool] && base.SampleSize > 0 {
			out = append(out, anomaly{
				Kind: "new_tool", Severity: "medium", Score: 0.6,
				Description: "First-time tool use: " + c.tool,
				Detail:      map[string]any{"tool": c.tool},
				AuditLogID:  c.id, SessionID: c.sessionID,
			})
		}
		for _, p := range collectArgs(c.args, pathArgKeys) {
			d := dirOf(p)
			if !knownPaths[d] && len(base.KnownPaths) > 0 {
				out = append(out, anomaly{
					Kind: "new_path", Severity: "low", Score: 0.4,
					Description: "Access to a new location: " + d,
					Detail:      map[string]any{"path": d},
					AuditLogID:  c.id, SessionID: c.sessionID,
				})
			}
		}
		for _, u := range collectArgs(c.args, urlArgKeys) {
			h := hostOf(u)
			if h != "" && !knownDomains[h] && len(base.KnownDomains) > 0 {
				out = append(out, anomaly{
					Kind: "new_domain", Severity: "medium", Score: 0.65,
					Description: "Contact with a new domain: " + h,
					Detail:      map[string]any{"domain": h},
					AuditLogID:  c.id, SessionID: c.sessionID,
				})
			}
		}
		if strings.ToUpper(c.decision) != "ALLOW" {
			recentDenies++
		}
		if c.piDetected {
			recentPis++
		}
	}

	n := float64(max(1, len(recent)))
	recentDenyRate := float64(recentDenies) / n
	recentPiRate := float64(recentPis) / n

	// The absolute counts alongside the rates are what keep this quiet: two
	// denials out of three calls is a 67% rate and means nothing.
	if recentDenyRate > base.DenyRate+0.2 && recentDenies >= 3 {
		out = append(out, anomaly{
			Kind: "deny_spike", Severity: "high", Score: math.Min(1, recentDenyRate),
			Description: fmt.Sprintf("Deny rate spiked to %s%% (baseline %s%%)",
				fixed(recentDenyRate*100, 0), fixed(base.DenyRate*100, 0)),
			Detail: map[string]any{
				"recentDenyRate":   recentDenyRate,
				"baselineDenyRate": base.DenyRate,
				"recentDenies":     recentDenies,
			},
		})
	}
	if recentPiRate > base.PiRate+0.1 && recentPis >= 2 {
		out = append(out, anomaly{
			Kind: "pi_spike", Severity: "high", Score: math.Min(1, recentPiRate),
			Description: "Prompt-injection detections rose to " + fixed(recentPiRate*100, 0) + "%",
			Detail: map[string]any{
				"recentPiRate":   recentPiRate,
				"baselinePiRate": base.PiRate,
				"recentPis":      recentPis,
			},
		})
	}
	if len(recent) >= 2 {
		minT, maxT := recent[0].createdAt, recent[0].createdAt
		for _, c := range recent[1:] {
			if c.createdAt < minT {
				minT = c.createdAt
			}
			if c.createdAt > maxT {
				maxT = c.createdAt
			}
		}
		span := math.Max(float64(maxT-minT)/3_600_000, 1.0/60.0)
		recentRate := float64(len(recent)) / span
		if base.AvgCallsPerHour > 0 && recentRate > base.AvgCallsPerHour*3 && len(recent) >= 10 {
			out = append(out, anomaly{
				Kind: "rate_spike", Severity: "medium",
				Score: math.Min(1, recentRate/(base.AvgCallsPerHour*5)),
				Description: fmt.Sprintf("Call rate %s/h is %sx the baseline",
					fixed(recentRate, 0), fixed(recentRate/base.AvgCallsPerHour, 1)),
				Detail: map[string]any{
					"recentRate":   recentRate,
					"baselineRate": base.AvgCallsPerHour,
				},
			})
		}
	}
	return out
}

// fixed is Number.prototype.toFixed. It is display only — these strings are
// anomaly descriptions — so the half-way rounding rule differing from V8's in
// the last digit is a cosmetic difference and not a behavioural one.
func fixed(v float64, digits int) string {
	return strconv.FormatFloat(v, 'f', digits, 64)
}

// ── liveness ────────────────────────────────────────────────────────────────

// The two windows from src/lib/liveness.ts. They are shared with the dashboard,
// which draws the same three states, so a session that reads as active here has
// to read as active there.
const (
	activeWindowMS = 60_000
	idleWindowMS   = 5 * 60_000
)

// livenessOf is the three-state liveness of a last-seen stamp. lastSeen is in
// SECONDS, as every drizzle timestamp column stores it; the windows are
// milliseconds because that is what the shared constants are.
func livenessOf(lastSeenSec int64, nowMS int64) string {
	age := nowMS - lastSeenSec*1000
	switch {
	case age < activeWindowMS:
		return "active"
	case age < idleWindowMS:
		return "idle"
	default:
		return "deactivated"
	}
}

// ── ordered sets ────────────────────────────────────────────────────────────

// orderedSet is a JavaScript Set: membership plus insertion order.
//
// The order is the whole reason this is not a map. knownTools and knownPaths
// are written into agent_baselines, so a Go map's randomised iteration would
// store a different-looking baseline on every scan of an unchanged agent, and
// any diff of two scans would be noise.
type orderedSet struct {
	seen  map[string]bool
	order []string
}

func newOrderedSet() *orderedSet { return &orderedSet{seen: map[string]bool{}} }

func (s *orderedSet) add(v string) {
	if s.seen[v] {
		return
	}
	s.seen[v] = true
	s.order = append(s.order, v)
}

func (s *orderedSet) all() []string {
	if s.order == nil {
		return []string{}
	}
	return s.order
}

func (s *orderedSet) take(n int) []string {
	if len(s.order) > n {
		return s.order[:n]
	}
	return s.all()
}

func setOf(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, v := range values {
		out[v] = true
	}
	return out
}
