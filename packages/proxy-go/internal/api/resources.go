package api

// One type per namespace, each method the one the commands and the TUI were
// already written against. Every one of them used to be an HTTP call; the names,
// the signatures and the types are unchanged, and what is underneath is two files
// on this machine. See localstore.go.
//
// The TypeScript twin is packages/proxy/src/api-client/*, and the two have to
// agree: they read and write the SAME files, and so does the guard.
//
// ONE FILE MEANS ONE POLICY, and that is the only place the shape of this shows
// its history. A service held many and pinned one as active; a machine holds the
// one it enforces. List answers with it or with nothing, and the operations that
// only make sense among several say so plainly rather than pretending.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// ── /policies ──────────────────────────────────────────────────────────────

type PoliciesAPI struct{ c *Client }

func (p PoliciesAPI) List(ctx context.Context) ([]PolicyListEntry, error) {
	s, err := readStore()
	if err != nil || s.Policy == nil {
		return []PolicyListEntry{}, err
	}
	return []PolicyListEntry{{
		ID:        s.Policy.ID,
		Name:      s.Policy.Name,
		Rules:     s.Policy.Rules,
		Mode:      policyMode(s.Policy),
		Version:   localVersion,
		Hash:      hashOf(s.Policy),
		CreatedBy: "this machine",
		CreatedAt: time.UnixMilli(0).UTC().Format(time.RFC3339Nano),
	}}, nil
}

func policyMode(p *PolicySet) PolicyMode {
	if p.Mode == ModeWhitelist {
		return ModeWhitelist
	}
	return ModeDenylist
}

func detailOf(p *PolicySet) PolicyDetail {
	cp := *p
	cp.Mode = policyMode(p)
	return PolicyDetail{
		PolicySet:   cp,
		VersionMeta: localVersion,
		Hash:        hashOf(p),
		CreatedAtV:  time.UnixMilli(0).UTC().Format(time.RFC3339Nano),
	}
}

// Get fetches the policy. version is ignored: there is no history to read.
func (p PoliciesAPI) Get(ctx context.Context, id string, version int) (PolicyDetail, error) {
	s, err := readStore()
	if err != nil {
		return PolicyDetail{}, err
	}
	if err := resolveID(id, s.Policy); err != nil {
		return PolicyDetail{}, err
	}
	return detailOf(s.Policy), nil
}

// Create refuses when the machine already has a policy, rather than merging or
// overwriting: this is the command somebody runs when they think the machine has
// nothing, and the rules it would replace are being enforced right now.
func (p PoliciesAPI) Create(ctx context.Context, policy PolicySet) (PolicyDetail, error) {
	s, err := readStore()
	if err != nil {
		return PolicyDetail{}, err
	}
	if s.Policy != nil {
		return PolicyDetail{}, errors.New(
			"this machine already has a policy. `solongate policy show local` prints it, " +
				"`solongate policy delete local` removes it.")
	}
	next := policy
	if next.ID == "" {
		next.ID = "local"
	}
	if next.Name == "" {
		next.Name = "local"
	}
	next.Mode = policyMode(&next)
	s.Policy = &next
	s.absent = false
	if err := writeStore(s); err != nil {
		return PolicyDetail{}, err
	}
	return detailOf(&next), nil
}

func (p PoliciesAPI) Update(ctx context.Context, id string, policy PolicySet) (PolicyDetail, error) {
	s, err := readStore()
	if err != nil {
		return PolicyDetail{}, err
	}
	if err := resolveID(id, s.Policy); err != nil {
		return PolicyDetail{}, err
	}
	next := policy
	next.ID = s.Policy.ID
	next.Mode = policyMode(&next)
	s.Policy = &next
	if err := writeStore(s); err != nil {
		return PolicyDetail{}, err
	}
	return detailOf(&next), nil
}

// Remove deletes the rules. THE LAYERS SURVIVE: a rate limit and a DLP
// configuration are not part of the rule list, and deleting rules must not
// quietly switch the DLP scanner off.
func (p PoliciesAPI) Remove(ctx context.Context, id string) error {
	s, err := readStore()
	if err != nil {
		return err
	}
	if err := resolveID(id, s.Policy); err != nil {
		return err
	}
	if !s.Security.empty() || s.SelfProtect != nil {
		s.Policy = nil
		return writeStore(s)
	}
	if err := os.Remove(PolicyPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// RuleSpec is the shorthand a caller sends — deny this command, allow this path —
// and this expands it into a full rule, so two callers cannot produce differently
// shaped rules for the same request.
type RuleSpec struct {
	ToolPattern string   `json:"toolPattern,omitempty"`
	Kind        string   `json:"kind,omitempty"`
	Value       string   `json:"value,omitempty"`
	Effect      string   `json:"effect,omitempty"`
	Permission  []string `json:"permission,omitempty"`
}

// RuleMutation is the answer to any call that adds or changes a rule. Deduped
// says the rule was already there, which is a success, not a failure.
type RuleMutation struct {
	OK            bool        `json:"ok"`
	Deduped       bool        `json:"deduped"`
	Rule          *PolicyRule `json:"rule,omitempty"`
	PolicyID      string      `json:"policy_id"`
	PolicyVersion int         `json:"policy_version,omitempty"`
	Message       string      `json:"message,omitempty"`
}

func constraintsOf(r PolicyRule) string {
	raw, _ := json.Marshal([]any{r.CommandConstraints, r.PathConstraints, r.FilenameConstraints, r.URLConstraints})
	return string(raw)
}

func describeRule(effect string, spec RuleSpec) string {
	verb := "Block"
	if effect == "ALLOW" {
		verb = "Allow"
	}
	switch {
	case spec.Kind == "tool" && spec.Value != "":
		return verb + " the " + spec.Value + " tool"
	case spec.Kind != "" && spec.Value != "":
		return verb + " " + spec.Kind + " " + spec.Value
	default:
		pattern := spec.ToolPattern
		if pattern == "" {
			pattern = "*"
		}
		return verb + " " + pattern
	}
}

func (p PoliciesAPI) AddRule(ctx context.Context, id string, spec RuleSpec) (RuleMutation, error) {
	s, err := readStore()
	if err != nil {
		return RuleMutation{}, err
	}
	if err := resolveID(id, s.Policy); err != nil {
		return RuleMutation{}, err
	}
	rules := append([]PolicyRule(nil), s.Policy.Rules.Items...)

	effect := spec.Effect
	if effect == "" {
		effect = "DENY"
	}
	toolPattern := spec.ToolPattern
	if spec.Kind == "tool" && spec.Value != "" {
		toolPattern = spec.Value
	}
	if toolPattern == "" {
		toolPattern = "*"
	}
	// Highest first, and above whatever is already there: a rule somebody just
	// added is the one they expect to decide the next call.
	priority := 10
	for _, r := range rules {
		if r.Priority >= priority {
			priority = r.Priority + 1
		}
	}

	rule := PolicyRule{
		ID:                nextRuleID(rules),
		Description:       describeRule(effect, spec),
		Effect:            effect,
		Priority:          priority,
		ToolPattern:       toolPattern,
		MinimumTrustLevel: "UNTRUSTED",
		Enabled:           true,
	}
	if len(spec.Permission) > 0 {
		raw, err := json.Marshal(spec.Permission)
		if err != nil {
			return RuleMutation{}, err
		}
		rule.Permission = raw
	}
	if spec.Kind != "" && spec.Kind != "tool" && spec.Value != "" {
		side := "denied"
		if effect == "ALLOW" {
			side = "allowed"
		}
		c := &Constraint{}
		if side == "allowed" {
			c.Allowed = []string{spec.Value}
		} else {
			c.Denied = []string{spec.Value}
		}
		switch spec.Kind {
		case "command":
			rule.CommandConstraints = c
		case "path":
			rule.PathConstraints = &PathConstraint{Allowed: c.Allowed, Denied: c.Denied}
		case "filename":
			rule.FilenameConstraints = c
		case "url":
			rule.URLConstraints = c
		default:
			return RuleMutation{}, fmt.Errorf("unknown rule kind %q", spec.Kind)
		}
	}

	// Deduped by what the rule DOES, not by its generated id.
	for i := range rules {
		if rules[i].Effect == rule.Effect && rules[i].ToolPattern == rule.ToolPattern &&
			constraintsOf(rules[i]) == constraintsOf(rule) {
			existing := rules[i]
			return RuleMutation{OK: true, Deduped: true, Rule: &existing, PolicyID: s.Policy.ID, PolicyVersion: localVersion}, nil
		}
	}

	rules = append(rules, rule)
	// Raw is cleared on purpose: it holds the bytes that ARRIVED, and they no
	// longer describe this list. Keeping them would write the old rules back.
	s.Policy.Rules = Rules{Items: rules}
	if err := writeStore(s); err != nil {
		return RuleMutation{}, err
	}
	return RuleMutation{OK: true, Rule: &rule, PolicyID: s.Policy.ID, PolicyVersion: localVersion}, nil
}

func (p PoliciesAPI) RevokeRule(ctx context.Context, id, ruleID string) (RuleMutation, error) {
	s, err := readStore()
	if err != nil {
		return RuleMutation{}, err
	}
	if err := resolveID(id, s.Policy); err != nil {
		return RuleMutation{}, err
	}
	kept := make([]PolicyRule, 0, len(s.Policy.Rules.Items))
	found := false
	for _, r := range s.Policy.Rules.Items {
		if r.ID == ruleID {
			found = true
			continue
		}
		kept = append(kept, r)
	}
	if !found {
		return RuleMutation{}, fmt.Errorf("no rule %s in this policy. `solongate policy show local` lists them.", ruleID)
	}
	s.Policy.Rules = Rules{Items: kept}
	if err := writeStore(s); err != nil {
		return RuleMutation{}, err
	}
	return RuleMutation{OK: true, PolicyID: s.Policy.ID, PolicyVersion: localVersion}, nil
}

// Active is what the guard would enforce on the next call, read from the same
// file it reads — so this is not a report about what should happen, it is the
// input to what does.
func (p PoliciesAPI) Active(ctx context.Context, agentID string) (ActivePolicy, error) {
	s, err := readStore()
	if err != nil {
		return ActivePolicy{}, err
	}
	l := toLayers(s.Security)
	out := ActivePolicy{
		Policy:                s.Policy,
		Version:               localVersion,
		MatchedBy:             "pinned",
		SelfProtectionEnabled: s.SelfProtect == nil || *s.SelfProtect,
		Security:              &ActivePolicySecurity{},
	}
	if s.Policy != nil {
		out.Hash = hashOf(s.Policy)
	}
	nums := &RateLimitSettings{PerMinute: l.RateLimit.PerMinute, PerHour: l.RateLimit.PerHour, PerDay: l.RateLimit.PerDay}
	switch l.RateLimit.Mode {
	case LayerBlock:
		out.Security.RateLimit = nums
	case LayerDetect:
		out.Security.RateLimitObserve = nums
	}
	custom := make([]json.RawMessage, 0, len(l.DLP.Custom))
	for _, c := range l.DLP.Custom {
		if raw, err := json.Marshal(c); err == nil {
			custom = append(custom, raw)
		}
	}
	if l.DLP.Mode == LayerBlock {
		out.Security.DLPBlock = &DLPSettings{Patterns: l.DLP.Patterns, Custom: custom}
	}
	if l.DLP.Mode != LayerOff {
		out.Security.DLPRedact = &DLPSettings{Patterns: l.DLP.Patterns, Custom: custom}
	}
	if s.Security != nil && s.Security.LocalLogs != nil {
		if raw, err := json.Marshal(s.Security.LocalLogs); err == nil {
			out.Security.LocalLogs = raw
		}
	}
	return out, nil
}

// SetActive has nothing to pin. A service kept several policies and chose one;
// the file IS the choice. Saying so beats accepting the call and changing
// nothing, which is what a no-op would do to `solongate policy activate`.
func (p PoliciesAPI) SetActive(ctx context.Context, policyID string) error {
	if policyID == "" {
		return errors.New(
			"nothing to switch off: enforcement is this machine's policy file. " +
				"`solongate policy delete local` stops it, or set every rule to disabled.")
	}
	s, err := readStore()
	if err != nil {
		return err
	}
	return resolveID(policyID, s.Policy)
}

// ── /settings ──────────────────────────────────────────────────────────────

type SettingsAPI struct{ c *Client }

type SecurityLayersResponse struct {
	Layers            SecurityLayers `json:"layers"`
	AvailablePatterns []string       `json:"availablePatterns"`
}

func (s SettingsAPI) GetSecurityLayers(ctx context.Context) (SecurityLayersResponse, error) {
	st, err := readStore()
	if err != nil {
		return SecurityLayersResponse{}, err
	}
	return SecurityLayersResponse{Layers: toLayers(st.Security), AvailablePatterns: AvailablePatterns()}, nil
}

func (s SettingsAPI) SetSecurityLayers(ctx context.Context, layers SecurityLayers) (SecurityLayers, error) {
	st, err := readStore()
	if err != nil {
		return SecurityLayers{}, err
	}
	next := fromLayers(layers, st.Security)
	st.Security = next
	st.absent = false
	if err := writeStore(st); err != nil {
		return SecurityLayers{}, err
	}
	// The change is worth seeing beside a burst later: "the limit was 30 then".
	recordRateLimitChange(layers)
	return toLayers(next), nil
}

func (s SettingsAPI) GetRateLimitHistory(ctx context.Context) ([]RateLimitChange, error) {
	return readRateLimitHistory(), nil
}

func (s SettingsAPI) ClearRateLimitHistory(ctx context.Context) error {
	if err := os.WriteFile(historyPath(), []byte("[]"), 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// GuardStatus is this machine's guard against the one this binary ships.
//
// `latest` used to mean "the newest version the service serves". It means the
// version in this build now, which is the only newer one a machine can get: the
// installer writes the shipped hook, so an out-of-date install is fixed by
// reinstalling rather than by waiting for a download.
type GuardStatus struct {
	Latest        int  `json:"latest"`
	Installed     *int `json:"installed"`
	UpToDate      bool `json:"up_to_date"`
	DeviceCount   int  `json:"device_count"`
	OutdatedCount int  `json:"outdated_count"`
}

// GuardVersions is filled in by the install layer, which owns both numbers. It
// is a function variable rather than an import because internal/install imports
// this package, and a cycle is not worth one integer.
var GuardVersions = func() (latest int, installed *int) { return 0, nil }

func (s SettingsAPI) GetGuardStatus(ctx context.Context) (GuardStatus, error) {
	latest, installed := GuardVersions()
	out := GuardStatus{Latest: latest, Installed: installed, DeviceCount: 1}
	if installed != nil && *installed >= latest {
		out.UpToDate = true
	}
	if installed != nil && *installed < latest {
		out.OutdatedCount = 1
	}
	return out, nil
}

func (s SettingsAPI) GetSelfProtection(ctx context.Context) (bool, error) {
	st, err := readStore()
	if err != nil {
		return true, err
	}
	// Defaults ON: a file that says nothing leaves protection on, because the
	// failure mode of guessing wrong the other way is a guard that can be edited
	// out of the way.
	return st.SelfProtect == nil || *st.SelfProtect, nil
}

func (s SettingsAPI) SetSelfProtection(ctx context.Context, enabled bool) (bool, error) {
	st, err := readStore()
	if err != nil {
		return false, err
	}
	st.SelfProtect = &enabled
	st.absent = false
	if err := writeStore(st); err != nil {
		return false, err
	}
	return enabled, nil
}

// LocalLogsConfig is where the hooks write the record. On a machine with no
// service this is the only destination there is, so it reads as ON with the
// default folder unless somebody named another — the FOLDER is the part worth
// choosing.
type LocalLogsConfig struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

func (s SettingsAPI) GetLocalLogs(ctx context.Context) (LocalLogsConfig, error) {
	st, err := readStore()
	if err != nil {
		return LocalLogsConfig{}, err
	}
	if st.Security != nil && st.Security.LocalLogs != nil && strings.TrimSpace(st.Security.LocalLogs.Path) != "" {
		return LocalLogsConfig{Enabled: st.Security.LocalLogs.Enabled, Path: st.Security.LocalLogs.Path}, nil
	}
	return LocalLogsConfig{Enabled: true, Path: DefaultLogDir()}, nil
}

func (s SettingsAPI) SetLocalLogs(ctx context.Context, cfg LocalLogsConfig) (LocalLogsConfig, error) {
	st, err := readStore()
	if err != nil {
		return LocalLogsConfig{}, err
	}
	path := strings.TrimSpace(cfg.Path)
	if st.Security == nil {
		st.Security = &guardSecurity{}
	}
	if path == "" {
		st.Security.LocalLogs = nil
	} else {
		st.Security.LocalLogs = &localLogsBlock{Enabled: cfg.Enabled, Path: path}
	}
	st.absent = false
	if err := writeStore(st); err != nil {
		return LocalLogsConfig{}, err
	}
	if path == "" {
		return LocalLogsConfig{Enabled: true, Path: DefaultLogDir()}, nil
	}
	return LocalLogsConfig{Enabled: cfg.Enabled, Path: path}, nil
}

// ── /stats ─────────────────────────────────────────────────────────────────

type StatsAPI struct{ c *Client }

const (
	msHour = int64(3_600_000)
	msDay  = int64(86_400_000)
)

// Get counts what is RECORDED, which is not the same as what was called: the
// guard records a denial and the post-tool hook records the rest, so a client
// with no post-tool stage leaves denials only. That was true of the service's
// numbers too.
func (s StatsAPI) Get(ctx context.Context) (Stats, error) {
	rows := readLog()
	st, _ := readStore()
	tools := map[string]bool{}
	var out Stats
	for _, r := range rows {
		if r.Tool != "" {
			tools[r.Tool] = true
		}
		if r.Decision == "DENY" {
			out.Denied++
		} else {
			out.Allowed++
		}
	}
	out.TotalCalls = len(rows)
	out.RegisteredTools = len(tools)
	if st.Policy != nil {
		out.ActivePolicies = 1
	}
	for i, r := range rows {
		if i >= 20 {
			break
		}
		e := toAuditEntry(r)
		out.RecentActivity = append(out.RecentActivity, struct {
			ID               string   `json:"id"`
			ToolName         string   `json:"tool_name"`
			Decision         string   `json:"decision"`
			TrustLevel       string   `json:"trust_level"`
			EvaluationTimeMs *float64 `json:"evaluation_time_ms"`
			CreatedAt        string   `json:"created_at"`
		}{e.ID, e.ToolName, e.Decision, e.TrustLevel, e.EvaluationTimeMs, e.CreatedAt})
	}
	return out, nil
}

func (s StatsAPI) Timeseries(ctx context.Context, period, granularity string) (Timeseries, error) {
	bucketMS := msHour
	if granularity == "1d" {
		bucketMS = msDay
	}
	span := msDay
	switch period {
	case "7d":
		span = 7 * msDay
	case "30d":
		span = 30 * msDay
	case "all":
		span = 0
	}
	now := time.Now().UnixMilli()
	since := int64(0)
	if span > 0 {
		since = now - span
	}

	type bucket struct {
		total, allowed, denied, timed int
		ms                            float64
	}
	buckets := map[int64]*bucket{}
	for _, r := range readLog() {
		if r.at <= 0 || r.at < since {
			continue
		}
		key := (r.at / bucketMS) * bucketMS
		b := buckets[key]
		if b == nil {
			b = &bucket{}
			buckets[key] = b
		}
		b.total++
		if r.Decision == "DENY" {
			b.denied++
		} else {
			b.allowed++
		}
		if r.EvaluationTimeMs != nil {
			b.ms += *r.EvaluationTimeMs
			b.timed++
		}
	}

	keys := make([]int64, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	out := Timeseries{Period: period, Granularity: "hour", Timeseries: []TimeseriesPoint{}}
	if bucketMS == msDay {
		out.Granularity = "day"
	}
	for _, k := range keys {
		b := buckets[k]
		avg := 0.0
		if b.timed > 0 {
			// Averaged over the entries that CARRY a time, not over every entry:
			// an older line without one would pull the average towards zero.
			avg = float64(int((b.ms/float64(b.timed))*10+0.5)) / 10
		}
		out.Timeseries = append(out.Timeseries, TimeseriesPoint{
			Timestamp:    time.UnixMilli(k).UTC().Format(time.RFC3339Nano),
			Total:        b.total,
			Allowed:      b.allowed,
			Denied:       b.denied,
			AvgEvalTimeM: avg,
		})
	}
	return out, nil
}

// Drift groups by the REASON a call was denied rather than by rule id: a local
// record carries the reason the guard gave and not which rule produced it, and
// the reason is what somebody reads anyway.
func (s StatsAPI) Drift(ctx context.Context, days int) (Drift, error) {
	if days < 1 {
		days = 7
	}
	span := int64(days) * msDay
	now := time.Now().UnixMilli()

	type agg struct {
		count int
		tool  string
	}
	current, previous := map[string]*agg{}, map[string]*agg{}
	for _, r := range readLog() {
		if r.at <= 0 || r.Decision != "DENY" {
			continue
		}
		age := now - r.at
		var into map[string]*agg
		switch {
		case age <= span:
			into = current
		case age <= span*2:
			into = previous
		default:
			continue
		}
		key := "denied"
		if r.Reason != nil && strings.TrimSpace(*r.Reason) != "" {
			key = strings.TrimSpace(*r.Reason)
		}
		a := into[key]
		if a == nil {
			a = &agg{}
			into[key] = a
		}
		a.count++
		if a.tool == "" {
			a.tool = r.Tool
		}
	}

	out := Drift{Days: days}
	seen := map[string]bool{}
	keys := []string{}
	for _, m := range []map[string]*agg{current, previous} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	for _, a := range current {
		out.TotalCurrent += a.count
	}
	for _, a := range previous {
		out.TotalPrevious += a.count
	}
	for _, k := range keys {
		cur, prev := 0, 0
		tool := ""
		if a := current[k]; a != nil {
			cur, tool = a.count, a.tool
		}
		if a := previous[k]; a != nil {
			prev = a.count
			if tool == "" {
				tool = a.tool
			}
		}
		reason, lastTool := k, tool
		row := struct {
			RuleID   *string  `json:"rule_id"`
			Reason   *string  `json:"reason"`
			LastTool *string  `json:"last_tool"`
			Current  int      `json:"current"`
			Previous int      `json:"previous"`
			Delta    int      `json:"delta"`
			DeltaPct *float64 `json:"delta_pct"`
			IsNew    bool     `json:"is_new"`
			Spike    bool     `json:"spike"`
		}{Reason: &reason, Current: cur, Previous: prev, Delta: cur - prev, IsNew: prev == 0 && cur > 0, Spike: prev > 0 && cur >= prev*2}
		if lastTool != "" {
			row.LastTool = &lastTool
		}
		// A percentage against zero is not a large increase, it is undefined.
		// IsNew is what says that case out loud.
		if prev > 0 {
			pct := float64(int(float64(cur-prev)/float64(prev)*1000+0.5)) / 10
			row.DeltaPct = &pct
		}
		out.Rules = append(out.Rules, row)
	}
	sort.SliceStable(out.Rules, func(i, j int) bool { return out.Rules[i].Current > out.Rules[j].Current })
	return out, nil
}

// SecurityInsights stays raw JSON, as it was: pinning a struct to it would mean
// this version silently dropping whatever is added next.
//
// `anomalies` are minutes that reached the CONFIGURED limit, never a statistical
// baseline. There is no inference here and there was none in the service either;
// the name is older than the behaviour.
func (s StatsAPI) SecurityInsights(ctx context.Context, days int) (json.RawMessage, error) {
	if days < 1 {
		days = 7
	}
	span := int64(days) * msDay
	now := time.Now().UnixMilli()
	st, err := readStore()
	if err != nil {
		return nil, err
	}
	layers := toLayers(st.Security)
	limit := layers.RateLimit.PerMinute

	perMinute, perDay, perAgent, perPattern := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	dlpHits := []map[string]any{}
	scanned := 0
	for _, r := range readLog() {
		if r.at <= 0 || now-r.at > span {
			continue
		}
		scanned++
		agent := "unknown"
		if r.AgentName != nil && *r.AgentName != "" {
			agent = *r.AgentName
		} else if r.AgentID != nil && *r.AgentID != "" {
			agent = *r.AgentID
		}
		perAgent[agent]++
		perDay[time.UnixMilli(r.at).UTC().Format("2006-01-02")]++
		minute := time.UnixMilli((r.at / 60_000) * 60_000).UTC().Format(time.RFC3339)
		perMinute[agent+" "+minute]++
		for _, name := range r.DLP {
			perPattern[name]++
		}
		if len(r.DLP) > 0 || (r.Reason != nil && strings.Contains(strings.ToLower(*r.Reason), "dlp")) {
			if len(dlpHits) < 200 {
				dlp := r.DLP
				if dlp == nil {
					dlp = []string{}
				}
				dlpHits = append(dlpHits, map[string]any{
					"id": r.id, "tool": r.Tool, "decision": toAuditEntry(r).Decision,
					"patterns": dlp, "created_at": toAuditEntry(r).CreatedAt,
				})
			}
		}
	}

	anomalies := []map[string]any{}
	if limit > 0 {
		for _, kv := range sortedCounts(perMinute, 100) {
			if kv.Count < limit {
				continue
			}
			parts := strings.SplitN(kv.Key, " ", 2)
			row := map[string]any{"agent": parts[0], "count": kv.Count, "limit": limit}
			if len(parts) > 1 {
				row["minute"] = parts[1]
			}
			anomalies = append(anomalies, row)
		}
	}

	callsPerDay := []map[string]any{}
	dayKeys := make([]string, 0, len(perDay))
	for k := range perDay {
		dayKeys = append(dayKeys, k)
	}
	sort.Strings(dayKeys)
	for _, k := range dayKeys {
		callsPerDay = append(callsPerDay, map[string]any{"day": k, "count": perDay[k]})
	}

	topAgents := []map[string]any{}
	for _, kv := range sortedCounts(perAgent, 6) {
		topAgents = append(topAgents, map[string]any{"agent": kv.Key, "count": kv.Count})
	}
	byPattern := []map[string]any{}
	for _, kv := range sortedCounts(perPattern, 20) {
		byPattern = append(byPattern, map[string]any{"pattern": kv.Key, "count": kv.Count})
	}

	return json.Marshal(map[string]any{
		"days":             days,
		"layers":           layers,
		"anomalyThreshold": limit,
		"scanned":          scanned,
		"totalCalls":       scanned,
		"limitHistory":     readRateLimitHistory(),
		"anomalies":        anomalies,
		"dlpHits":          dlpHits,
		"callsPerDay":      callsPerDay,
		"topAgents":        topAgents,
		"dlpByPattern":     byPattern,
	})
}

// ── /audit-logs ────────────────────────────────────────────────────────────

type AuditAPI struct{ c *Client }

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

func (a AuditAPI) List(ctx context.Context, q AuditQuery) (AuditList, error) {
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
 * record of anything. On a machine the file is the record — somebody who owns
 * the machine can always delete it, and the CLI does not have to help.
 */

// ruleFromEntry turns one recorded call into a rule.
//
// `exact` narrows to what that call actually did — the command, the path, the URL
// the entry carries. `tool` covers the tool as a whole, which is the wider and
// more dangerous of the two, so it is never the default.
func ruleFromEntry(ctx context.Context, p PoliciesAPI, id, scope, effect string) (RuleMutation, error) {
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
// it did not look for a url at all, and for a path it took the BASENAME — so
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
func (a AuditAPI) Whitelist(ctx context.Context, id, scope string) (RuleMutation, error) {
	return ruleFromEntry(ctx, PoliciesAPI{a.c}, id, scope, "ALLOW")
}

// Block is the inverse: turn a call that was allowed into a DENY rule.
func (a AuditAPI) Block(ctx context.Context, id, scope string) (RuleMutation, error) {
	return ruleFromEntry(ctx, PoliciesAPI{a.c}, id, scope, "DENY")
}
