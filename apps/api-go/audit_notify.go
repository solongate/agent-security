package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/codeyevsky/solongate/api/internal/store"
)

// What a recorded call sets off: the outbound webhooks and the alert rules.
//
// These are ports of src/lib/denial-webhook.ts and src/lib/denial-alerts.ts,
// and only the parts POST /v1/audit-logs drives. The CRUD half of both — the
// /v1/settings/denial-webhook and /v1/settings/denial-alerts routes, with their
// validation, their redaction and their send-test — belongs to the settings
// slice; what is here is the delivery path, because dropping it would silently
// stop every Slack, Telegram and email alert a customer has configured while
// every endpoint kept answering 200.
//
// Everything in this file is FIRE-AND-FORGET and must stay that way. The
// endpoint that calls it is the one an installed guard fires from a detached
// child on every denial; putting a stranger's webhook endpoint on that path
// would make this service as slow as the slowest thing anyone has configured.

// notifyTimeout bounds one delivery attempt. It is the live app's four seconds,
// and it is per request rather than for the whole fan-out.
const notifyTimeout = 4 * time.Second

// notifyBudget bounds the whole background job. Without it a project with a
// black-holed webhook accumulates goroutines at the rate its agents make calls.
const notifyBudget = 30 * time.Second

// notifyClient is shared so connections are reused across deliveries. A fresh
// client per call means a fresh TLS handshake per denial.
var notifyClient = &http.Client{Timeout: notifyTimeout}

// notifySlots bounds how many of these jobs run at once.
//
// Without it this is a goroutine per audit write, on the endpoint every
// installed guard fires from a detached child. A project with one slow webhook
// and a looping agent would accumulate them at the rate of its calls, each
// holding the connection pool for two settings reads — so the busiest tenant
// would starve every other tenant's queries. The Node app is not exposed to
// this in the same way; a Go one is, and the ceiling is the difference between
// a slow webhook being that customer's problem and it being everyone's.
//
// Sixty-four is generous for what these jobs do: two reads and some HTTP.
var notifySlots = make(chan struct{}, 64)

// notifyAudit runs the webhook fan-out and the alert evaluation off the request
// path. ctx must already be detached from the request's — see the call site.
//
// When every slot is taken the job is DROPPED rather than queued, and said so
// in the log. Queueing would only move the pile-up somewhere less visible, and a
// dropped alert is recoverable — the next call over the threshold fires it —
// while an exhausted process is not.
func (s *server) notifyAudit(ctx context.Context, projectID string, entry store.AuditLog) {
	select {
	case notifySlots <- struct{}{}:
	default:
		log.Print("[API:notify] delivery skipped: too many in flight")
		return
	}
	go func() {
		defer func() { <-notifySlots }()
		ctx, cancel := context.WithTimeout(ctx, notifyBudget)
		defer cancel()
		s.emitWebhookEvent(ctx, projectID, webhookEventFor(projectID, entry))
		s.evaluateDenialAlerts(ctx, projectID)
	}()
}

// ── webhooks ────────────────────────────────────────────────────────────────

// denialEvent is the JSON delivered to a customer's endpoint. It is a published
// integration surface: field names and the X-SolonGate-Event header are what
// somebody's Zapier or n8n flow matches on.
type denialEvent struct {
	Event            string       `json:"event"`
	Timestamp        string       `json:"timestamp"`
	RequestID        string       `json:"request_id"`
	ProjectID        string       `json:"project_id"`
	Decision         string       `json:"decision"`
	DenyLayer        string       `json:"deny_layer,omitempty"`
	Tool             string       `json:"tool"`
	Permission       string       `json:"permission,omitempty"`
	MatchedRuleID    *string      `json:"matched_rule_id"`
	Reason           *string      `json:"reason"`
	EvaluationTimeMs *float64     `json:"evaluation_time_ms"`
	Agent            webhookAgent `json:"agent"`
}

type webhookAgent struct {
	ID   *string `json:"id"`
	Name *string `json:"name"`
}

func webhookEventFor(projectID string, entry store.AuditLog) denialEvent {
	decision := strings.ToUpper(entry.Decision)
	isDenial := decision == "DENY" || decision == "DENIED"

	ev := denialEvent{
		Event:            "allow",
		Timestamp:        store.ISO(entry.CreatedAt),
		RequestID:        entry.RequestID,
		ProjectID:        projectID,
		Decision:         decision,
		Tool:             entry.ToolName,
		Permission:       entry.Permission,
		MatchedRuleID:    nullable(entry.MatchedRuleID),
		Reason:           nullable(entry.Reason),
		EvaluationTimeMs: entry.EvaluationTimeMs,
		Agent:            webhookAgent{ID: nullable(entry.AgentID), Name: nullable(entry.AgentName)},
	}
	if isDenial {
		ev.Event = "denial"
		ev.DenyLayer = classifyDenyLayer(entry.Reason)
	}
	return ev
}

var selfProtectionReason = regexp.MustCompile(`(?i)tamper protection|self-protection`)

// classifyDenyLayer says which layer refused the call.
//
// The distinction is the one thing a webhook consumer most wants: a POLICY deny
// is somebody's rules working, and a SELF_PROTECTION deny is an agent trying to
// disable the guard, which is a different kind of message to wake up to.
func classifyDenyLayer(reason string) string {
	lower := strings.ToLower(reason)
	if selfProtectionReason.MatchString(reason) || strings.HasPrefix(lower, "solongate:") {
		return "SELF_PROTECTION"
	}
	return "POLICY"
}

// denialWebhook is one configured endpoint.
//
// The field ORDER is the stored order, because the settings routes write this
// list back through this struct; it is src/lib/denial-webhook.ts's object
// literal. `headers` is omitted when there are none rather than written as
// null, which is what the live parser produces for a hook with no extra
// headers.
type denialWebhook struct {
	ID        string            `json:"id"`
	URL       string            `json:"url"`
	Enabled   *bool             `json:"enabled"`
	CreatedAt string            `json:"createdAt"`
	Events    string            `json:"events"`
	Headers   map[string]string `json:"headers,omitempty"`
}

func (h denialWebhook) isEnabled() bool { return h.Enabled == nil || *h.Enabled }

// wants is the per-hook event filter.
func (h denialWebhook) wants(isDenial bool) bool {
	switch h.Events {
	case "all":
		return true
	case "allowed":
		return !isDenial
	default:
		return isDenial
	}
}

// readDenialWebhooks parses the stored list.
//
// A stored value that is not a JSON array is a LEGACY single URL, from before
// the setting held more than one, and it is still honoured — a customer who has
// not opened the settings page since would otherwise stop receiving events with
// nothing in any log to say why.
func (s *server) readDenialWebhooks(ctx context.Context, projectID string) []denialWebhook {
	raw, ok, err := s.store.SettingJSON(ctx, store.SettingDenialWebhook, projectID)
	if err != nil || !ok {
		return nil
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if !strings.HasPrefix(raw, "[") {
		// The epoch is the created-at the live parser substitutes for a row that
		// predates the field, and GET /v1/settings/denial-webhook renders it —
		// so it is set here rather than left empty, which would put an unparseable
		// date in front of the settings page.
		return []denialWebhook{{ID: "legacy", URL: raw, Events: "denials", CreatedAt: store.ISOms(0)}}
	}
	var list []denialWebhook
	if json.Unmarshal([]byte(raw), &list) != nil {
		return nil
	}
	out := make([]denialWebhook, 0, len(list))
	for _, h := range list {
		if h.ID == "" || h.URL == "" {
			continue
		}
		if h.Events != "allowed" && h.Events != "all" {
			h.Events = "denials"
		}
		h.Headers = sanitizeWebhookHeaders(h.Headers)
		out = append(out, h)
	}
	return out
}

// sanitizeWebhookHeaders drops the two headers this service sets itself.
//
// Letting a stored Content-Type through would let a saved configuration change
// how the body is interpreted at the far end, and X-SolonGate-Event is the field
// a consumer routes on — a hook that could override it could make a denial
// arrive labelled as an allow.
func sanitizeWebhookHeaders(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := map[string]string{}
	n := 0
	for k, v := range in {
		key := store.Clip(strings.TrimSpace(k), 128)
		if key == "" {
			continue
		}
		if strings.EqualFold(key, "content-type") || strings.EqualFold(key, "x-solongate-event") {
			continue
		}
		out[key] = store.Clip(v, 2048)
		if n++; n >= 20 {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *server) emitWebhookEvent(ctx context.Context, projectID string, ev denialEvent) {
	hooks := s.readDenialWebhooks(ctx, projectID)
	if len(hooks) == 0 {
		return
	}
	isDenial := ev.Event == "denial"

	var wg sync.WaitGroup
	for _, h := range hooks {
		if !h.isEnabled() || !h.wants(isDenial) {
			continue
		}
		wg.Add(1)
		go func(h denialWebhook) {
			defer wg.Done()
			postNotifyJSON(ctx, h.URL, map[string]string{"X-SolonGate-Event": ev.Event}, h.Headers, ev)
		}(h)
	}
	wg.Wait()
}

// postJSON delivers one payload. The failure is logged WITHOUT the URL: a
// webhook URL is a bearer credential — a Slack incoming-webhook URL is the
// whole authentication — and a log line quoting it hands it to anyone with log
// access.
func postNotifyJSON(ctx context.Context, url string, own map[string]string, extra map[string]string, payload any) bool {
	body, err := marshalNoEscape(payload)
	if err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range own {
		req.Header.Set(k, v)
	}
	resp, err := notifyClient.Do(req)
	if err != nil {
		log.Printf("[API:notify] delivery failed: %v", redactURLs(err.Error()))
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

var urlInText = regexp.MustCompile(`https?://[^\s"]+`)

// redactURLs keeps a customer's webhook URL out of this service's logs even
// when it arrives inside somebody else's error string.
func redactURLs(s string) string {
	return urlInText.ReplaceAllString(s, "<url>")
}

// ── alert rules ─────────────────────────────────────────────────────────────

// alertRule is one configured alert: src/lib/denial-alerts.ts's AlertRule,
// field for field and in its order.
//
// The evaluation in this file reads only a few of these. The rest are here
// because the settings slice writes the list back THROUGH this struct — the
// live app's write() does the same, storing its parsed model — and a field this
// type did not carry would be a field a save silently deleted. The one write on
// the delivery path, recordAlertFired, still patches the raw JSON instead, so a
// key added by a newer settings page survives a cooldown stamp.
//
// The optional members carry omitempty because the original leaves them
// `undefined`, and JSON.stringify omits those: a rule with no Telegram target
// has no `telegram` key rather than a null one, and the dashboard tests for the
// key's absence.
type alertRule struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Enabled       *bool    `json:"enabled"`
	Threshold     int64    `json:"threshold"`
	WindowSeconds int64    `json:"windowSeconds"`
	Signal        string   `json:"signal"`
	DenyLayers    []string `json:"denyLayers,omitempty"`
	ToolPatterns  []string `json:"toolPatterns,omitempty"`
	// Developers narrows a rule to the machines of named people.
	//
	// Empty means the whole project, which is what every rule written before
	// this meant and still means. It exists because a fleet reports into the
	// host's project, so without it a host's alerts are the whole fleet at once
	// and there is no way to watch one contractor without being paged for
	// everybody.
	//
	// The ids are guest account ids, matched against the key each row was
	// reported by. A rule naming somebody who has since been revoked simply
	// stops matching, which is the right answer: they are not on the fleet.
	Developers      []string `json:"developers,omitempty"`
	SlackURLs       []string `json:"slackUrls,omitempty"`
	Emails          []string `json:"emails,omitempty"`
	Telegram        []string `json:"telegram,omitempty"`
	LastTriggeredAt string   `json:"lastTriggeredAt,omitempty"`
	CreatedAt       string   `json:"createdAt"`
}

func (r alertRule) isEnabled() bool { return r.Enabled == nil || *r.Enabled }

func (r alertRule) hasTarget() bool {
	return len(r.SlackURLs) > 0 || len(r.Emails) > 0 || len(r.Telegram) > 0
}

// normalise is the live parser's per-rule coercion, and it runs on everything
// read out of storage — the delivery path here and the settings routes both.
//
// The clamps are the reason a rule cannot be used as an amplifier: a threshold
// of 1 with a window of one second would deliver a message per call.
//
// The rest is what makes a stored rule a COMPLETE one, because the settings
// routes render these fields and write them back: a rule with no name shows as
// "Alert", one with no createdAt is stamped now rather than rendering an empty
// date, and `enabled` becomes a real boolean so the toggle has a position.
func (r *alertRule) normalise() {
	if r.Name == "" {
		r.Name = "Alert"
	}
	r.Name = store.Clip(r.Name, 120)
	if r.CreatedAt == "" {
		r.CreatedAt = store.ISOms(store.NowMS())
	}
	enabled := r.isEnabled()
	r.Enabled = &enabled
	r.Threshold = clampInt64(r.Threshold, 5, 100, 5)
	r.WindowSeconds = clampInt64(r.WindowSeconds, 30, 86400, 300)
	switch r.Signal {
	case "any", "deny", "dlp", "ratelimit":
	default:
		r.Signal = "any"
	}
	r.DenyLayers = alertDenyLayers(r.DenyLayers)
	r.ToolPatterns = alertToolPatterns(r.ToolPatterns)
	r.Developers = alertDevelopers(r.Developers)
}

// alertDenyLayers keeps only the two layers a denial can come from. An
// unrecognised name is dropped rather than carried: it would be compared
// against classifyDenyLayer's output, which only ever produces these two, so a
// stored typo is a filter that silently matches nothing.
func alertDenyLayers(in []string) []string {
	var out []string
	for _, l := range in {
		if l == "POLICY" || l == "SELF_PROTECTION" {
			out = append(out, l)
		}
	}
	return out
}

// alertToolPatterns applies the original's caps: 120 characters a pattern,
// fifty patterns, no empties.
func alertToolPatterns(in []string) []string {
	var out []string
	for _, t := range in {
		if t = store.Clip(t, 120); t == "" {
			continue
		}
		out = append(out, t)
		if len(out) >= 50 {
			break
		}
	}
	return out
}

// alertDevelopers caps and cleans the account list a rule is narrowed to.
//
// Twenty is a bound on the query below rather than a product limit: each id
// becomes a bound parameter in an IN clause, and a rule naming a whole fleet is
// a rule that should have named nobody.
func alertDevelopers(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] || len(v) > 128 {
			continue
		}
		seen[v] = true
		out = append(out, v)
		if len(out) >= 20 {
			break
		}
	}
	return out
}

func clampInt64(v, min, max, def int64) int64 {
	if v == 0 {
		return def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func (s *server) readAlertRules(ctx context.Context, projectID string) []alertRule {
	raw, ok, err := s.store.SettingJSON(ctx, store.SettingDenialAlerts, projectID)
	if err != nil || !ok || !strings.HasPrefix(strings.TrimSpace(raw), "[") {
		return nil
	}
	var list []alertRule
	if json.Unmarshal([]byte(raw), &list) != nil {
		return nil
	}
	out := make([]alertRule, 0, len(list))
	for _, r := range list {
		if r.ID == "" || !r.hasTarget() {
			continue
		}
		r.normalise()
		out = append(out, r)
	}
	return out
}

// alertCooldowns is the in-process half of the cooldown.
//
// The stored lastTriggeredAt is the durable half; this one closes the window
// between deciding to fire and writing that back, during which a second call
// would evaluate the same rule again. It is per-process, so N replicas can each
// send once — the live app has exactly the same limitation, for the same
// reason, and the alternative is a lock in the settings table on the hot path
// of the highest-volume endpoint.
var alertCooldowns sync.Map // rule id -> time.Time

// evaluateDenialAlerts counts the window behind each enabled rule and delivers
// the ones that crossed their threshold.
func (s *server) evaluateDenialAlerts(ctx context.Context, projectID string) {
	rules := s.readAlertRules(ctx, projectID)
	if len(rules) == 0 {
		return
	}
	now := time.Now()

	fired := map[string]string{}
	for _, rule := range rules {
		if !rule.isEnabled() {
			continue
		}
		cooldown := time.Duration(rule.WindowSeconds) * time.Second
		if inCooldown(rule, now, cooldown) {
			continue
		}

		bd, err := s.countAlertWindow(ctx, projectID, rule, now)
		if err != nil {
			log.Printf("[API:notify] alert window failed: %v", err)
			continue
		}
		if bd.total < rule.Threshold {
			continue
		}
		// Re-checked after the count, because counting is a database round trip
		// and a second call can have claimed the rule while it was in flight.
		if inCooldown(rule, now, cooldown) {
			continue
		}
		alertCooldowns.Store(rule.ID, now)

		s.dispatchAlert(ctx, rule, bd)
		fired[rule.ID] = now.UTC().Format("2006-01-02T15:04:05.000Z")
	}

	if len(fired) > 0 {
		s.recordAlertFired(ctx, projectID, fired)
	}
}

func inCooldown(rule alertRule, now time.Time, cooldown time.Duration) bool {
	if rule.LastTriggeredAt != "" {
		if t, err := time.Parse(time.RFC3339, rule.LastTriggeredAt); err == nil {
			if now.Sub(t) < cooldown {
				return true
			}
		}
	}
	if v, ok := alertCooldowns.Load(rule.ID); ok {
		if last, ok := v.(time.Time); ok && now.Sub(last) < cooldown {
			return true
		}
	}
	return false
}

// alertBreakdown is what the window contained, split the way the message
// describes it.
type alertBreakdown struct {
	total         int64
	denials       int64
	dlpDetected   int64
	dlpBlocked    int64
	burstDetected int64
	burstBlocked  int64
}

// add folds one developer's window into the rule's total.
func (b *alertBreakdown) add(o alertBreakdown) {
	b.total += o.total
	b.denials += o.denials
	b.dlpDetected += o.dlpDetected
	b.dlpBlocked += o.dlpBlocked
	b.burstDetected += o.burstDetected
	b.burstBlocked += o.burstBlocked
}

// maxAlertWindowRows is the live route's cap on the window scan. A rule with a
// day-long window on a busy project would otherwise read the day.
const maxAlertWindowRows = 5000

// countAlertWindow classifies each call in the window ONCE, in the live app's
// precedence: a secret outranks a burst, and a burst outranks a plain denial.
//
// The precedence is not cosmetic. Counting a call as both a DLP hit and a
// denial would cross a threshold of five on three calls, and the message would
// name a number the audit page does not show.
// countAlertWindowFor counts a rule that names specific developers.
//
// It walks them one at a time because the filter narrows to one account, and it
// adds the breakdowns together because the threshold belongs to the RULE: eleven
// denials spread across three named contractors is the same eleven a rule
// watching one of them would have counted.
//
// A name that no longer matches anything contributes nothing rather than
// failing the rule. Somebody revoked from the fleet stops being counted, which
// is the right answer, and a rule that stopped firing entirely because one of
// its names had left would be a rule that goes quiet exactly when it should not.
func (s *server) countAlertWindowFor(ctx context.Context, projectID string, rule alertRule, base store.AuditFilter, now time.Time) (alertBreakdown, error) {
	var total alertBreakdown
	scoped := rule
	scoped.Developers = nil

	for _, who := range rule.Developers {
		f := base
		f.UserID = who
		bd, err := s.countAlertWindowRows(ctx, projectID, scoped, f, now)
		if err != nil {
			return total, err
		}
		total.add(bd)
	}
	return total, nil
}

func (s *server) countAlertWindow(ctx context.Context, projectID string, rule alertRule, now time.Time) (alertBreakdown, error) {
	filter := store.AuditFilter{
		Since: now.Add(-time.Duration(rule.WindowSeconds) * time.Second).Unix(),
		Order: "created_at",
		Dir:   store.Desc,
		Limit: maxAlertWindowRows,
	}
	// A rule narrowed to named people counts only their rows. The filter takes
	// one account, so several are counted by asking once each and adding the
	// windows together: the threshold is about the rule, not about any one
	// person, so eleven denials spread across three named contractors is the
	// same eleven a rule watching one of them would have seen.
	if len(rule.Developers) > 0 {
		return s.countAlertWindowFor(ctx, projectID, rule, filter, now)
	}
	return s.countAlertWindowRows(ctx, projectID, rule, filter, now)
}

// countAlertWindowRows is the classification itself, over whatever window the
// caller asked for.
func (s *server) countAlertWindowRows(ctx context.Context, projectID string, rule alertRule, filter store.AuditFilter, now time.Time) (alertBreakdown, error) {
	var bd alertBreakdown

	rows, err := s.store.ListAuditLogs(ctx, projectID, filter)
	if err != nil || len(rows) == 0 {
		return bd, err
	}

	layers := s.store.GetSecurityLayers(ctx, projectID)
	dlpOff := layers.DLP.Mode == store.LayerOff
	rlOff := layers.RateLimit.Mode == store.LayerOff

	wantDLP := (rule.Signal == "dlp" || rule.Signal == "any") && !dlpOff
	wantRL := (rule.Signal == "ratelimit" || rule.Signal == "any") && !rlOff && layers.RateLimit.PerMinute > 0
	wantDeny := rule.Signal == "any" || rule.Signal == "deny"

	var scanner *dlpScanner
	if wantDLP {
		scanner = newDLPScanner(layers)
	}

	burst := map[string]bool{}
	if wantRL {
		counts := map[string]int64{}
		for _, r := range rows {
			counts[burstKey(r.AgentName, r.CreatedAt)]++
		}
		for k, n := range counts {
			if n > layers.RateLimit.PerMinute {
				burst[k] = true
			}
		}
	}

	for _, r := range rows {
		isDeny := r.Decision == "DENY" || r.Decision == "DENIED"
		hasSecret := wantDLP && r.ArgumentsSummary != "" && len(scanner.scan(r.ArgumentsSummary)) > 0
		inBurst := wantRL && burst[burstKey(r.AgentName, r.CreatedAt)]

		switch {
		case hasSecret:
			bd.total++
			if layers.DLP.Mode == store.LayerBlock {
				bd.dlpBlocked++
			} else {
				bd.dlpDetected++
			}
		case inBurst:
			bd.total++
			if layers.RateLimit.Mode == store.LayerBlock {
				bd.burstBlocked++
			} else {
				bd.burstDetected++
			}
		case wantDeny && isDeny && !fromDisabledLayer(r.Reason, dlpOff, rlOff):
			bd.total++
			bd.denials++
		}
	}
	return bd, nil
}

// fromDisabledLayer drops a denial written by a layer that has since been
// turned off. Without it, switching DLP off would still count yesterday's DLP
// denials towards today's threshold and page somebody about a layer that is no
// longer running.
func fromDisabledLayer(reason string, dlpOff, rlOff bool) bool {
	if rlOff && rateLimitReason.MatchString(reason) {
		return true
	}
	if dlpOff && dlpReasonPrefix.MatchString(reason) {
		return true
	}
	return false
}

// recordAlertFired writes lastTriggeredAt back without disturbing any other
// field of the stored rules.
//
// It is a read-modify-write over the raw JSON, patching only the one key, so a
// field this build does not model — a channel added by a newer settings page —
// survives. Modelling the rules fully and writing the model back is how a
// half-ported service quietly deletes somebody's configuration.
func (s *server) recordAlertFired(ctx context.Context, projectID string, fired map[string]string) {
	raw, ok, err := s.store.SettingJSON(ctx, store.SettingDenialAlerts, projectID)
	if err != nil || !ok {
		return
	}
	var rules []map[string]any
	if json.Unmarshal([]byte(raw), &rules) != nil {
		return
	}
	changed := false
	for i, r := range rules {
		id, _ := r["id"].(string)
		if at, hit := fired[id]; hit {
			rules[i]["lastTriggeredAt"] = at
			changed = true
		}
	}
	if !changed {
		return
	}
	b, err := marshalNoEscape(rules)
	if err != nil {
		return
	}
	if err := s.store.SetSettingJSON(ctx, store.SettingDenialAlerts, projectID, string(b),
		"Per-project denial alert rules (JSON)"); err != nil {
		log.Printf("[API:notify] could not record alert cooldown: %v", err)
	}
}

// ── delivery ────────────────────────────────────────────────────────────────

func (s *server) dispatchAlert(ctx context.Context, rule alertRule, bd alertBreakdown) {
	summary := describeBreakdown(bd, rule.WindowSeconds)
	trip := "Triggered because " + signalLabel(rule.Signal) + " reached your threshold of " +
		intText(rule.Threshold) + " within " + windowLabel(rule.WindowSeconds) + "."
	// Where an alert points. Empty unless the installation names its own UI, and
	// empty means the alert says what happened without offering a link to a host
	// this build cannot know the address of.
	dashURL := strings.TrimRight(env("DASHBOARD_URL", ""), "/")
	if dashURL != "" {
		dashURL += "/audit"
	}

	var wg sync.WaitGroup
	if len(rule.Telegram) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			text := "🚨 <b>SolonGate security alert</b>\n\n<b>" + escapeAlertHTML(summary) + "</b>\n\n" +
				escapeAlertHTML(trip)
			if dashURL != "" {
				text += "\n\n<a href=\"" + dashURL + "\">Open the audit log →</a>"
			}
			sendTelegram(ctx, rule.Telegram, text)
		}()
	}
	for _, url := range rule.SlackURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			postNotifyJSON(ctx, url, nil, nil, map[string]any{
				"text": ":rotating_light: SolonGate security alert: " + summary,
				"blocks": []any{map[string]any{
					"type": "section",
					"text": map[string]any{
						"type": "mrkdwn",
						"text": "*:rotating_light: SolonGate security alert*\n" + summary + "\n" + trip +
							slackAuditLink(dashURL),
					},
				}},
			})
		}(url)
	}
	if len(rule.Emails) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendAlertEmail(ctx, rule.Emails, summary, trip, signalLabel(rule.Signal), dashURL)
		}()
	}
	wg.Wait()
}

// describeBreakdown is the sentence at the top of every alert. The pluralisation
// and the wording are the live app's, because these strings are what somebody
// has a Slack search saved for.
func describeBreakdown(bd alertBreakdown, windowSeconds int64) string {
	mins := (windowSeconds + 30) / 60
	if mins < 1 {
		mins = 1
	}
	var parts []string
	if bd.denials > 0 {
		parts = append(parts, intText(bd.denials)+" denial"+pluralSuffix(bd.denials))
	}
	if bd.dlpDetected > 0 {
		parts = append(parts, intText(bd.dlpDetected)+" DLP detected")
	}
	if bd.dlpBlocked > 0 {
		parts = append(parts, intText(bd.dlpBlocked)+" DLP blocked")
	}
	if bd.burstDetected > 0 {
		parts = append(parts, intText(bd.burstDetected)+" rate-limit burst"+pluralSuffix(bd.burstDetected)+" detected")
	}
	if bd.burstBlocked > 0 {
		parts = append(parts, intText(bd.burstBlocked)+" rate-limit burst"+pluralSuffix(bd.burstBlocked)+" blocked")
	}
	if len(parts) == 0 {
		parts = append(parts, intText(bd.total)+" event"+pluralSuffix(bd.total))
	}
	return strings.Join(parts, ", ") + " in the last " + intText(mins) + " min"
}

func pluralSuffix(n int64) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func signalLabel(signal string) string {
	switch signal {
	case "deny":
		return "denials"
	case "dlp":
		return "DLP secrets"
	case "ratelimit":
		return "rate-limit bursts"
	case "any":
		return "any signal"
	}
	return "events"
}

func windowLabel(seconds int64) string {
	switch {
	case seconds < 60:
		return intText(seconds) + " seconds"
	case seconds < 3600:
		m := (seconds + 30) / 60
		return intText(m) + " minute" + pluralSuffix(m)
	case seconds < 86400:
		h := (seconds + 1800) / 3600
		return intText(h) + " hour" + pluralSuffix(h)
	default:
		d := (seconds + 43200) / 86400
		return intText(d) + " day" + pluralSuffix(d)
	}
}

var htmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// escapeHTML is for the Telegram and email bodies, which are rendered as HTML.
// The summary carries a tool name, which carries whatever a client called its
// tool — an unescaped `<` there is an injected tag in somebody's inbox.
func escapeAlertHTML(s string) string { return htmlEscaper.Replace(s) }

func sendTelegram(ctx context.Context, chatIDs []string, html string) {
	token := strings.TrimSpace(env("TELEGRAM_BOT_TOKEN", ""))
	if token == "" {
		log.Print("[API:notify] telegram alert skipped: TELEGRAM_BOT_TOKEN not configured")
		return
	}
	// The token is in the URL because that is Telegram's API. It is never
	// logged: postJSON reports failures without the URL.
	url := "https://api.telegram.org/bot" + token + "/sendMessage"
	for _, chatID := range chatIDs {
		postNotifyJSON(ctx, url, nil, nil, map[string]any{
			"chat_id":                  chatID,
			"text":                     html,
			"parse_mode":               "HTML",
			"disable_web_page_preview": true,
		})
	}
}

// sendAlertEmail tries Brevo first and falls back to Resend, which is the live
// app's order. Both are optional: a deployment with neither configured logs and
// carries on rather than failing the alert evaluation.
func sendAlertEmail(ctx context.Context, emails []string, summary, trip, watching, dashURL string) {
	subject := "SolonGate alert: " + summary
	text := "SolonGate security alert\n\n" + summary + "\n\n" + trip
	button := ""
	if dashURL != "" {
		text += "\n\nOpen the audit log: " + dashURL
		button = `<p style="margin:20px 0"><a href="` + dashURL + `" style="display:inline-block;background:#1432A0;color:#fff;text-decoration:none;font-weight:600;font-size:14px;padding:10px 18px;border-radius:8px">Open the audit log →</a></p>`
	}
	html := `<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:520px;margin:0 auto;color:#0f172a">` +
		`<div style="font-size:18px;font-weight:700;margin-bottom:4px">🚨 SolonGate security alert</div>` +
		`<div style="font-size:15px;font-weight:600;background:#fef2f2;border:1px solid #fecaca;color:#991b1b;border-radius:8px;padding:12px 14px;margin:12px 0">` +
		escapeAlertHTML(summary) + `</div>` +
		`<p style="font-size:14px;line-height:1.5;color:#334155;margin:12px 0">` + escapeAlertHTML(trip) + `</p>` +
		button +
		`<p style="font-size:12px;color:#94a3b8;margin-top:24px">You are receiving this because you set a SolonGate alert for ` +
		escapeAlertHTML(watching) + `. Manage or remove it with ` + "`solongate alerts`" + `.</p>` +
		`</div>`

	sendEmailHTML(ctx, emails, subject, text, html, "alert")
}

// sendEmailHTML is the transport under every email this service sends.
//
// Brevo first and Resend as the fallback, which is the live app's order. Both
// are optional: a deployment with neither configured logs and carries on rather
// than failing whatever produced the message — an alert evaluation and a report
// run are both things that must not take the request down with them.
//
// `what` names the message in the skip log only. Two callers now (alerts and
// reports) and the log line has to say which one went nowhere, or "email
// skipped" on a busy instance is unattributable.
func sendEmailHTML(ctx context.Context, emails []string, subject, text, html, what string) {
	if len(emails) == 0 {
		return
	}
	brevo := strings.TrimSpace(env("BREVO_API_KEY", ""))
	resend := strings.TrimSpace(env("RESEND_API_KEY", ""))
	if brevo == "" && resend == "" {
		log.Printf("[API:notify] email %s skipped: no BREVO_API_KEY / RESEND_API_KEY configured", what)
		return
	}
	// No default sender. A built-in address would send this installation's mail
	// from a domain it does not own, which is both a forgery and a message that
	// bounces — so an operator who wants mail names their own, and until they do
	// this skips the same way a missing provider key does.
	fromEmail := strings.TrimSpace(env("RESEND_FROM_EMAIL", ""))
	if fromEmail == "" {
		log.Printf("[API:notify] email %s skipped: RESEND_FROM_EMAIL is not set", what)
		return
	}
	fromName := env("RESEND_FROM_NAME", "SolonGate")

	if brevo != "" {
		to := make([]map[string]string, 0, len(emails))
		for _, e := range emails {
			to = append(to, map[string]string{"email": e})
		}
		if postNotifyJSON(ctx, "https://api.brevo.com/v3/smtp/email", nil, map[string]string{"api-key": brevo}, map[string]any{
			"sender":      map[string]string{"name": fromName, "email": fromEmail},
			"to":          to,
			"subject":     subject,
			"htmlContent": html,
			"textContent": text,
			"tags":        []string{"transactional"},
		}) {
			return
		}
	}
	if resend != "" {
		postNotifyJSON(ctx, "https://api.resend.com/emails", nil,
			map[string]string{"Authorization": "Bearer " + resend}, map[string]any{
				"from":    fromName + " <" + fromEmail + ">",
				"to":      emails,
				"subject": subject,
				"text":    text,
				"html":    html,
			})
	}
}

func intText(n int64) string {
	b, err := json.Marshal(n)
	if err != nil {
		return "0"
	}
	return string(b)
}

// logRollup records a roll-up failure without the row it was for. The audit
// entry it belongs to is already stored and carries the detail; this line only
// has to say which table stopped agreeing with it.
func logRollup(what string, err error) {
	log.Printf("[API:audit] %s roll-up failed: %v", what, err)
}

// slackAuditLink is the trailing link on a Slack alert, and empty when the
// installation has named no UI to link to. A bare `<|Open the audit log>` renders
// in Slack as the literal text, which reads as a bug in the alert rather than as
// a deployment that has no dashboard.
func slackAuditLink(dashURL string) string {
	if dashURL == "" {
		return ""
	}
	return "\n<" + dashURL + "|Open the audit log>"
}
