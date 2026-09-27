package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/hookbundle"
	"github.com/codeyevsky/solongate/system/internal/policyjson"
	"github.com/codeyevsky/solongate/system/internal/store"
)

// GET /api/v1/policies/active — the endpoint every installed guard polls.
//
// This is the most consequential response in the service. A guard fetches it on
// a ten-second cache, writes the result to ~/.solongate/.policy-cache-<agent>.json
// and enforces whatever it says until the next successful fetch. Four fields are
// read off it and each one decides something a machine then does:
//
//	policy                  — the rules. Absent or null means the guard has no
//	                          dashboard policy and falls back to a local
//	                          policy.json, or to enforcing nothing.
//	self_protection_enabled — the tamper guard. Only a BOOLEAN is honoured; the
//	                          hook's `typeof === 'boolean'` test means any other
//	                          value leaves the cached value alone, and the
//	                          default is ON.
//	security                — the DLP, rate-limit, ghost and local-log layers.
//	hook_versions           — what makes a device self-update.
//
// The one that has to be exactly right is `security`, because the guard
// distinguishes the key being ABSENT from its value being NULL:
//
//	security = body?.security !== undefined ? body.security : null
//
// and sgshared.PolicyCache carries a HasSecurity flag for the same reason. A
// present null REPLACES the cached configuration — that is how switching local
// logging off in the dashboard reaches a laptop. Omitting the key instead would
// leave a stale block in place forever, which is precisely the bug the comment
// in guard.mjs is about. So this route ALWAYS sends `security`, on every branch,
// including the ones where there is no policy at all.
//
// The same goes for `localLogs` inside it: guardEnforcementConfig returns five
// members and the live route then assigns a sixth unconditionally, so the object
// always has all six. Six nulls is a meaningful answer. A missing key is not.

// activePolicyResponse is the wire shape, in the live app's field order.
//
// Version, Hash and MatchedBy are omitempty because the null-policy branches
// genuinely do not carry them, and the CLI's ActivePolicy declares them the
// same way. Policy, SelfProtectionEnabled, Security and HookVersions are NOT
// omitempty for the reason in the file note: their zero values are answers.
type activePolicyResponse struct {
	Policy                json.RawMessage      `json:"policy"`
	Version               int64                `json:"version,omitempty"`
	Hash                  string               `json:"hash,omitempty"`
	MatchedBy             string               `json:"matched_by,omitempty"`
	SelfProtectionEnabled bool                 `json:"self_protection_enabled"`
	Security              *store.GuardSecurity `json:"security"`
	HookVersions          activeHookVersions   `json:"hook_versions"`

	//
	// omitempty, and that is load bearing twice over. On the no-policy branch
	// there is no variant and the response has to keep the exact key set the
	// tests pin. And for a policy with no variants at all — every policy
	// written before the bundle — the key is absent, so the response is
	// byte-for-byte what it was. It is here for the dashboard and for `solongate
	// policy active`, which can say WHICH of the host's settings is running; a
	// deployed guard decodes into a map and ignores it.

	// Managed says this key belongs to a developer working under somebody
	// else's policy.
	//
	// The guard needs it before it decides which credential to trust, and by
	// then it has not polled anything — so it keeps the last answer on disk and
	// reads that first. This is where the answer comes from.
	//
	// omitempty, so the response to every non-guest is byte-for-byte what it
	// was, including on the no-policy branch the tests pin.
	Managed bool `json:"managed,omitempty"`
}

// activeHookVersions is HOOK_VERSIONS. The numbers come from
// internal/hookbundle — the same table GET /v1/hooks/{name} serves — so this
// endpoint cannot advertise a version the bundle route would not hand over. A
// device told about a guard 81 that /hooks/guard answers with 80 self-updates
// on every single tool call and never stops.
type activeHookVersions struct {
	Guard  int64 `json:"guard"`
	Audit  int64 `json:"audit"`
	Shield int64 `json:"shield"`
}

func activeHookVersionsNow() activeHookVersions {
	get := func(name string) int64 {
		b, ok := hookbundle.Get(name)
		if !ok {
			return 0
		}
		return b.Version
	}
	return activeHookVersions{Guard: get("guard"), Audit: get("audit"), Shield: get("shield")}
}

func (s *server) policyActiveGet(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	if key.ProjectID == "" {
		// The live app's first line, kept verbatim even though withAuth cannot
		// produce a key without a project: it answers `{policy: null}` and
		// NOTHING else — no security, no hook_versions. A guard reading that
		// keeps whatever it had cached, which is the right behaviour for a
		// response that means "I do not know who you are".
		apiauth.JSON(w, http.StatusOK, map[string]any{"policy": nil})
		return
	}

	ctx := r.Context()
	q := r.URL.Query()
	agentID := q.Get("agent_id")

	// `hv` and `clients` are telemetry the DEVICE reports about itself: which
	// guard version it is running and which clients it is registered for.
	// Recorded without blocking the response, because this is the guard's hot
	// path — the original spells that as a bare `void recordGuardVersion(...)`.
	if hv, ok := policyParseIntOK(q.Get("hv")); ok {
		deviceID := key.KeyID
		if deviceID == "" {
			deviceID = "unknown"
		}
		clients := policySplitClients(q.Get("clients"))
		go s.recordGuardVersionAsync(context.WithoutCancel(ctx), key.ProjectID, hv, deviceID, agentID, clients)
	}

	// The five reads run TOGETHER, as the original's Promise.all does, and it
	// is not a micro-optimisation here. This is the guard's poll: it runs
	// before tool calls on every machine in the fleet, and five Turso round
	// trips in series is five times the latency of one — long enough that the
	// hook's two-second budget starts expiring and devices fall back to a
	// cached policy they should not have needed.
	var (
		layers      store.SecurityLayers
		localLogs   store.LocalLogsConfig
		selfProtect bool
		rows        []store.ActivePolicyRow
		rowsErr     error
		override    string
		wg          sync.WaitGroup
	)
	wg.Add(5)
	go func() { defer wg.Done(); layers = s.store.GetSecurityLayers(ctx, key.ProjectID) }()
	go func() { defer wg.Done(); localLogs = s.store.GetLocalLogs(ctx, key.ProjectID) }()
	go func() { defer wg.Done(); selfProtect = s.store.SelfProtectionEnabled(ctx, key.ProjectID) }()
	go func() { defer wg.Done(); rows, rowsErr = s.store.PolicyVersionsForSelection(ctx, key.ProjectID) }()
	go func() { defer wg.Done(); override = s.store.ActivePolicyOverride(ctx, key.ProjectID) }()
	wg.Wait()

	// Only the policy read can fail the request. The other four swallow their
	// errors into safe defaults inside the store — self-protection ON, layers
	// in detect — because a settings blip must not stop a policy from being
	// delivered.
	if rowsErr != nil {
		apiauth.Internal(w, "api", rowsErr)
		return
	}

	security := store.GuardEnforcementConfig(layers)
	security.LocalLogs = &localLogs

	base := activePolicyResponse{
		SelfProtectionEnabled: selfProtect,
		Security:              &security,
		HookVersions:          activeHookVersionsNow(),
	}

	if len(rows) == 0 {
		apiauth.JSON(w, http.StatusOK, base)
		return
	}

	latest := policyLatestPerID(rows)

	if override == store.ActivePolicyNone {
		// Deliberately deactivated. Distinct from "no override set", which
		// falls through to recency selection — the difference between a project
		// that enforces nothing on purpose and one that enforces its newest
		// policy.
		apiauth.JSON(w, http.StatusOK, base)
		return
	}
	if override != "" {
		if pinned, ok := latest.get(override); ok {
			out := base
			out.Policy = pinned.PolicyData
			out.Version = pinned.Version
			out.Hash = pinned.Hash
			out.MatchedBy = "pinned"
			policyApplyBundle(&out, pinned.PolicyData, localLogs)
			apiauth.JSON(w, http.StatusOK, out)
			return
		}
		// The pinned policy has been deleted. Falling through to recency
		// selection rather than answering "no policy" is the live behaviour and
		// the safer one: a deleted pin must not silently disarm a fleet.
	}

	chosen, matchedBy := policySelectForAgent(latest, agentID)
	if chosen == nil {
		apiauth.JSON(w, http.StatusOK, base)
		return
	}

	out := base
	out.Policy = chosen.PolicyData
	out.Version = chosen.Version
	out.Hash = chosen.Hash
	out.MatchedBy = matchedBy
	policyApplyBundle(&out, chosen.PolicyData, localLogs)
	apiauth.JSON(w, http.StatusOK, out)
}

// policyApplyBundle is the one place a bundled policy meets the wire.
//
// It does two things and both are about what a guard sees. The document is
// projected — the bundle keys stripped — so an installed binary parses exactly
// the shape it always has. And the security block is replaced when the policy
// carries one, because
// a policy that names its own DLP means to override the project's setting
// rather than to sit beside it.
//
// LocalLogs is assigned again on this path and not inherited, because it is the
// only member of the security object with `omitempty` on it: it reaches the
// wire because policyActiveGet sets it, and a branch that builds a fresh block
// without it drops the key. A guard reads an absent key as "no answer" and
// freezes whatever it had, which is how local logging would become impossible
// to switch off on a machine that had it on.
func policyApplyBundle(out *activePolicyResponse, policyData []byte, localLogs store.LocalLogsConfig) {
	p := policyProject(policyData)
	out.Policy = p.Document
	if !p.HasLayers {
		return
	}
	security := store.GuardEnforcementConfig(p.Layers)
	security.LocalLogs = &localLogs
	out.Security = &security
}

// ── selection ───────────────────────────────────────────────────────────────

// policyOrderedLatest is the newest version of each distinct policy id, in the
// order the ids were first seen.
//
// The order is not cosmetic. Selection below breaks ties with a strict `>` on
// created_at, so when two policies were written in the same second the FIRST
// one iterated wins — and a JavaScript Map iterates in insertion order. A Go
// map here would pick a different policy on different requests, which is a guard
// that enforces one policy on one poll and another on the next.
type policyOrderedLatest struct {
	ids  []string
	rows map[string]*store.ActivePolicyRow
}

func (m *policyOrderedLatest) get(id string) (*store.ActivePolicyRow, bool) {
	r, ok := m.rows[id]
	return r, ok
}

// policyLatestPerID groups the project's versions by the id INSIDE policy_data.
//
// A policy with no id is bucketed under `__anonymous__`, exactly as the
// original does, so several unnamed policies collapse into one rather than each
// becoming its own candidate.
func policyLatestPerID(rows []store.ActivePolicyRow) *policyOrderedLatest {
	m := &policyOrderedLatest{rows: map[string]*store.ActivePolicyRow{}}
	for i := range rows {
		row := &rows[i]
		id := "__anonymous__"
		if p, ok := policyjson.ParseObject(row.PolicyData); ok {
			if s := policyjson.Str(p.Get("id")); s != "" {
				id = s
			}
		}
		existing, seen := m.rows[id]
		if !seen {
			m.ids = append(m.ids, id)
			m.rows[id] = row
			continue
		}
		if row.Version > existing.Version {
			m.rows[id] = row
		}
	}
	return m
}

// policySelectForAgent is the three-tier match the guard's policy comes from.
//
//	policy-id — the caller's agent_id IS a policy id. This is the "Use in
//	            terminal" button: the dashboard puts a policy id in
//	            SOLONGATE_AGENT_ID and the guard sends it as agent_id.
//	agent     — the policy lists this agent in its `agents` array.
//	wildcard  — the policy lists `*`, which is also what a policy with no
//	            `agents` array at all is treated as.
//
// Within a tier the NEWEST by created_at wins. The `else if` between the
// specific and wildcard branches is the original's and is load-bearing: a
// policy that matches the agent explicitly is never also considered as a
// wildcard candidate, so it cannot displace a newer wildcard policy from a tier
// it does not belong to.
func policySelectForAgent(m *policyOrderedLatest, agentID string) (*store.ActivePolicyRow, string) {
	var direct, specific, wildcard *store.ActivePolicyRow

	for _, id := range m.ids {
		row := m.rows[id]
		p, ok := policyjson.ParseObject(row.PolicyData)
		if !ok {
			// `if (!p) continue` — a version whose policy_data is null or is
			// not an object is not a candidate.
			continue
		}

		// `Array.isArray(p.agents) && p.agents.length > 0 ? p.agents : ['*']` —
		// a policy with no agent list, or an empty one, applies everywhere.
		agents := []string{"*"}
		if arr, isArr := policyjson.Array(p.Get("agents")); isArr && len(arr) > 0 {
			agents = make([]string, 0, len(arr))
			for _, v := range arr {
				agents = append(agents, policyjson.Str(v))
			}
		}

		if agentID != "" && policyjson.Str(p.Get("id")) == agentID {
			if direct == nil || row.CreatedAt > direct.CreatedAt {
				direct = row
			}
			continue
		}

		matchesSpecific := agentID != "" && policyContains(agents, agentID)
		matchesWildcard := policyContains(agents, "*")

		// The `else` binds to the WHOLE first condition, timestamp included.
		// A policy that names this agent but is older than the current
		// specific candidate therefore falls through and is still considered
		// as a wildcard — which is not what the shape of the code suggests and
		// is what the live app does. Written out rather than switched on
		// matchesSpecific alone, because those two are not the same program.
		if matchesSpecific && (specific == nil || row.CreatedAt > specific.CreatedAt) {
			specific = row
		} else if matchesWildcard && (wildcard == nil || row.CreatedAt > wildcard.CreatedAt) {
			wildcard = row
		}
	}

	switch {
	case direct != nil:
		return direct, "policy-id"
	case specific != nil:
		return specific, "agent"
	case wildcard != nil:
		return wildcard, "wildcard"
	}
	return nil, ""
}

func policyContains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// ── POST /api/v1/policies/active ────────────────────────────────────────────

// policyActiveSet pins the policy the guard should use, or deactivates the
// project entirely.
//
// An empty or missing policyId is not a no-op: it stores the `__none__`
// sentinel, which the GET above reads as "this project enforces nothing". That
// is the dashboard's off switch, and collapsing it to "no override" would turn
// it into "enforce the newest policy" — the opposite of what the operator
// clicked.
func (s *server) policyActiveSet(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	if key.ProjectID == "" {
		// The live app answers this with a bare `{error: 'No project'}` at 400,
		// NOT the service's error envelope. It is reproduced rather than
		// normalised because it is what is deployed.
		apiauth.JSON(w, http.StatusBadRequest, map[string]any{"error": "No project"})
		return
	}

	var body struct {
		PolicyID any `json:"policyId"`
	}
	// `.catch(() => ({}))`: an unparseable body deactivates, because that is
	// what `typeof undefined === 'string'` being false leads to.
	if !apiauth.DecodeJSON(w, r, &body, true) {
		return
	}
	policyID, _ := body.PolicyID.(string)

	if err := s.store.SetActivePolicyOverride(r.Context(), key.ProjectID, policyID); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	// `active` echoes null rather than "" when nothing was pinned; the
	// dashboard tests it for null to decide whether to show "no active policy".
	var active any
	if policyID != "" {
		active = policyID
	}
	apiauth.JSON(w, http.StatusOK, struct {
		OK     bool `json:"ok"`
		Active any  `json:"active"`
	}{true, active})
}

// ── guard version telemetry ─────────────────────────────────────────────────

// The port of src/lib/guard-version.ts's recordGuardVersion.
//
// It lives here rather than in the store because /policies/active is the only
// writer: the poll IS the report. /v1/settings/guard-status reads the same row
// and belongs to another slice; both go through the store's closed set of
// setting names, so neither can be handed a key from a request.
//
// Everything about it is best-effort. A failure is logged and dropped, never
// propagated — telemetry must not be able to fail a policy delivery, which is
// the one thing this endpoint exists to do.

const (
	// guardActiveWindow is fourteen days. A device that has not polled inside
	// it is dropped from the map, which is what keeps the row from growing
	// forever as laptops are reimaged.
	guardActiveWindow = 14 * 24 * time.Hour

	// The caps are the original's slice() bounds: 64 characters per name,
	// sixteen clients per device.
	guardNameMax    = 64
	guardClientsMax = 16
)

// guardDeviceEntry is one device's row in the stored map. `agents` is the
// older, weaker signal — which client last called in — and `clients` is what
// the device says it is REGISTERED for, which is the question `doctor` and
// `repair` answer. Both are kept because a device running an older guard sends
// only the first.
type guardDeviceEntry struct {
	Version int64            `json:"v"`
	TS      int64            `json:"ts"`
	Agents  map[string]int64 `json:"agents,omitempty"`
	Clients []string         `json:"clients,omitempty"`
}

func (s *server) recordGuardVersionAsync(ctx context.Context, projectID string, version int64, deviceID, agent string, clients []string) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.recordGuardVersion(ctx, projectID, version, deviceID, agent, clients); err != nil {
		// The project id is logged and the device id is not: the device id is
		// an API key's database id, and a log of which keys are live is a list
		// of what to go looking for.
		log.Printf("api: could not record a guard version for project %s: %v", projectID, err)
	}
}

func (s *server) recordGuardVersion(ctx context.Context, projectID string, version int64, deviceID, agent string, clients []string) error {
	if deviceID == "" {
		return nil
	}
	nowMS := store.NowMS()

	devices := map[string]guardDeviceEntry{}
	if raw, ok, err := s.store.SettingJSON(ctx, store.SettingGuardVersions, projectID); err == nil && ok && raw != "" {
		// A row that will not decode is replaced rather than repaired. It is
		// telemetry; the alternative is one bad write jamming every future one.
		_ = json.Unmarshal([]byte(raw), &devices)
	}

	entry := devices[deviceID]

	// Each poll reports ONE agent, so the previous timestamps are carried
	// forward — overwriting the map would erase the other three clients on
	// every call.
	agents := map[string]int64{}
	for k, v := range entry.Agents {
		agents[k] = v
	}
	if agent != "" {
		agents[store.Clip(agent, guardNameMax)] = nowMS
	}
	for a, t := range agents {
		if nowMS-t > guardActiveWindow.Milliseconds() {
			delete(agents, a)
		}
	}

	// The reported list REPLACES the stored one — it is a full snapshot of what
	// is registered right now, so a client the user removed has to disappear.
	// Only when the device sends nothing at all is the previous list kept,
	// which is how an older guard that does not report this yet keeps its row.
	kept := entry.Clients
	if len(clients) > 0 {
		kept = clients
		if len(kept) > guardClientsMax {
			kept = kept[:guardClientsMax]
		}
		for i := range kept {
			kept[i] = store.Clip(kept[i], guardNameMax)
		}
	}

	next := guardDeviceEntry{Version: version, TS: nowMS}
	if len(agents) > 0 {
		next.Agents = agents
	}
	if len(kept) > 0 {
		next.Clients = kept
	}
	devices[deviceID] = next

	for id, d := range devices {
		if nowMS-d.TS > guardActiveWindow.Milliseconds() {
			delete(devices, id)
		}
	}

	value, err := json.Marshal(devices)
	if err != nil {
		return err
	}
	return s.store.SetSettingJSON(ctx, store.SettingGuardVersions, projectID, string(value),
		"Per-device guard hook versions")
}

// policySplitClients parses `?clients=claude-code,codex`, dropping empties.
// The names are the device's own answer to "what am I registered for", and
// nothing here validates them against a list — an unrecognised client is stored
// and simply not surfaced in the UI, which is what lets a new one appear
// without a deploy.
func policySplitClients(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
