package main

// Keeping the cached policy current.
//
// The cache is `~/.solongate/.policy-cache-<agent>.json` and it is the ONLY
// thing this binary evaluates against: the Rego is compiled in-process from
// whatever policy is in there. Nothing in this program used to write it. The
// Node hook did, and only on the path where it decides the call itself — it
// hands over to this binary near the top of the file, well before its own
// stale-while-revalidate ever runs.
//
// So on a machine with the native binary installed, which is every machine that
// has a published platform package, the cache went stale and stayed stale. A
// rule added, changed or revoked in the dashboard never reached the guard, and
// nothing said so: denials went on citing rules the user had already deleted,
// and the policy they were reading in `policy active` was not the one being
// enforced.
//
// The refresh is a detached child, exactly like the audit post beside it. It
// must never be on the hot path — a tool call waiting on a network round trip
// is the thing the whole binary exists to avoid — so this call's verdict is
// answered from the cache that is there, and the refresh rewrites it for the
// NEXT call. A policy change therefore lands within one tool call, which is the
// same guarantee the Node implementation gives.

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/codeyevsky/solongate/sgshared"
)

// How old a cache may be before a refresh is kicked off. The Node hook's
// POLICY_TTL_MS, and it has to stay the same number: with both implementations
// installed, two different windows would mean the policy a machine enforces
// depends on which one answered.
const policyCacheTTL = 10 * time.Second

// policyCachePath is the file both implementations share.
func policyCachePath(agent string) string {
	return filepath.Join(sgshared.SGDir(), ".policy-cache-"+sgshared.AgentKey(agent)+".json")
}

// cacheIsStale reports whether the cached policy is old enough to refresh.
// A cache that is absent or unreadable is stale: there is nothing to trust.
func cacheIsStale(c *sgshared.PolicyCache) bool {
	if c == nil || c.TS == 0 {
		return true
	}
	return time.Since(time.UnixMilli(c.TS)) >= policyCacheTTL
}

// refreshPolicyDetached spawns this binary to rewrite the cache and returns
// immediately.
//
// Fire and forget in the strongest sense: the child is released, nothing waits
// on it, and every failure inside it leaves the existing cache alone. A refresh
// that cannot run must never be able to disarm a guard that is working.
// refreshGrace is how long a stale cache may hold a call while it catches up.
//
// It was 300ms and spent on a CHILD PROCESS doing the fetch: a spawn, a Go
// runtime start, a DNS lookup and a TLS handshake, and only then the request.
// That is comfortably more than 300ms on a cold connection, so the wait almost
// always expired and the call went out on the stale policy anyway -- which is
// the thing the wait was added to stop.
//
// The fetch is in-process now, so this budget buys the round trip itself rather
// than a process start. 1.2s is chosen against what it is competing with: a rule
// the user changed seconds ago and expects to be in force, versus one slow call
// per TTL at worst. A network that needs longer than this is one where waiting
// further would be the wrong answer, and the cache is still there.
const refreshGrace = 1200 * time.Millisecond

// waitForRefresh blocks until the child signals it wrote the cache, or the bound
// passes. Reports whether the cache is worth re-reading.
//
// Kept for the path where a refresh is already in flight from somewhere else;
// the hot path fetches in-process instead.
func waitForRefresh(done <-chan struct{}, d time.Duration) bool {
	select {
	case <-done:
		return true
	case <-time.After(d):
		// Not a failure. The child keeps running and its write lands for the next
		// call, which is the behaviour this had before the wait existed.
		return false
	}
}

// refreshPolicyDetached spawns the refresh and returns a channel that closes
// when the child exits, or nil when no child could be started.
//
// The channel is what lets ONE caller wait a bounded moment for it; nothing is
// required to. The child is still fire-and-forget: it is released either way and
// its failure modes are unchanged.
func refreshPolicyDetached(cred sgshared.Credential, agent string) <-chan struct{} {
	if cred.APIKey == "" {
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		return nil
	}
	payload, err := json.Marshal(map[string]string{
		"url":   cred.APIURL,
		"key":   cred.APIKey,
		"agent": agent,
	})
	if err != nil {
		return nil
	}
	cmd := exec.Command(self, "--sg-refresh-policy", base64.StdEncoding.EncodeToString(payload))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	detach(cmd)
	if cmd.Start() != nil {
		return nil
	}

	// Waited on in a goroutine rather than released outright, so a caller can
	// learn the cache has been rewritten. The wait is what reaps the child; a
	// caller that stops listening leaves this goroutine to finish on its own and
	// the process exits regardless.
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	return done
}

// fetchAndWriteCache is what a refresh IS: fetch the active policy, write the
// cache, report whether the file on disk is now current.
//
// One implementation, called both in-process (bounded, on the hot path) and
// from the detached child. Two would drift, and the thing that would drift is
// which policy a machine enforces.
//
// The written shape is the Node hook's, field for field, because both read it.
// `security` is written whenever the KEY was present, including as null — a
// project with DLP configured and no policy would otherwise lose DLP every time
// this ran.
func fetchAndWriteCache(apiURL, key, agent string, timeout time.Duration) bool {
	if key == "" || apiURL == "" {
		return false
	}
	req, err := http.NewRequest(http.MethodGet, apiURL+"/api/v1/policies/active", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("X-Agent-Id", agent)

	res, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		// A 4xx here is an answer about the KEY, not about the policy, and the
		// cache that is already on disk is a better guess than nothing.
		return false
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return false
	}

	// Decoded into a map rather than a struct so a field this version does not
	// know about survives the round trip. The Node hook reads the same file and
	// may understand more of it than this binary does.
	var doc map[string]json.RawMessage
	if json.Unmarshal(body, &doc) != nil {
		return false
	}

	// The VERSION this response describes. Kept for two reasons: `solongate
	// trace` can say which policy a call was judged against, and the write below
	// can refuse to go backwards.
	fetchedVersion := int64(0)
	if v, ok := doc["version"]; ok {
		_ = json.Unmarshal(v, &fetchedVersion)
	}

	// Two refreshes can be in flight at once — one per tool call, and calls
	// overlap. If a slow one started before a rule was added and lands after a
	// fast one that already wrote the new policy, it overwrites it with the OLD
	// policy under a FRESH timestamp: the guard then enforces the superseded
	// rules and considers the cache current for another full TTL.
	//
	// That is an intermittent stale ALLOW with nothing to see afterwards, which
	// is the worst shape a bug in this file can take. So a response never
	// replaces a cache that already describes a NEWER version.
	if fetchedVersion > 0 {
		if cur := readCachedVersion(policyCachePath(agent)); cur > fetchedVersion {
			return false
		}
	}

	out := map[string]interface{}{"_ts": time.Now().UnixMilli()}
	out["policy"] = jsonOrNull(doc["policy"])
	out["selfProtect"] = jsonOrNull(doc["self_protection_enabled"])
	if fetchedVersion > 0 {
		out["policyVersion"] = fetchedVersion
	}
	if v, ok := doc["security"]; ok {
		out["security"] = jsonOrNull(v)
	}
	if v, ok := doc["hook_versions"]; ok {
		out["hookVersions"] = jsonOrNull(v)
	}

	// Whether this machine is under somebody else's policy, recorded OUTSIDE
	// the per-agent cache.
	//
	// It cannot live in the cache: that file's name comes from
	// SOLONGATE_AGENT_ID, so naming an agent nobody has ever used would produce
	// no cache and therefore no managed flag, which is precisely the escape
	// this is closing. sgshared.SaveFleet writes only on a change, because this
	// runs behind every tool call.
	//
	// The error is dropped for the same reason every other write on this path
	// drops one: a poll that could not update a file must not fail the tool
	// call, and the state on disk is still the last answer.
	_ = sgshared.SaveFleet(sgshared.FleetState{Managed: jsonTrue(doc["managed"])})

	encoded, err := json.Marshal(out)
	if err != nil {
		return false
	}

	// Written through a temp file in the same directory and renamed, so a call
	// reading the cache while this runs sees the old file or the new one and
	// never a half-written one. A torn cache reads as "no policy".
	dir := sgshared.SGDir()
	if os.MkdirAll(dir, 0o755) != nil {
		return false
	}
	tmp, err := os.CreateTemp(dir, ".policy-cache-*.tmp")
	if err != nil {
		return false
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return false
	}
	if tmp.Close() != nil {
		_ = os.Remove(tmpName)
		return false
	}
	if os.Rename(tmpName, policyCachePath(agent)) != nil {
		_ = os.Remove(tmpName)
		return false
	}
	return true
}

// runPolicyRefresh is the detached child's whole job.
func runPolicyRefresh(arg string) {
	raw, err := base64.StdEncoding.DecodeString(arg)
	if err != nil {
		return
	}
	var p struct {
		URL   string `json:"url"`
		Key   string `json:"key"`
		Agent string `json:"agent"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return
	}
	fetchAndWriteCache(p.URL, p.Key, p.Agent, 8*time.Second)
}

// readCachedVersion is the policy version the cache on disk describes, or 0 for
// a cache that is absent, unreadable, or was written before the field existed.
//
// Zero means "cannot tell", and a caller must treat that as no obstacle: a
// cache with no version is one written by an older build or by the Node hook,
// and refusing to replace it would freeze the machine on whatever it holds.
func readCachedVersion(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var probe struct {
		PolicyVersion int64 `json:"policyVersion"`
	}
	if json.Unmarshal(b, &probe) != nil {
		return 0
	}
	return probe.PolicyVersion
}

// jsonOrNull keeps a raw field as itself, mapping an absent one to null.
func jsonOrNull(v json.RawMessage) interface{} {
	if len(v) == 0 {
		return nil
	}
	return json.RawMessage(v)
}

// jsonTrue reads a boolean out of ONE RAW FIELD of the decoded response.
//
// It takes json.RawMessage and not interface{}, and that signature is the fix
// rather than a tidy-up. The document above is unmarshalled into
// map[string]json.RawMessage so that a field this binary does not know about
// still survives the round trip — which means every value in that map is a
// []byte and never a decoded bool. The previous version took interface{} and
// type-asserted to bool, an assertion a json.RawMessage cannot satisfy, so it
// answered false on every call this package ever made. `managed` was therefore
// false on every machine in the field, sgshared.SaveFleet saw no change from
// the zero value and returned before writing, and ~/.solongate/.fleet.json was
// never created anywhere. Everything that reads it — the environment-key
// escape in config.go, the agent-id escape in main.go, the local policy.json
// refusal, and the whole managed CLI refusal list in proxy-go — was inert.
//
// It went unnoticed because the sibling fields do not share the bug: policy,
// self_protection_enabled, security and hook_versions all go through
// jsonOrNull, which passes the bytes along. managed was the only field routed
// through a type assertion, and this is that function's only caller.
//
// Only a real `true` counts. Anything else — absent, null, a string, a number,
// malformed JSON — is false, which is the same rule the hook applies to
// self_protection_enabled and for the same reason: a value this code does not
// recognise must not be read as an instruction. An absent key arrives here as a
// nil RawMessage and Unmarshal refuses it, which is the answer we want: the API
// sends `managed` with omitempty, so an unmanaged machine gets no key at all.
func jsonTrue(raw json.RawMessage) bool {
	var b bool
	return json.Unmarshal(raw, &b) == nil && b
}
