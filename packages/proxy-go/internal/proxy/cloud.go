package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/api"
	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// Every cloud call the proxy runtime makes, on the CLI's own HTTP layer.
//
// They go through api.Client.Do rather than a second HTTP client so they
// inherit the whole of that layer: the retry rule (GETs retried, mutations
// never), the per-attempt deadline, the `{ error: { code, message } }`
// envelope, and the scrubbing that keeps an API key out of a transport error's
// message. A second HTTP path here would be a second place for a key to leak
// from.
//
// The client is pointed at the proxy's OWN key with SetViewCredentials, which
// overrides resolution without touching disk. A proxy started with --api-key
// must not change what this machine's guard hooks enforce with.

func newCloudClient(apiKey, apiURL string) *api.Client {
	if apiURL == "" {
		apiURL = config.DefaultAPIURL
	}
	c := api.New()
	c.SetViewCredentials(&config.Credential{APIKey: apiKey, APIURL: apiURL})
	return c
}

// ── licence ────────────────────────────────────────────────────────────────

// licenseResult says what the /auth/me call decided.
type licenseResult int

const (
	licenseOK licenseResult = iota
	licenseInvalid
	licenseInactive
	licenseUnreachable
)

// checkLicense is the proxy's licence gate, and it FAILS CLOSED ON A NETWORK
// ERROR.
//
// That is deliberately not what the embedded SDK does. The SDK lets a call
// through when the licence server is unreachable, because there it is one
// component inside somebody else's tool server and an outage at SolonGate must
// not become an outage in their product. The proxy is the product: it is
// started by an agent, it has not yet forwarded anything, and refusing to start
// leaves the agent with no MCP server rather than with an unguarded one. Those
// are opposite situations and they get opposite answers.
func checkLicense(ctx context.Context, c *api.Client) (licenseResult, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_, err := c.Auth.Me(reqCtx)
	if err == nil {
		return licenseOK, nil
	}

	var apiErr *api.Error
	if errors.As(err, &apiErr) {
		switch apiErr.Status {
		case 401:
			return licenseInvalid, err
		case 403:
			return licenseInactive, err
		case 0:
			// No answer at all: DNS, TCP, TLS or a timeout.
			return licenseUnreachable, err
		}
		// Any other status — a 500, a 502 from a proxy in front of the API — is
		// treated as validated, exactly as the Node implementation does. Only
		// 401 and 403 are answers about the key; everything else is the
		// service having a bad day, and refusing to start over it would take
		// every user offline with it.
		return licenseOK, nil
	}
	return licenseUnreachable, err
}

// ── policy ─────────────────────────────────────────────────────────────────

// fetchCloudPolicy reads the policy this proxy should enforce.
//
// With no --policy-id it lists the account's policies and takes the first, the
// same as the Node implementation. That is a weak selection rule and it is
// preserved rather than improved: changing which policy an existing install
// picks up is a silent change to what it enforces.
func fetchCloudPolicy(ctx context.Context, c *api.Client, policyID string) (PolicyDoc, error) {
	resolvedID := policyID
	if resolvedID == "" {
		// Asked over the wire rather than through c.Policies.List, which reads
		// THIS MACHINE now. Mixing the two would have the proxy resolve an id from
		// the local file and then fetch that id from a service — a policy from one
		// place carrying a name from another.
		var listed struct {
			Policies []struct {
				ID string `json:"id"`
			} `json:"policies"`
		}
		if err := c.Do(ctx, http.MethodGet, "/policies", api.RequestOptions{Timeout: 10 * time.Second}, &listed); err != nil {
			return PolicyDoc{}, err
		}
		if len(listed.Policies) == 0 {
			return PolicyDoc{}, errors.New("the service has no policies. Write one there, or drop the key and this machine enforces its own file.")
		}
		resolvedID = listed.Policies[0].ID
	}

	var fields map[string]json.RawMessage
	if err := c.Do(ctx, http.MethodGet, "/policies/"+neturl.PathEscape(resolvedID),
		api.RequestOptions{Timeout: 10 * time.Second}, &fields); err != nil {
		return PolicyDoc{}, err
	}

	raw, err := json.Marshal(fields)
	if err != nil {
		return PolicyDoc{}, err
	}
	doc, err := DecodePolicyDoc(raw)
	if err != nil {
		return PolicyDoc{}, err
	}
	if doc.Set.ID == "" {
		doc.Set.ID = "cloud"
	}
	if doc.Set.Name == "" {
		doc.Set.Name = "Cloud Policy"
	}
	if doc.Set.Version == 0 {
		doc.SetVersion(1)
	}
	return doc, nil
}

// pushPolicy writes a policy up. PUT first, POST on a 404 — the policy may not
// exist yet, and creating it is the point of the first push.
func pushPolicy(ctx context.Context, c *api.Client, cloudID string, doc PolicyDoc) (int, error) {
	payload := map[string]any{
		"id":          cloudID,
		"name":        orDefault(doc.Set.Name, "Default Policy"),
		"description": orDefault(doc.Set.Description, "Synced from proxy"),
		"version":     orOne(doc.Set.Version),
		"rules":       doc.RawRules(),
	}

	var out map[string]json.RawMessage
	err := c.Do(ctx, http.MethodPut, "/policies/"+neturl.PathEscape(cloudID),
		api.RequestOptions{Body: payload, Timeout: 15 * time.Second}, &out)
	if err == nil {
		return versionOf(out, doc.Set.Version), nil
	}

	var apiErr *api.Error
	if errors.As(err, &apiErr) && apiErr.Status == 404 {
		out = nil
		if err := c.Do(ctx, http.MethodPost, "/policies",
			api.RequestOptions{Body: payload, Timeout: 15 * time.Second}, &out); err != nil {
			return 0, err
		}
		return versionOf(out, doc.Set.Version), nil
	}
	return 0, err
}

func versionOf(out map[string]json.RawMessage, fallback int) int {
	if raw, ok := out["_version"]; ok {
		var n int
		if json.Unmarshal(raw, &n) == nil && n != 0 {
			return n
		}
	}
	return fallback
}

// ── audit ──────────────────────────────────────────────────────────────────

// auditEntry is one decision as the API records it. The snake_case members are
// the API's spelling, not this port's choice.
type auditEntry struct {
	Tool             string         `json:"tool"`
	Arguments        map[string]any `json:"arguments"`
	Decision         string         `json:"decision"`
	Reason           string         `json:"reason"`
	Permission       string         `json:"permission,omitempty"`
	MatchedRule      string         `json:"matchedRule,omitempty"`
	EvaluationTimeMs int64          `json:"evaluationTimeMs"`
	AgentID          string         `json:"agent_id,omitempty"`
	AgentName        string         `json:"agent_name,omitempty"`
	SubAgentID       string         `json:"sub_agent_id,omitempty"`
	SubAgentName     string         `json:"sub_agent_name,omitempty"`
	// Timestamp is only written to the local backup file. The API stamps its
	// own, and sending one would let a clock-skewed machine reorder somebody
	// else's audit trail.
	Timestamp string `json:"timestamp,omitempty"`
}

const auditMaxRetries = 3

// auditBackupPath is resolved against the working directory the proxy started
// in, like the Node implementation's `resolve('.solongate-audit-backup.jsonl')`.
func auditBackupPath() string {
	abs, err := filepath.Abs(".solongate-audit-backup.jsonl")
	if err != nil {
		return ".solongate-audit-backup.jsonl"
	}
	return abs
}

// sendAuditLog delivers one decision, retrying a server error and never a
// client one.
//
// A 4xx is an answer: the entry is malformed or the key is not allowed to write
// it, and sending it again produces the same answer while delaying the next
// one. A 5xx or a dropped connection is not an answer, so it is retried, and if
// every attempt fails the entry goes to a local file rather than being lost —
// an audit trail with a hole in it is worse than one that is late.
func sendAuditLog(ctx context.Context, c *api.Client, entry auditEntry, log func(string)) {
	for attempt := 0; attempt < auditMaxRetries; attempt++ {
		err := c.Do(ctx, http.MethodPost, "/audit-logs",
			api.RequestOptions{Body: entry, Timeout: 5 * time.Second}, nil)
		if err == nil {
			return
		}
		var apiErr *api.Error
		if errors.As(err, &apiErr) && apiErr.Status >= 400 && apiErr.Status < 500 {
			log("Audit log rejected (" + strconv.Itoa(apiErr.Status) + "): " + apiErr.Message)
			return
		}
		if attempt < auditMaxRetries-1 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(500*(1<<attempt)) * time.Millisecond):
			}
		}
	}

	log("Audit log failed after " + strconv.Itoa(auditMaxRetries) + " retries, saving to local backup.")
	entry.Timestamp = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	line, err := json.Marshal(entry)
	if err != nil {
		log("Audit backup encode error: " + err.Error())
		return
	}
	f, err := os.OpenFile(auditBackupPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log("Audit backup write error: " + err.Error())
		return
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		log("Audit backup write error: " + err.Error())
	}
}

// ── registration ───────────────────────────────────────────────────────────

type toolRegistration struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
	Permissions []string       `json:"permissions"`
	Enabled     bool           `json:"enabled"`
}

// registerTool makes one tool visible on the dashboard. A 409 means it is
// already there, which is the normal case on every restart.
func registerTool(ctx context.Context, c *api.Client, tool toolRegistration) error {
	err := c.Do(ctx, http.MethodPost, "/tools",
		api.RequestOptions{Body: tool, Timeout: 15 * time.Second}, nil)
	if err == nil {
		return nil
	}
	var apiErr *api.Error
	if errors.As(err, &apiErr) && apiErr.Status == 409 {
		return nil
	}
	return err
}

type serverRegistration struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Command string `json:"command,omitempty"`
	Args    string `json:"args,omitempty"`
}

// registerServer records the upstream on the dashboard's MCP Servers page.
// Returns the HTTP status so the caller can tell "created" from "already
// known", which read very differently in the log.
func registerServer(ctx context.Context, c *api.Client, reg serverRegistration) (int, error) {
	err := c.Do(ctx, http.MethodPost, "/mcp-servers",
		api.RequestOptions{Body: reg, Timeout: 15 * time.Second}, nil)
	if err == nil {
		return 200, nil
	}
	var apiErr *api.Error
	if errors.As(err, &apiErr) {
		return apiErr.Status, err
	}
	return 0, err
}

// ── small helpers ──────────────────────────────────────────────────────────

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func orOne(v int) int {
	if v == 0 {
		return 1
	}
	return v
}
