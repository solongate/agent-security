package sdk

import (
	"context"
	"net/http"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/api"
	"github.com/codeyevsky/solongate/proxy/internal/config"
	"github.com/codeyevsky/solongate/proxy/internal/core"
)

// The three cloud routes the SDK needs that internal/api does not have yet.
//
// They go through api.Client.Do rather than a second HTTP client, so they
// inherit the whole of that layer: the retry rule (GETs retried, mutations
// never), the per-attempt deadline, the `{ error: { code, message } }`
// envelope, and the scrubbing that keeps a key out of a transport error's
// message. Adding a second HTTP path here would mean a second place for a key
// to leak from.
//
// The client is pointed at the SDK's own key with SetViewCredentials, which
// overrides resolution WITHOUT touching disk — an embedded gateway must not
// change what this machine's guard hooks enforce with.

func newCloudClient(apiKey, apiURL string) *api.Client {
	if apiURL == "" {
		apiURL = config.DefaultAPIURL
	}
	c := api.New()
	c.SetViewCredentials(&config.Credential{APIKey: apiKey, APIURL: apiURL})
	return c
}

type cloudPolicy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Version     int               `json:"_version"`
	Rules       []core.PolicyRule `json:"rules"`
	CreatedAt   string            `json:"_created_at"`
}

// fetchDefaultPolicy reads /policies/default, the account's active policy.
func fetchDefaultPolicy(ctx context.Context, c *api.Client) (core.PolicySet, int, error) {
	var out cloudPolicy
	if err := c.Do(ctx, http.MethodGet, "/policies/default",
		api.RequestOptions{Timeout: 10 * time.Second}, &out); err != nil {
		return core.PolicySet{}, 0, err
	}
	id := out.ID
	if id == "" {
		id = "cloud"
	}
	name := out.Name
	if name == "" {
		name = "Cloud Policy"
	}
	version := out.Version
	if version == 0 {
		version = 1
	}
	rules := out.Rules
	if rules == nil {
		rules = []core.PolicyRule{}
	}
	return core.PolicySet{
		ID: id, Name: name, Description: out.Description,
		Version: version, Rules: rules, CreatedAt: out.CreatedAt,
	}, out.Version, nil
}

// auditEntry is one decision as the API records it.
type auditEntry struct {
	Tool             string         `json:"tool"`
	Arguments        map[string]any `json:"arguments"`
	Decision         string         `json:"decision"`
	Reason           string         `json:"reason"`
	MatchedRule      string         `json:"matchedRule,omitempty"`
	EvaluationTimeMs float64        `json:"evaluationTimeMs"`
}

// postAuditLog delivers one audit entry. The caller does NOT wait for it — see
// SolonGate.sendAuditLog.
func postAuditLog(ctx context.Context, c *api.Client, entry auditEntry) error {
	return c.Do(ctx, http.MethodPost, "/audit-logs",
		api.RequestOptions{Body: entry, Timeout: 5 * time.Second}, nil)
}
