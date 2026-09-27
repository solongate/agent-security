package main

// The port of src/lib/starter-policy.ts: the policy every new project is seeded
// with, written by /v1/auth/session in the same request that creates the
// project.
//
// It lives in this slice because /v1/auth/session is the only route that writes
// it. It is NOT policy evaluation — packages/guard-go owns json-to-rego, the
// extractors and the OPA glue, and nothing here compiles or interprets a rule.
// This file produces the JSON document and its hash and hands both to the
// store.
//
// Why the seed exists at all: a project with no policy means an installed guard
// that permits everything, which is worse than no guard, because the person
// believes they are protected. Provisioning ships this so that enforcement is
// live the moment the first device pairs.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/codeyevsky/solongate/system/internal/store"
)

// The rules are declared as Go structs rather than as a map, and that is the
// load-bearing decision in this file.
//
// The hash stored beside a policy is the SHA-256 of the bytes that were stored,
// and Go's encoder sorts a map's keys while JSON.stringify preserves insertion
// order. Encoding a map here would produce a different serialisation for the
// same policy, so the document and its hash would still agree with each other
// but would stop being comparable with anything the Node app wrote. A struct
// serialises in FIELD DECLARATION ORDER, so the field order below is the key
// order in the original object literal and has to stay that way.

// starterConstraint is one `{ denied: [...] }` block. The four constraint kinds
// carry the same shape and differ only in which field a rule sets.
type starterConstraint struct {
	Denied []string `json:"denied"`
}

// starterRule is the rule() helper's output: the shared fields, then the single
// constraint the caller spread in. Exactly one of the four pointers is set, so
// omitempty renders the constraint in the position the spread put it — after
// `enabled`.
//
// One constraint type per rule, single-star globs, no catch-alls: the same
// rules the policy editor enforces, so this can be edited from day one instead
// of being a document the UI refuses to save.
type starterRule struct {
	ID                string             `json:"id"`
	Description       string             `json:"description"`
	Effect            string             `json:"effect"`
	Priority          int                `json:"priority"`
	ToolPattern       string             `json:"toolPattern"`
	MinimumTrustLevel string             `json:"minimumTrustLevel"`
	Enabled           bool               `json:"enabled"`
	Command           *starterConstraint `json:"commandConstraints,omitempty"`
	Filename          *starterConstraint `json:"filenameConstraints,omitempty"`
	Path              *starterConstraint `json:"pathConstraints,omitempty"`
	URL               *starterConstraint `json:"urlConstraints,omitempty"`
}

type starterPolicySet struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Mode        string        `json:"mode"`
	Rules       []starterRule `json:"rules"`
}

// authStarterPolicy builds the document. Every id is a fresh UUID, as in the
// original, so two projects seeded a second apart do not share rule ids.
func authStarterPolicy(newID func() string) (starterPolicySet, bool) {
	ids := make([]string, 7)
	for i := range ids {
		ids[i] = newID()
		if ids[i] == "" {
			return starterPolicySet{}, false
		}
	}

	rule := func(i int, description string, priority int) starterRule {
		return starterRule{
			ID:                ids[i],
			Description:       description,
			Effect:            "DENY",
			Priority:          priority,
			ToolPattern:       "*",
			MinimumTrustLevel: "UNTRUSTED",
			Enabled:           true,
		}
	}

	r1 := rule(1, "Destructive filesystem commands wipe work that cannot be recovered.", 10)
	r1.Command = &starterConstraint{Denied: []string{"rm*", "*rm -rf*", "*mkfs*", "*dd if=*"}}

	r2 := rule(2, "Privilege escalation lets a mistake reach the whole machine.", 20)
	r2.Command = &starterConstraint{Denied: []string{"sudo*", "*chmod 777*"}}

	r3 := rule(3, "Credential files are the highest-value thing an agent can read.", 30)
	r3.Filename = &starterConstraint{Denied: []string{
		"*.env", ".env.*", "*.pem", "*.key", "id_rsa", "id_ed25519", "*credentials*",
	}}

	r4 := rule(4, "Credential directories hold keys for every service you use.", 40)
	r4.Path = &starterConstraint{Denied: []string{"*/.ssh/*", "*/.aws/*", "*/.gnupg/*", "*/.kube/*"}}

	r5 := rule(5, "Cloud metadata endpoints hand out live machine credentials.", 50)
	r5.URL = &starterConstraint{Denied: []string{"*169.254.169.254*", "*metadata.google.internal*"}}

	r6 := rule(6, "Paste sites and webhook catchers are where leaked data goes.", 60)
	r6.URL = &starterConstraint{Denied: []string{
		"*pastebin.com*", "*requestbin*", "*webhook.site*", "*ngrok.io*",
	}}

	return starterPolicySet{
		ID:          ids[0],
		Name:        "Starter protection",
		Description: "Destructive commands, credential files and known exfiltration targets.",
		Mode:        "denylist",
		Rules:       []starterRule{r1, r2, r3, r4, r5, r6},
	}, true
}

// authEncodePolicy serialises a policy the way JSON.stringify does.
//
// HTML escaping is off and the encoder's trailing newline is trimmed, for the
// reason apiauth.JSON gives: Go rewrites < > & into \u00xx forms and JavaScript
// does not, and the guard hashes the bytes it receives. This starter document
// happens to contain none of those three characters — but the hash written
// below is over exactly these bytes, so the two encoders have to be the same
// one or a later edit to the rules quietly changes what is stored.
func authEncodePolicy(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// authSeedStarterPolicy writes version 1 of a new project's policy.
//
// The hash is computed over the bytes that are stored, not over a
// re-serialisation of a parsed copy. GET /v1/policies/active hands that hash to
// the guard, which uses it to decide whether the policy it has cached is still
// current; a hash of anything other than the stored bytes makes that comparison
// meaningless the first time something round-trips the document.
func (s *server) authSeedStarterPolicy(ctx context.Context, projectID, userID string) error {
	policy, ok := authStarterPolicy(authNewID)
	if !ok {
		return authErrNoID
	}
	serialised, err := authEncodePolicy(policy)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(serialised)

	rowID := authNewID()
	if rowID == "" {
		return authErrNoID
	}
	return s.store.InsertPolicyVersion(ctx, store.PolicyVersion{
		ID:         rowID,
		ProjectID:  projectID,
		Version:    1,
		PolicyData: json.RawMessage(serialised),
		Hash:       hex.EncodeToString(sum[:]),
		Reason:     "Starter policy",
		CreatedBy:  userID,
		CreatedAt:  store.Now(),
	})
}
