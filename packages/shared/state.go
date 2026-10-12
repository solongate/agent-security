// SPDX-License-Identifier: Apache-2.0

// Package shared holds the shapes SolonGate keeps on disk, and the small
// functions that decide where on disk they go.
//
// It exists because the same declarations were written twice, in guard and
// in app, and the second copy immediately drifted. The drift was not a
// field: it was projectKey, hashing bytes in one module and UTF-16 code units
// in the other. That hash names a DIRECTORY and is computed independently in
// four places that never compare it, so the two implementations quietly used
// different folders for anyone whose home directory was not in English. Nothing
// errored. The TUI just showed an empty ring.
//
// So the rule for this package is narrow and worth keeping: it holds only what
// MORE THAN ONE program must agree about. A type that one binary reads and
// nothing else writes does not belong here, because a shared package that
// collects everything becomes a reason to change it, and changing it is the
// thing that has to stay expensive.
//
// The JavaScript side is still the reference. guard.mjs, audit.mjs and the
// TUI write these files today and will keep writing them for as long as
// the npm package is the entry point, so where this package and the JavaScript
// disagree, the JavaScript is right and this is a bug.
package shared

import "encoding/json"

type DLPCustom struct {
	Name string `json:"name"`
	Re   string `json:"re"`
}

type DLPConfig struct {
	Patterns []string    `json:"patterns"`
	Custom   []DLPCustom `json:"custom"`
}

type RateLimit struct {
	Mode      string `json:"mode"`
	PerMinute int    `json:"perMinute"`
	PerHour   int    `json:"perHour"`
	PerDay    int    `json:"perDay"`
}

type LocalLogs struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

type Security struct {
	DLPBlock  *DLPConfig `json:"dlpBlock"`
	DLPRedact *DLPConfig `json:"dlpRedact"`

	// THE DETECT-MODE PATTERNS: scan, record, change nothing. Written in place of
	// DLPRedact when the mode is detect, so exactly one of the three shapes is
	// ever on disk and a mode cannot accidentally do a stronger mode's work.
	//
	// There used to be two modes wearing three names. "detect" set DLPRedact, so
	// it masked the model's view of every secret it found, which is redacting,
	// not detecting, and "block" set both, so the only difference between them
	// was whether an argument hit also refused the call. A read whose secret was
	// in the FILE behaved identically in both: allowed, masked, and recorded as
	// clean. Somebody asking for detect got redaction they did not ask for, and
	// somebody asking for block got redaction where they expected a refusal.
	//
	// Each mode now does the thing its name is: detect observes, redact masks,
	// block refuses.
	DLPObserve *DLPConfig `json:"dlpObserve"`
	RateLimit  *RateLimit `json:"rateLimit"`

	// The DETECT-mode limits: count, do not block. Set by the API in place of
	// RateLimit when the mode is detect, so exactly one of the two is ever
	// present and a layer cannot accidentally enforce the observing one.
	//
	// Read by the post-tool audit hook on clients that have one, and by the
	// guard itself on clients that do not, where nothing else runs, so a
	// detect-mode burst that is not counted here is not counted anywhere.
	RateLimitObserve *RateLimit `json:"rateLimitObserve"`
	LocalLogs        *LocalLogs `json:"localLogs"`

	// ProtectedPaths are paths the agent may not read, write or delete, by any
	// route.
	//
	// NOT A POLICY RULE, and the difference is the whole reason this field
	// exists. A rule is matched against the strings in a tool call, and a
	// string match is a game with no end: `rm game.c` is caught and
	// `x=gam; y=e; rm "$x$y.c"` is not, nor is a script written and then run,
	// nor is a program the agent writes that calls unlink itself. This list is
	// handed to the operating system instead, by `solongate protect`, and the
	// guard's own check on it is the weakest of the three things enforcing it
	// rather than the only one.
	//
	// What actually holds per platform, and the honest version of each, is in
	// core/config/protectpaths.go. `solongate protect list` prints it rather
	// than implying the strongest case everywhere.
	ProtectedPaths []string `json:"protectedPaths,omitempty"`

	// Sandboxes are the closed boxes this machine has defined, each one a
	// directory an agent can be confined to and nothing else.
	//
	// A LIST RATHER THAN ONE SETTING, because a machine has more than one
	// project and they do not share a confinement. The box for a customer's
	// repository and the box for a scratch experiment want different
	// directories and often different answers about the network, and a single
	// setting made somebody edit it every time they changed what they were
	// working on, which is the kind of friction that ends with the feature
	// switched off.
	//
	// THE OTHER WAY ROUND FROM ProtectedPaths, and that is the point of both
	// of them. A protected list protects what somebody remembered to name,
	// which is never ~/.ssh, never a sibling customer's repository, never the
	// credentials of a tool they installed last month. A box protects
	// everything they did not name.
	Sandboxes []Sandbox `json:"sandboxes,omitempty"`

	// RequireSandbox refuses every tool call from an agent that was not started
	// through `solongate run`.
	//
	// FAILS CLOSED, which is why it is opt-in. Without it the protected list is
	// enforced by the OS for agents SolonGate started and by a string match for
	// the rest, and the difference is invisible from inside the agent. With it,
	// an agent outside the sandbox gets nothing at all.
	RequireSandbox bool `json:"requireSandbox,omitempty"`
}

// Sandbox is one closed box: an id, a directory, and whether the agent inside
// it can reach the network.
type Sandbox struct {
	// ID is what `solongate sandbox <id> <agent>` takes, zero-padded to three
	// digits from "001".
	//
	// SHORT AND REUSED ON PURPOSE. It is typed every time an agent is started,
	// so it has to be short enough to type and stable enough to remember; and
	// deleting a box frees its number for the next one, so a machine that has
	// made and removed boxes for a year still has small ids rather than "047".
	// The number names a slot, not a history.
	ID string `json:"id"`

	// Dir is the directory the box is about, as an ABSOLUTE path. "~/x" is a
	// shell convention rather than a path: the kernel does not expand it, so a
	// box keyed on that string would be a box around a directory that does not
	// exist.
	Dir string `json:"dir"`

	// Network is whether the agent in this box can reach the network.
	//
	// A PER-BOX CHOICE, because the right answer differs per project and
	// neither answer is safe in general. Off is a box nothing can leave, and
	// an agent that cannot reach its model cannot do anything either. On lets
	// the agent work and leaves exfiltration to the DLP and egress layers,
	// which read what is leaving, something a mount namespace cannot do.
	//
	// Defaults to ON when a box is created, because that is the box that works;
	// the TUI says what the choice costs rather than choosing quietly.
	Network bool `json:"network"`

	// Label is an optional human name, for a list of boxes that would otherwise
	// be a list of paths.
	Label string `json:"label,omitempty"`
}

// Rules stays raw. The guard compiles it to Rego and the CLI passes it through;
// decoding it into a struct here would mean a policy loses any field this
// version does not know about the moment something round-trips it.
type Policy struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Mode  string          `json:"mode"`
	Rules json.RawMessage `json:"rules"`

	// Agents scopes the RULES to named clients. Empty or absent means every
	// client, and so does an entry of "*".
	//
	// Here because the JavaScript guard has honoured it since before this
	// package existed and this one did not, so the same file meant two things
	// depending on whether a machine had the binary: a policy scoped to one
	// client was enforced against all of them here. The hook is the reference
	// for these shapes (see the package comment), so the hook's reading is the
	// correct one and this was the bug.
	//
	// It scopes the rules and nothing else. DLP, the rate limit, egress and the
	// tamper flag are configured in a different block of the same file and are
	// not the policy; a client out of scope still gets all of them. The hook
	// returned ALLOW above those layers for an out-of-scope client, which turned
	// a scoped policy into a way to disarm them, and that is fixed on its side
	// rather than copied to this one.
	Agents []string `json:"agents,omitempty"`
}

// AppliesTo reports whether this policy's rules are meant for the named client.
//
// Kept identical to the scope test in packages/hooks/guard.mjs: a missing or
// empty list is every client, "*" is every client, and otherwise the client has
// to be named exactly. Compared case-sensitively because the names are the
// client ids the installer bakes into the hook registration, not something a
// person types.
func (p *Policy) AppliesTo(client string) bool {
	if p == nil || len(p.Agents) == 0 {
		return true
	}
	for _, a := range p.Agents {
		if a == "*" || a == client {
			return true
		}
	}
	return false
}

// PolicyCache mirrors ~/.solongate/.policy-cache-<agent>.json.
//
// Security is a pointer on purpose. `null` there is an ANSWER, the API sent no
// security block, so this project has none, and it has to stay distinguishable
// from "the field was absent". Collapsing the two is what once made a stale
// device-wide marker decide where audit entries went.
type PolicyCache struct {
	TS          int64     `json:"_ts"`
	Policy      *Policy   `json:"policy"`
	SelfProtect *bool     `json:"selfProtect"`
	Security    *Security `json:"security"`

	// HasSecurity records whether the KEY was present, which is the distinction
	// the pointer above cannot carry on its own.
	HasSecurity bool `json:"-"`
}

func (c *PolicyCache) UnmarshalJSON(b []byte) error {
	type raw PolicyCache
	var r raw
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	*c = PolicyCache(r)
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err == nil {
		_, c.HasSecurity = probe["security"]
	}
	return nil
}

type Credential struct {
	APIKey string `json:"apiKey"`
	APIURL string `json:"apiUrl"`
}
