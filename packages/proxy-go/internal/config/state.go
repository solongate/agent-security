package config

import (
	"encoding/json"
	"os"

	"github.com/codeyevsky/solongate/sgshared"
)

// The on-disk shapes, in the spelling the Node implementation already writes.
//
// DUPLICATION, stated rather than hidden: DLPCustom, DLPConfig, RateLimit,
// LocalLogs, Security, Policy, PolicyCache and Credential are the
// same declarations as packages/guard-go/config.go. They are copied because the
// two modules do not depend on each other today, not because they are allowed
// to drift — a field added on one side and not the other is a setting that
// silently stops applying. They belong in one shared module; see the caveat in
// the port notes.

type DLPCustom = sgshared.DLPCustom

type DLPConfig = sgshared.DLPConfig

type RateLimit = sgshared.RateLimit

type LocalLogs = sgshared.LocalLogs

type Security = sgshared.Security

// Policy as the cache stores it. Rules stay raw: this package reads the cache
// to answer questions about configuration, and re-serialising a rule array is
// how a policy round trip loses fields the CLI never knew about.
type Policy = sgshared.Policy

// PolicyCache is the ENVELOPE the policy file may be written in:
// `{policy, security, selfProtect}`. The name is historical — it mirrored
// .policy-cache-<agent>.json, which a service filled — and it is kept because
// sgshared calls it that and both guards decode the file into it.
//
// Security is a pointer on purpose. `null` there is an ANSWER — this machine
// configures no layers — and it has to stay distinguishable from "the field was
// absent", which means defaults. HasSecurity carries that distinction, which a Go
// pointer alone cannot.
type PolicyCache = sgshared.PolicyCache

// LoadPolicyCache and PolicyCachesNewestFirst lived here.
//
// The cache held a service's answer — the policy, the layers, the tamper flag — per
// agent, with the freshest file winning because its agent had spoken to the service
// most recently. Nothing has written one since the refresh was removed, so every read
// missed, and each reader then did something worse than nothing:
//
//	LocalLogsSetting    returned "off, default folder" on every machine, and Live
//	                    SKIPS READING THE LOG when it is told off — so the guard
//	                    wrote entries no viewer would show.
//	audit.mjs           let a cache OUTRANK the policy file, so one left behind by an
//	                    older install could switch off the DLP the file configures.
//	shield.mjs          fell back to "every built-in pattern, no custom ones", so a
//	                    custom pattern never reached the only surface that sees the
//	                    prompt.
//
// All three read the policy file now. PolicyCache itself stays as a TYPE: it is the
// shape of the policy file's envelope, which is what sgshared calls it.

// TUIConfig is ~/.solongate/tui-config.json. Every field is optional; a missing
// or unreadable file is defaults, never an error the user has to deal with.
type TUIConfig struct {
	Notifications bool   `json:"notifications"`
	Accent        string `json:"accent,omitempty"`
	PollMs        int    `json:"pollMs,omitempty"`
}

// LoadTUIConfig defaults notifications ON. The file says `false` to turn them
// off, so an absent field must not read as off — that is why the raw decode
// uses a pointer rather than the struct's zero value.
func LoadTUIConfig() TUIConfig {
	cfg := TUIConfig{Notifications: true}
	b, err := os.ReadFile(TUIConfigPath())
	if err != nil {
		return cfg
	}
	var raw struct {
		Notifications *bool  `json:"notifications"`
		Accent        string `json:"accent"`
		PollMs        *int   `json:"pollMs"`
	}
	if json.Unmarshal(b, &raw) != nil {
		return cfg
	}
	if raw.Notifications != nil {
		cfg.Notifications = *raw.Notifications
	}
	cfg.Accent = raw.Accent
	if raw.PollMs != nil {
		cfg.PollMs = *raw.PollMs
	}
	return cfg
}

// BrowserAgentState is ~/.solongate/.browser-agent.json.
//
// The same shape and the same rule as the audit service above: Desired is what
// the person asked for and outlives the process, Pid is only ever evidence
// about right now. A reboot takes the process down and leaves the service
// wanted, and the next human CLI run brings it back.
//
// Pipe records which name the agent was started on, because that is the one
// thing that has to agree with the browser's policy: a mismatch is not an error
// anywhere, it is a browser that never connects and never says so.
type BrowserAgentState struct {
	Desired   string `json:"desired,omitempty"`
	Pid       int    `json:"pid,omitempty"`
	Pipe      string `json:"pipe,omitempty"`
	StartedAt int64  `json:"startedAt,omitempty"`

	// CDPPort is the browser's DevTools port, and it is what decides whether
	// the page layer runs at all.
	//
	// The connector path — the browser's own content analysis protocol — sees
	// pastes, drops, file pickers, downloads and printing. It is never told
	// about a typed message, a request body, a dictated sentence or a
	// microphone, so four of the six channels this product watches exist only
	// in the page. The page layer needs a browser started with
	// --remote-debugging-port, and nothing here starts one: this is the port to
	// LOOK on, checked every five seconds and silent when nothing answers.
	//
	// Zero is off. See browseragent.Start for why the default is zero and what
	// turning it on actually means.
	CDPPort int `json:"cdpPort,omitempty"`

	// Version is what the RUNNING agent was started as. It is how a later CLI
	// tells a fresh agent from a stale one without asking the process: an update
	// replaces the binary on disk, but the process already up keeps the code it
	// launched with, and this is the stamp that says which. Ensure restarts the
	// agent when this no longer matches the binary beside the hook.
	Version string `json:"version,omitempty"`

	// OCREngine is what the agent said would read screenshots here, and
	// OCRStamp is the agent binary it said it about.
	//
	// A CACHE, and it is here rather than recomputed because finding out costs
	// a process launch and a self test — PowerShell loading a WinRT projection
	// on a cold machine is a second or two — and `browser status` is a command
	// people type all day. The stamp is the binary's size and modification
	// time, so an update that changes the recogniser invalidates this without
	// anybody having to remember to.
	//
	// An empty OCREngine with a stamp means the answer was NO, and that is a
	// real answer worth caching too: a fleet laptop with no language pack
	// should not pay for finding that out on every command.
	OCREngine string `json:"ocrEngine,omitempty"`
	OCRAdvice string `json:"ocrAdvice,omitempty"`
	OCRStamp  string `json:"ocrStamp,omitempty"`
}

func LoadBrowserAgentState() BrowserAgentState {
	var s BrowserAgentState
	if b, err := os.ReadFile(BrowserAgentStatePath()); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func SaveBrowserAgentState(s BrowserAgentState) error {
	return writeJSONCompact(BrowserAgentStatePath(), s)
}

// SelfUpdateState is ~/.solongate/.self-update.json.
//
// Auto is opt-in and its absence means OFF. A global npm install usually needs
// sudo on macOS, so a background install there can only fail; defaulting it on
// would mean a daily failed install nobody asked for. NeedsAdmin records the
// version npm refused for permissions so that one is not retried forever.
type SelfUpdateState struct {
	LastCheckAt int64            `json:"lastCheckAt,omitempty"`
	LatestSeen  string           `json:"latestSeen,omitempty"`
	Attempts    map[string]int64 `json:"attempts,omitempty"`
	Installed   string           `json:"installed,omitempty"`
	Auto        bool             `json:"auto,omitempty"`
	NeedsAdmin  string           `json:"needsAdmin,omitempty"`
}

func LoadSelfUpdateState() SelfUpdateState {
	var s SelfUpdateState
	if b, err := os.ReadFile(SelfUpdateStatePath()); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func SaveSelfUpdateState(s SelfUpdateState) error {
	return writeJSONCompact(SelfUpdateStatePath(), s)
}

// KeyRejected is ~/.solongate/.key-rejected.json — the marker the guard drops
// when the cloud refuses the credential a hook used.
type KeyRejected struct {
	TS        int64  `json:"ts,omitempty"`
	Cwd       string `json:"cwd,omitempty"`
	KeySource string `json:"keySource,omitempty"`
	APIURL    string `json:"apiUrl,omitempty"`
}

// LoadKeyRejected lived here. The guard dropped a marker when a service answered 401
// or 403 to an audit write and removed it on the next success, so its presence was the
// whole finding: a stale key in a project .env made every write fail while enforcement
// kept working, which is invisible unless something says it out loud. Nothing writes a
// marker, because nothing writes to a service.

// writeJSONCompact matches the Node writers: JSON.stringify with no indent.
// Indentation would be cosmetic here and these files are read by both
// implementations, so the format stays the one already on disk.
func writeJSONCompact(path string, v any) error {
	if err := EnsureDir(); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
