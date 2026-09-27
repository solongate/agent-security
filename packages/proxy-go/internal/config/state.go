package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/codeyevsky/solongate/sgshared"
)

// The on-disk shapes, in the spelling the Node implementation already writes.
//
// DUPLICATION, stated rather than hidden: DLPCustom, DLPConfig, RateLimit,
// LocalLogs, GhostConfig, Security, Policy, PolicyCache and Credential are the
// same declarations as packages/guard-go/config.go. They are copied because the
// two modules do not depend on each other today, not because they are allowed
// to drift — a field added on one side and not the other is a setting that
// silently stops applying. They belong in one shared module; see the caveat in
// the port notes.

type DLPCustom = sgshared.DLPCustom

type DLPConfig = sgshared.DLPConfig

type RateLimit = sgshared.RateLimit

type LocalLogs = sgshared.LocalLogs

type GhostConfig = sgshared.GhostConfig

type Security = sgshared.Security

// Policy as the cache stores it. Rules stay raw: this package reads the cache
// to answer questions about configuration, and re-serialising a rule array is
// how a policy round trip loses fields the CLI never knew about.
type Policy = sgshared.Policy

// PolicyCache mirrors ~/.solongate/.policy-cache-<agent>.json.
//
// Security is a pointer on purpose. `null` there is an ANSWER — the API sent no
// security block, so this project has none — and it has to stay distinguishable
// from "the field was absent". HasSecurity carries that distinction, which a Go
// pointer alone cannot.
type PolicyCache = sgshared.PolicyCache

// LoadPolicyCache returns nil when there is no readable cache for this agent.
// Nil is a MISS and callers must treat it as one; it is never "there is nothing
// configured".
func LoadPolicyCache(agent string) *PolicyCache {
	b, err := os.ReadFile(PolicyCachePath(agent))
	if err != nil {
		return nil
	}
	var c PolicyCache
	if err := json.Unmarshal(b, &c); err != nil {
		return nil
	}
	return &c
}

// PolicyCachesNewestFirst lists every agent's cache on this device, most
// recently refreshed first. Readers that want "what is configured here" walk
// them in this order: the freshest cache is the one whose agent last spoke to
// the cloud, so it carries the current answer.
func PolicyCachesNewestFirst() []string {
	entries, err := os.ReadDir(Dir())
	if err != nil {
		return nil
	}
	type stamped struct {
		path string
		mod  int64
	}
	var found []stamped
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, ".policy-cache-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		p := filepath.Join(Dir(), name)
		var mod int64
		if info, err := e.Info(); err == nil {
			mod = info.ModTime().UnixNano()
		}
		found = append(found, stamped{p, mod})
	}
	for i := 1; i < len(found); i++ {
		for j := i; j > 0 && found[j].mod > found[j-1].mod; j-- {
			found[j], found[j-1] = found[j-1], found[j]
		}
	}
	out := make([]string, 0, len(found))
	for _, f := range found {
		out = append(out, f.path)
	}
	return out
}

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

// LogsServerState is ~/.solongate/.logs-server.json.
//
// Desired is the source of truth and is deliberately separate from Pid: the
// local audit-log service is a SERVICE. Ctrl+C, a closed terminal or a reboot
// takes the process down without taking the service down, and the next human
// CLI run brings it back. Only an explicit stop writes desired "off".
type LogsServerState struct {
	Desired   string `json:"desired,omitempty"`
	Pid       int    `json:"pid,omitempty"`
	Port      int    `json:"port,omitempty"`
	StartedAt int64  `json:"startedAt,omitempty"`
}

// LogsServerPort is the fixed port the dashboard looks for.
const LogsServerPort = 8788

func LoadLogsServerState() LogsServerState {
	var s LogsServerState
	if b, err := os.ReadFile(LogsServerStatePath()); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func SaveLogsServerState(s LogsServerState) error {
	return writeJSONCompact(LogsServerStatePath(), s)
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

// LoadKeyRejected returns nil when the last cloud call this device made was
// accepted, which is the common case.
func LoadKeyRejected() *KeyRejected {
	b, err := os.ReadFile(KeyRejectedPath())
	if err != nil {
		return nil
	}
	var k KeyRejected
	if json.Unmarshal(b, &k) != nil {
		return nil
	}
	return &k
}

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
