// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"

	"github.com/solongate/agent-security/packages/shared"
)

// The on-disk shapes, in the spelling the Node implementation already writes.
//
// DUPLICATION, stated rather than hidden: DLPCustom, DLPConfig, RateLimit,
// LocalLogs, Security, Policy, PolicyCache and Credential are the
// same declarations as packages/guard/config.go. They are copied because the
// two modules do not depend on each other today, not because they are allowed
// to drift — a field added on one side and not the other is a setting that
// silently stops applying. They belong in one shared module; see the caveat in
// the port notes.

type DLPCustom = shared.DLPCustom

type DLPConfig = shared.DLPConfig

type RateLimit = shared.RateLimit

type LocalLogs = shared.LocalLogs

type Security = shared.Security

// Policy as the cache stores it. Rules stay raw: this package reads the cache
// to answer questions about configuration, and re-serialising a rule array is
// how a policy round trip loses fields the CLI never knew about.
type Policy = shared.Policy

// PolicyCache is the ENVELOPE the policy file may be written in:
// `{policy, security, selfProtect}`. The name is historical — it mirrored
// .policy-cache-<agent>.json, which a service filled — and it is kept because
// shared calls it that and both guards decode the file into it.
//
// Security is a pointer on purpose. `null` there is an ANSWER — this machine
// configures no layers — and it has to stay distinguishable from "the field was
// absent", which means defaults. HasSecurity carries that distinction, which a Go
// pointer alone cannot.
type PolicyCache = shared.PolicyCache

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
// shape of the policy file's envelope, which is what shared calls it.

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

// BrowserAgentState and SelfUpdateState lived here, with their loaders and savers.
//
// BrowserAgentState tracked a browser agent: a desired state that outlived the
// process, the pid that was evidence about right now, the pipe name the browser's
// policy had to agree with, and the DevTools port that decided whether the page layer
// ran at all. There is no browser agent in this build.
//
// SelfUpdateState tracked a `npm i -g` that ran in the background: when it last
// looked, what version it saw, which versions npm had refused for permissions so they
// were not retried forever, and an opt-in flag that defaulted OFF because a global
// install usually needs sudo on macOS and a daily failed install nobody asked for is
// worse than no update. There is nothing to update from — this build fetches nothing —
// and how a release reaches a machine is a decision for whoever ships it.
//
// Both were read and written by nothing outside this file.

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
