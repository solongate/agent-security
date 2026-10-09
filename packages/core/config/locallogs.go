// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// LocalLogSetting is where this machine's audit trail goes.
//
// Enabled and File were two separate questions and used to be answered as one: Live
// decided on/off by whether the file had lines in it, so an enabled log that happened
// to be empty reported "local logs off" and told the user to enable what was already
// on.
type LocalLogSetting struct {
	// Enabled is ALWAYS TRUE, and the field is kept because Live and the Settings
	// panel both read it.
	//
	// It used to mean what it says. While there was a service the choice was real —
	// entries went to the service OR to a file, never both — so `localLogs.enabled:
	// false` meant "do not write locally". With nowhere to send them, a false here
	// stopped meaning "send them elsewhere" and started meaning "lose them", so both
	// writers ignore it: the guard and the audit hook record unconditionally and the
	// setting chooses only the FOLDER. A viewer that reported off would be describing
	// a state the writers cannot be in — and worse, Live SKIPS READING THE FILE when
	// this is false, so it showed nothing while entries landed correctly.
	Enabled bool
	// The folder the policy asks for, verbatim. Empty when the policy names none.
	ConfiguredPath string
	// False when that folder cannot be used HERE — a Windows path on Linux, or a
	// directory that does not exist on this machine.
	UsableHere bool
	// The file entries actually land in, after any fallback.
	File string
}

var trailingSep = regexp.MustCompile(`[\\/]+$`)

// LocalLogsSetting resolves the folder the way the HOOKS resolve it.
//
// Local logging takes a FOLDER and the hooks append solongate-audit.jsonl inside it,
// so a policy naming /home/me gets /home/me/solongate-audit.jsonl. Every viewer used
// to read the DEFAULT folder unconditionally, so with a custom folder configured the
// dataroom, `watch` and `doctor` all showed an empty log while entries were landing
// somewhere else.
//
// IT READS THE POLICY FILE. It used to read the policy CACHES, newest first, because
// that is where a service's answer was kept — and nothing has written one since the
// refresh was removed, so this returned "off, default folder" on every machine. Which
// is the same bug the paragraph above describes, arrived at from the other side: a
// custom folder was ignored, and Live stopped reading the log at all.
//
// Both spellings of the file are accepted, as everywhere else: the envelope, and a
// policy document carrying `security` inside it.
func LocalLogsSetting() LocalLogSetting {
	def := LocalLogSetting{Enabled: true, UsableHere: true, File: DefaultLocalLogFile()}

	b, err := os.ReadFile(filepath.Join(Dir(), "policy.json"))
	if err != nil {
		return def
	}
	type localLogsBlock struct {
		Enabled *bool  `json:"enabled"`
		Path    string `json:"path"`
	}
	type securityBlock struct {
		LocalLogs *localLogsBlock `json:"localLogs"`
	}
	var doc struct {
		Security *securityBlock `json:"security"`
		Policy   *struct {
			Security *securityBlock `json:"security"`
		} `json:"policy"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return def
	}
	sec := doc.Security
	if sec == nil || sec.LocalLogs == nil {
		if doc.Policy != nil {
			sec = doc.Policy.Security
		}
	}
	if sec == nil || sec.LocalLogs == nil {
		return def
	}

	raw := strings.TrimSpace(sec.LocalLogs.Path)
	dir := trailingSep.ReplaceAllString(raw, "")
	if dir == "" {
		return def
	}
	// Not absolute HERE means the hooks cannot use it and fall back. The usual cause
	// is a folder set from another OS: a C:/... on Linux, which Node would treat as
	// relative and create inside whatever repository the agent happened to run in.
	if !filepath.IsAbs(dir) {
		return LocalLogSetting{Enabled: true, ConfiguredPath: raw, UsableHere: false, File: DefaultLocalLogFile()}
	}
	file := filepath.Join(dir, "solongate-audit.jsonl")
	usable := exists(file) || exists(dir)
	resolved := file
	if !usable {
		resolved = DefaultLocalLogFile()
	}
	return LocalLogSetting{Enabled: true, ConfiguredPath: raw, UsableHere: usable, File: resolved}
}

// LocalLogFile is the file this device is actually writing to. Long-lived views
// should call it rather than caching the answer: the folder can change from the
// dashboard mid-session.
func LocalLogFile() string { return LocalLogsSetting().File }

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// AccountMark and EnsureLocalLogOwner lived here.
//
// AccountMark hashed the key into the 16-character `acct` tag stamped on every local
// log line; EnsureLocalLogOwner wrote the same tag into a `.owner` marker beside the
// log so a change of account could be noticed. Both existed because one machine's log
// could hold two accounts' calls. There are no accounts, nothing writes the tag, and
// a reader that still filtered on it would drop every line written since.
