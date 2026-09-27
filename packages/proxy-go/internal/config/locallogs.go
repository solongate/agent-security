package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// LocalLogSetting is what local logging is set to on this device, and where it
// can actually go.
//
// The two are separate questions and used to be answered as one. Live decided
// on/off by whether the log file had lines in it, so an enabled log that
// happened to be empty — a fresh install, a folder just changed, an account
// just switched — reported "local logs off" and told the user to enable
// something that was already on.
type LocalLogSetting struct {
	// The project setting, as the hooks read it.
	Enabled bool
	// The folder the project asked for, verbatim. Empty when nothing is set.
	ConfiguredPath string
	// False when that folder cannot be used HERE — a Windows path on Linux, or
	// a directory that does not exist on this machine.
	UsableHere bool
	// The file entries actually land in, after any fallback.
	File string
}

var trailingSep = regexp.MustCompile(`[\\/]+$`)

// LocalLogsSetting resolves the setting the way the hooks resolve it.
//
// Local logging takes a FOLDER from the dashboard and the hooks append
// solongate-audit.jsonl inside it, so a user who set /home/me gets
// /home/me/solongate-audit.jsonl. Every viewer used to read the DEFAULT folder
// unconditionally, so with a custom folder configured the dataroom, `watch` and
// `doctor` all showed an empty log while entries were landing correctly
// somewhere else.
//
// The folder lives in the policy cache the hooks themselves read, so it is read
// from there, preferring the most recently refreshed cache.
func LocalLogsSetting() LocalLogSetting {
	off := LocalLogSetting{UsableHere: true, File: DefaultLocalLogFile()}
	for _, cache := range PolicyCachesNewestFirst() {
		b, err := os.ReadFile(cache)
		if err != nil {
			continue
		}
		var c struct {
			Security *struct {
				LocalLogs *struct {
					Enabled *bool  `json:"enabled"`
					Path    string `json:"path"`
				} `json:"localLogs"`
			} `json:"security"`
		}
		if json.Unmarshal(b, &c) != nil {
			continue
		}
		// No answer in this cache — an older agent that never carried the
		// setting must not out-vote a newer one that does.
		if c.Security == nil || c.Security.LocalLogs == nil || c.Security.LocalLogs.Enabled == nil {
			continue
		}
		raw := strings.TrimSpace(c.Security.LocalLogs.Path)
		if !*c.Security.LocalLogs.Enabled {
			off.ConfiguredPath = raw
			return off
		}
		dir := trailingSep.ReplaceAllString(raw, "")
		if dir == "" {
			return LocalLogSetting{Enabled: true, UsableHere: true, File: DefaultLocalLogFile()}
		}
		// Not absolute HERE means the hooks cannot use it and fall back. The
		// usual cause is a folder set from another OS: a C:/... on Linux, which
		// Node would treat as relative and create inside whatever repo the
		// agent happened to be running in.
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
	return off
}

// LocalLogFile is the file this device is actually writing to. Long-lived views
// should call it rather than caching the answer: the folder can change from the
// dashboard mid-session.
func LocalLogFile() string { return LocalLogsSetting().File }

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// AccountMark is the per-account tag written beside local log entries and into
// the owner marker. A hash prefix, never the key itself, so a log file that
// leaves the machine does not carry a credential.
func AccountMark(apiKey string) string {
	if apiKey == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])[:16]
}

// EnsureLocalLogOwner records which account the local log belongs to and
// reports whether the owner changed.
//
// The file is one per machine and no entry records which account produced it,
// so after pairing a different account the previous one's calls were still
// showing up in Live. Clearing on an in-app switch was not enough: the account
// can also change by pairing a new device, by signing out, or from the
// dashboard.
//
// Nothing is deleted. Entries carry the account that wrote them and readers
// keep only their own, so a change of account separates the history instead of
// destroying it; the marker is kept as the record of whose it is.
func EnsureLocalLogOwner(activeAPIKey string) bool {
	marker := LocalLogOwnerPath()
	want := AccountMark(activeAPIKey)
	have := ""
	if b, err := os.ReadFile(marker); err == nil {
		have = strings.TrimSpace(string(b))
	}
	if have == want {
		return false
	}
	if os.MkdirAll(LocalLogsDir(), 0o755) == nil {
		// Not writable is not fatal: the marker is retried on the next run.
		_ = os.WriteFile(marker, []byte(want), 0o644)
	}
	return true
}
