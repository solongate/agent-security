// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/solongate/agent-security/packages/sgshared"
)

// Where a decision gets recorded. Local storage and the cloud are EXCLUSIVE:
// the setting says "keep these on my machines instead of your cloud", so when it
// is on nothing leaves, and when it is off nothing is written to disk.

var trailingSep = regexp.MustCompile(`[\\/]+$`)

// The folder is a PROJECT setting, so it reaches every device on the project: a
// Windows path arrives on a Linux machine and is not a location there. Node
// would treat it as relative and create it under the agent's working directory,
// polluting whatever repo it happened to be in. Fall back instead — the entry
// matters more than the location.
func resolveLocalLogDir(raw string) string {
	dir := trailingSep.ReplaceAllString(strings.TrimSpace(raw), "")
	if dir == "" {
		return ""
	}
	if !filepath.IsAbs(dir) {
		return filepath.Join(sgshared.SGDir(), "local-logs")
	}
	return dir
}

// accountMark hashed the key into the 16 characters stamped on each line as `acct`,
// so a machine paired to two accounts could tell whose calls were whose. Nothing
// pairs, and nothing ever read the stamp — see config.go.

func writeLocalLog(sec *sgshared.Security, entry map[string]interface{}) {
	dir := ""
	if sec != nil && sec.LocalLogs != nil {
		dir = resolveLocalLogDir(sec.LocalLogs.Path)
	}
	if dir == "" {
		// No folder named, so the per-device default. RECORDING IS NOT OPTIONAL:
		// this used to return when the configuration said local logging was off,
		// which made sense while there was a service to POST to instead. With that
		// gone, returning here loses the record entirely — the only thing the
		// setting can still choose is WHERE.
		dir = filepath.Join(sgshared.SGDir(), "local-logs")
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	if os.MkdirAll(dir, sgshared.DirMode) != nil {
		dir = filepath.Join(sgshared.SGDir(), "local-logs")
		if os.MkdirAll(dir, sgshared.DirMode) != nil {
			return
		}
	}
	logFile := filepath.Join(dir, "solongate-audit.jsonl")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, sgshared.FileMode)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
	// The mode on OpenFile applies only when it CREATES the file, so a log an
	// older version wrote 0644 would keep it forever. The Node twin narrows it
	// the same way, in its detached writer.
	_ = os.Chmod(logFile, sgshared.FileMode)
}
