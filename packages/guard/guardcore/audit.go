// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package guardcore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/solongate/agent-security/packages/shared"
)

var trailingSep = regexp.MustCompile(`[\\/]+$`)

func resolveLocalLogDir(raw string) string {
	dir := trailingSep.ReplaceAllString(strings.TrimSpace(raw), "")
	if dir == "" {
		return ""
	}
	if !filepath.IsAbs(dir) {
		return filepath.Join(shared.SGDir(), "local-logs")
	}
	return dir
}

// localLogsOff reports whether the user switched the local audit log off. It
// reads the block the way the client writes it and the TUI reads it back: a
// block with no path stands for the default folder, which is always on, so
// only a configured path can carry enabled=false.
func localLogsOff(sec *shared.Security) bool {
	if sec == nil || sec.LocalLogs == nil {
		return false
	}
	return !sec.LocalLogs.Enabled && strings.TrimSpace(sec.LocalLogs.Path) != ""
}

func WriteLocalLog(sec *shared.Security, entry map[string]interface{}) {
	if localLogsOff(sec) {
		return
	}
	dir := ""
	if sec != nil && sec.LocalLogs != nil {
		dir = resolveLocalLogDir(sec.LocalLogs.Path)
	}
	if dir == "" {

		dir = filepath.Join(shared.SGDir(), "local-logs")
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	if os.MkdirAll(dir, shared.DirMode) != nil {
		dir = filepath.Join(shared.SGDir(), "local-logs")
		if os.MkdirAll(dir, shared.DirMode) != nil {
			return
		}
	}
	logFile := filepath.Join(dir, "solongate-audit.jsonl")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, shared.FileMode)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))

	_ = os.Chmod(logFile, shared.FileMode)
}
