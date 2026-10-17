// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type LocalLogSetting struct {
	Enabled bool

	ConfiguredPath string

	UsableHere bool

	File string
}

var trailingSep = regexp.MustCompile(`[\\/]+$`)

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

func LocalLogFile() string { return LocalLogsSetting().File }

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}