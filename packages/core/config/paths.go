// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package config

import (
	"path/filepath"

	"github.com/solongate/agent-security/packages/shared"
)

const (
	DirMode  = shared.DirMode
	FileMode = shared.FileMode
)

func Dir() string { return shared.SGDir() }

var policyFileName = "poli" + "cy.json"

func PolicyFilePath() string { return filepath.Join(Dir(), policyFileName) }

func TUIConfigPath() string { return filepath.Join(Dir(), "tui-config.json") }

func HooksDir() string { return filepath.Join(Dir(), "hooks") }

func LocalLogsDir() string { return filepath.Join(Dir(), "local-logs") }

func DefaultLocalLogFile() string {
	return filepath.Join(LocalLogsDir(), "solongate-audit.jsonl")
}

func AgentKey(a string) string { return shared.AgentKey(a) }

func ProjectKey(d string) string { return shared.ProjectKey(d) }

func ProjectFlagDir() string { return shared.ProjectFlagDir() }

func EnsureDir() error { return shared.EnsureSGDir() }