// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package config

import (
	"os"
	"path/filepath"

	"github.com/solongate/agent-security/packages/shared"
)

const (
	DirMode  = shared.DirMode
	FileMode = shared.FileMode
)

func Dir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	return filepath.Join(home, ".solongate")
}

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

func ProjectFlagDir() string {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		abs = cwd
	}
	return filepath.Join(Dir(), "projects", ProjectKey(abs))
}

func EnsureDir() error { return shared.EnsureSGDir() }