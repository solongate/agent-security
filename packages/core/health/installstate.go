// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package health

import (
	"github.com/solongate/agent-security/packages/core/install"
)

type clientPaths struct {
	antigravityDir string
}

func globalPaths() clientPaths {
	p := install.GlobalPaths()
	return clientPaths{
		antigravityDir: p.AntigravityDir,
	}
}

func pathExists(p string) bool { return install.Exists(p) }

func isGuardInstalled() bool         { return install.ClaudeGuardInstalled() }
func installedGuardVersion() *int    { return install.InstalledGuardVersion() }
func codexDetected() bool            { return install.CodexDetected() }
func opencodeDetected() bool         { return install.OpencodeDetected() }
func isOpencodeGuardInstalled() bool { return install.OpencodeGuardInstalled() }

func isAntigravityGuardInstalled() bool { return install.AntigravityGuardInstalled() }

type codexStatus struct {
	registered bool
	trusted    bool
	disabled   bool
}

func codexHooksStatus() codexStatus {
	s := install.CodexHooksStatus()
	return codexStatus{registered: s.Registered, trusted: s.Trusted, disabled: s.Disabled}
}