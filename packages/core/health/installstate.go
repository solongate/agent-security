// SPDX-License-Identifier: Apache-2.0

package health

import (
	"github.com/solongate/agent-security/packages/core/install"
)

// What `doctor` asks about this machine's own installation.
//
// Every answer comes from core/install — the package that WRITES these files
// — rather than from a second reader here. A disagreement between the two would
// be worse than a missing feature: the health check would say the machine is
// guarded while the installer thought it was not, and one of them would be wrong
// about whether anything is watching.
//
// Nothing here reports "not installed" for a client that is not on the machine.
// A row saying Codex is unguarded, on a machine with no Codex, is noise that
// teaches people to ignore the check.

// clientPaths is the narrow view the checks below need. It is a projection of
// install.Paths, not a second resolution of it: only Antigravity is asked about
// by path, because its row keys off the config file existing rather than off a
// parsed registration.
type clientPaths struct {
	antigravityDir       string
	antigravityHooksPath string
}

func globalPaths() clientPaths {
	p := install.GlobalPaths()
	return clientPaths{
		antigravityDir:       p.AntigravityDir,
		antigravityHooksPath: p.AntigravityHooksPath,
	}
}

func pathExists(p string) bool { return install.Exists(p) }

// guardHookName is the file the installer writes into ~/.solongate/hooks.
const guardHookName = install.GuardHookName

func isGuardInstalled() bool         { return install.ClaudeGuardInstalled() }
func installedGuardVersion() *int    { return install.InstalledGuardVersion() }
func codexDetected() bool            { return install.CodexDetected() }
func opencodeDetected() bool         { return install.OpencodeDetected() }
func isOpencodeGuardInstalled() bool { return install.OpencodeGuardInstalled() }
func isCodexGuardInstalled() bool    { return install.CodexGuardInstalled() }

// codexStatus keeps the three answers in the shape the doctor rows read them in.
type codexStatus struct {
	registered bool
	trusted    bool
	disabled   bool
}

func codexHooksStatus() codexStatus {
	s := install.CodexHooksStatus()
	return codexStatus{registered: s.Registered, trusted: s.Trusted, disabled: s.Disabled}
}
