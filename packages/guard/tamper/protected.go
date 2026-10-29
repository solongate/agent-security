// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tamper

import (
	"path/filepath"
	"strings"

	"github.com/solongate/agent-security/packages/policy"
	"github.com/solongate/agent-security/packages/shared"
)

// UserProtectedCheck refuses a tool call that names a path the user protected
// with `solongate policy protect`. Those are stored absolute, while agents
// mostly name files relative to the project they run in, so a relative path
// is also checked resolved against cwd.
func UserProtectedCheck(toolName string, args map[string]interface{}, sec *shared.Security, cwd string) string {
	if sec == nil || len(sec.ProtectedPaths) == 0 {
		return ""
	}
	norm := make([]string, 0, len(sec.ProtectedPaths))
	for _, p := range sec.ProtectedPaths {
		if p = strings.TrimSpace(p); p != "" {
			norm = append(norm, NormPath(filepath.Clean(p)))
		}
	}
	if len(norm) == 0 {
		return ""
	}

	for _, raw := range ExtractTargetPaths(args) {
		if hit := underProtectedFrom(raw, cwd, norm); hit != "" {
			return protectedReason(raw, hit)
		}
	}

	isExec := policy.IsExecTool(toolName) || GuardToolsExec[strings.ToLower(toolName)]
	for _, raw := range policy.ExtractPaths(args, isExec) {
		if hit := underProtectedFrom(raw, cwd, norm); hit != "" {
			return protectedReason(raw, hit)
		}
	}

	if isExec {
		for _, cmd := range policy.ExtractCommands(args) {
			c := NormPath(cmd)
			for _, p := range norm {
				if strings.Contains(c, p) {
					return protectedReason(p, p)
				}
			}
		}
	}
	return ""
}

// underProtectedFrom checks raw as written and, when it is relative and cwd
// is known, as resolved against cwd. The unresolved check stays because a
// protected path may itself have been written relative.
func underProtectedFrom(raw, cwd string, norm []string) string {
	if hit := underProtected(raw, norm); hit != "" {
		return hit
	}
	raw = strings.TrimSpace(raw)
	if cwd == "" || raw == "" || filepath.IsAbs(raw) {
		return ""
	}
	return underProtected(filepath.Join(cwd, raw), norm)
}

func underProtected(raw string, norm []string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	np := NormPath(filepath.Clean(raw))
	for _, p := range norm {

		if np == p || strings.HasPrefix(np, p+"/") {
			return p
		}
	}
	return ""
}

func protectedReason(named, hit string) string {
	if named == hit {
		return `Protected path: "` + hit + `" cannot be read, written or deleted by an agent`
	}
	return `Protected path: "` + named + `" is inside "` + hit + `", which cannot be read, written or deleted by an agent`
}

func SandboxRequired(sec *shared.Security) string {
	if sec == nil || !sec.RequireSandbox {
		return ""
	}
	confined, conclusive := shared.VerifiedInSandbox(sec.ProtectedPaths)
	if confined && conclusive {
		return ""
	}
	if !conclusive {
		return "Refused: this machine requires agents to be started with `solongate run` or " +
			"`solongate sandbox`, and there is no way to confirm that this one was. " +
			"Add a protected path, or use `solongate sandbox`, which can be verified."
	}
	if shared.InSandbox() {

		return "Refused: this process carries a sandbox marker but is not confined, " +
			"the kernel says otherwise. Start the agent with `solongate run` or " +
			"`solongate sandbox`, and remove SOLONGATE_SANDBOX from your shell profile."
	}
	return "Refused: this machine requires agents to be started with `solongate run` or " +
		"`solongate sandbox`. Protected paths are enforced by the operating system there, " +
		"and by string matching anywhere else."
}