// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"path/filepath"
	"strings"

	"github.com/solongate/agent-security/packages/policy"
	"github.com/solongate/agent-security/packages/shared"
)

func userProtectedCheck(toolName string, args map[string]interface{}, sec *shared.Security) string {
	if sec == nil || len(sec.ProtectedPaths) == 0 {
		return ""
	}
	norm := make([]string, 0, len(sec.ProtectedPaths))
	for _, p := range sec.ProtectedPaths {
		if p = strings.TrimSpace(p); p != "" {
			norm = append(norm, normTamperPath(filepath.Clean(p)))
		}
	}
	if len(norm) == 0 {
		return ""
	}

	for _, raw := range extractTargetPaths(args) {
		if hit := underProtected(raw, norm); hit != "" {
			return protectedReason(raw, hit)
		}
	}

	isExec := policy.IsExecTool(toolName) || tamperGuardToolsExec[strings.ToLower(toolName)]
	for _, raw := range policy.ExtractPaths(args, isExec) {
		if hit := underProtected(raw, norm); hit != "" {
			return protectedReason(raw, hit)
		}
	}

	if isExec {
		for _, cmd := range policy.ExtractCommands(args) {
			c := normTamperPath(cmd)
			for _, p := range norm {
				if strings.Contains(c, p) {
					return protectedReason(p, p)
				}
			}
		}
	}
	return ""
}

func underProtected(raw string, norm []string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	np := normTamperPath(filepath.Clean(raw))
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

func sandboxRequired(sec *shared.Security) string {
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