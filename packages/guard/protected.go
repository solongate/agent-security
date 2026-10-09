// SPDX-License-Identifier: Apache-2.0

package main

// The user's own protected paths, checked the way the tamper layer checks
// SolonGate's.
//
// SEPARATE FROM selfProtect ON PURPOSE. Self-protection is about keeping the
// guard armed and a person is allowed to turn it off. This list is a promise
// somebody made about their own files, and turning off the first must not
// quietly cancel the second.
//
// AND IT IS THE WEAKEST OF THE THREE THINGS HOLDING THAT PROMISE. It reads the
// strings in a tool call, so it catches `rm game.c` and does not catch
// `x=gam; y=e; rm "$x$y.c"`, a script written to /tmp and then run, or a
// program the agent compiles that calls unlink itself. That is not a gap to be
// closed by adding patterns; the set of ways to name a file without typing its
// name has no end. It is closed by the OS lock `solongate protect` puts on the
// file and by the sandbox `solongate run` puts around the agent, and this
// layer's job is to refuse the easy case immediately and with a reason a
// person can read.

import (
	"path/filepath"
	"strings"

	"github.com/solongate/agent-security/packages/policy"
	"github.com/solongate/agent-security/packages/shared"
)

// userProtectedCheck returns the deny reason, or "" when the call names none
// of the protected paths.
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

	// The TARGET fields first, which is where a well-behaved tool puts the file
	// it is about. Never the free-form body: a note that merely mentions the
	// path is not an attempt to open it, and refusing it would teach the user
	// that the feature is broken.
	for _, raw := range extractTargetPaths(args) {
		if hit := underProtected(raw, norm); hit != "" {
			return protectedReason(raw, hit)
		}
	}

	// Then anything that looks like a path anywhere in the call, including the
	// pieces of an exec command. ExtractPaths already does the tokenising and
	// the isExec split, and sharing it means a path shape the policy layer can
	// see is one this layer can see too.
	isExec := policy.IsExecTool(toolName) || tamperGuardToolsExec[strings.ToLower(toolName)]
	for _, raw := range policy.ExtractPaths(args, isExec) {
		if hit := underProtected(raw, norm); hit != "" {
			return protectedReason(raw, hit)
		}
	}

	// And a plain substring sweep over the command, for the same reason
	// commandTargetsProtected does it: a command has no argument structure this
	// layer can trust, and the path may arrive glued to a flag or inside quotes
	// that the tokeniser split differently than the shell will.
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

// underProtected reports which protected path covers raw: the path itself, or
// anything inside it when it is a directory.
func underProtected(raw string, norm []string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	np := normTamperPath(filepath.Clean(raw))
	for _, p := range norm {
		// `+ "/"` rather than a bare prefix, so protecting /home/me/game does
		// not also swallow /home/me/game-notes. The same rule tamper.go applies
		// to the hooks directory, and for the same reason.
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

// sandboxRequired reports whether this call must be refused for arriving from
// an agent SolonGate did not start.
//
// FAILS CLOSED and is opt-in for that reason. The marker is an environment
// variable set by `solongate run` on the process it launches; every descendant
// inherits it, and an agent started any other way does not have it. An agent
// could of course set the variable itself — and gain nothing by it, because
// the variable is not what confines anything. The confinement is the Landlock
// domain, the Seatbelt profile or the restricted token, which were applied
// before the agent's first instruction and which it cannot drop. The marker
// only reports the fact.
func sandboxRequired(sec *shared.Security) string {
	if sec == nil || !sec.RequireSandbox {
		return ""
	}
	if shared.InSandbox() {
		return ""
	}
	return "Refused: this machine requires agents to be started with `solongate run`. " +
		"Protected paths are enforced by the operating system there, and by string matching anywhere else."
}
