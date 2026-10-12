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
// FAILS CLOSED, and it now fails closed on a KERNEL FACT rather than on an
// environment variable's absence.
//
// What it used to do: trust the marker. The comment argued an agent gains
// nothing by setting it, because the variable confines nothing — true of the
// confinement and false of this check. The check refused on the marker's
// ABSENCE, so an agent that exported SOLONGATE_SANDBOX was neither confined
// nor refused. One line in a shell profile, inherited by every agent the
// machine ever starts, and the fail-closed switch failed open. Shell profiles
// are not on protectedTargets, so nothing stopped that line being written.
//
// What it does now: the marker says which confinement claims to be on, and the
// kernel is asked whether it is. In a box, PID 1 is the box's own init rather
// than the host's. Under `run`, a protected path cannot be opened for reading —
// outside the domain it can, because `protect` locks against writing and
// deleting and leaves a file readable. See shared.VerifiedInSandbox.
//
// AN INCONCLUSIVE ANSWER IS A REFUSAL, which is the whole point of a switch
// called require-sandbox: "I could not tell" and "it is confined" are different
// sentences, and only one of them should let a call through on a machine whose
// owner asked for this. `run` with no protected paths is the case that lands
// there, and the refusal says so rather than printing the generic line.
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
		// The marker is there and the kernel disagrees with it. Worth its own
		// sentence: somebody is either running a stale marker from a shell
		// profile or trying it on, and the generic line would send them looking
		// for a launcher problem that is not there.
		return "Refused: this process carries a sandbox marker but is not confined — " +
			"the kernel says otherwise. Start the agent with `solongate run` or " +
			"`solongate sandbox`, and remove SOLONGATE_SANDBOX from your shell profile."
	}
	return "Refused: this machine requires agents to be started with `solongate run` or " +
		"`solongate sandbox`. Protected paths are enforced by the operating system there, " +
		"and by string matching anywhere else."
}
