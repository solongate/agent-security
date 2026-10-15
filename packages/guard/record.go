// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

// Split from main.go: the detect/redact DLP mode marker, and the local-log
// recording of denials and observed-but-allowed calls.

import (
	"time"

	"github.com/solongate/agent-security/packages/shared"
)

// observingDLP is the config of a mode that WATCHES rather than refuses, and
// which of the two it is.
//
// Block is handled before this is ever reached, so only detect and redact get
// here. Returning the name alongside the config keeps the recorded reason
// honest: "DLP is in detect mode" and "DLP is in redact mode" are different
// sentences about different outcomes, and one of them used to be printed for
// both.
type observingCfg struct {
	cfg  *shared.DLPConfig
	mode string
}

func observingDLP(sec *shared.Security) *observingCfg {
	if sec == nil {
		return nil
	}
	if sec.DLPRedact != nil {
		return &observingCfg{cfg: sec.DLPRedact, mode: "redact"}
	}
	if sec.DLPObserve != nil {
		return &observingCfg{cfg: sec.DLPObserve, mode: "detect"}
	}
	return nil
}

// record writes the denial where the settings say it goes: to this machine, or
// to the cloud, never both. The cloud write is detached so the agent is not kept
// waiting on a network round trip for a decision already made.
func record(sec *shared.Security, hasSecurity bool, c call, agentType, agentName, reason string, started time.Time) {
	recordDecision(sec, hasSecurity, c, agentType, agentName, reason, "DENY", started)
	// Every denial in this binary comes through here on its way to deny(), which
	// makes it the one place the flag can be written without each layer having to
	// remember to. See writeDenyFlag for what the audit hook does with it.
	writeDenyFlag(shared.ProjectFlagDir(), c.Tool, c.CallID)
}

// recordObserved files a row for a call that was ALLOWED but carried a signal
// worth keeping, a DLP pattern matched in detect mode, say.
//
// Only for clients with no post-tool stage. Everywhere else the audit hook files
// the allow row and this would be a duplicate; on Antigravity nothing else ever
// runs, so a detect-mode hit that is not written here is not written at all, and
// a mode whose whole job is to observe would observe nothing.
func recordObserved(sec *shared.Security, hasSecurity bool, c call, agentType, agentName, reason string, started time.Time) {
	if activeClient.ReportsAfter {
		return
	}
	recordDecision(sec, hasSecurity, c, agentType, agentName, reason, "ALLOW", started)
}

func recordDecision(sec *shared.Security, hasSecurity bool, c call, agentType, agentName, reason, decisionVal string, started time.Time) {
	entry := map[string]interface{}{
		"tool":               c.Tool,
		"arguments":          c.Args,
		"decision":           decisionVal,
		"reason":             reason,
		"permission":         shared.GuessPermission(c.Tool),
		"source":             agentType + "-guard",
		"agent_id":           agentType,
		"agent_name":         agentName,
		"session_id":         c.SessionID,
		"evaluation_time_ms": elapsedMs(started),
	}
	local := map[string]interface{}{"ts": time.Now().UTC().Format(time.RFC3339Nano)}
	for k, v := range entry {
		local[k] = v
	}
	// The FILE is where a record goes. There used to be a POST here for the case
	// where local logging was switched off, and with the service gone that branch
	// could only ever lose the entry.
	writeLocalLog(sec, local)
}