// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"time"

	"github.com/solongate/agent-security/packages/guard/guardcore"
	"github.com/solongate/agent-security/packages/shared"
)

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

func record(sec *shared.Security, hasSecurity bool, c call, agentType, agentName, reason string, started time.Time) {
	recordDecision(sec, hasSecurity, c, agentType, agentName, reason, "DENY", started)

	writeDenyFlag(shared.ProjectFlagDir(), c.Tool, c.CallID)
}

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

	guardcore.WriteLocalLog(sec, local)
}