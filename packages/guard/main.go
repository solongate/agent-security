// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/solongate/agent-security/packages/guard/auditcmd"
	"github.com/solongate/agent-security/packages/guard/dlp"
	"github.com/solongate/agent-security/packages/guard/guardcore"
	"github.com/solongate/agent-security/packages/guard/ratelimit"
	"github.com/solongate/agent-security/packages/guard/shield"
	"github.com/solongate/agent-security/packages/guard/tamper"
	"github.com/solongate/agent-security/packages/guard/tokens"
	"github.com/solongate/agent-security/packages/policy"
	"github.com/solongate/agent-security/packages/shared"
)

var activeClient = clients["generic"]

func emit(d decision) { os.Exit(activeClient.Emit(d)) }

func deny(reason string) { emit(decision{Type: "deny", Reason: reason}) }

func allow() { emit(decision{Type: "allow"}) }

const hookVersion = 113

var buildVersion = "dev"

func main() {

	started := hookStart()

	if len(os.Args) > 1 && os.Args[1] == "--sg-version" {
		fmt.Println(hookVersion)
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "--sg-build" {
		fmt.Println(buildVersion)
		return
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "tokens":
			os.Exit(tokens.Run(os.Args[2:]))
		case "audit":
			os.Exit(auditcmd.Run(os.Args[2:], func(agentID string) bool { return clientFor(agentID).RedactsOutput }))
		case "shield":
			os.Exit(shield.Run(os.Args[2:]))
		}
	}

	agentType := "claude-code"
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "--") {
		agentType = os.Args[1]
	}
	agentName := agentType
	if len(os.Args) > 2 && !strings.HasPrefix(os.Args[2], "--") {
		agentName = os.Args[2]
	}

	agentID := agentType
	if v := os.Getenv("SOLONGATE_AGENT_ID"); v != "" {
		agentID = v
	}

	input, _ := io.ReadAll(os.Stdin)

	activeClient = clientFor(agentType)
	nc := normalizeToolCall(activeClient, agentType, input)
	c := nc.call

	local, localErr := guardcore.LoadLocalPolicyFile(c.Cwd)

	var sec *shared.Security
	hasSecurity := false
	if local != nil && local.HasSecurity {
		sec, hasSecurity = local.Security, true
	}
	if localErr != nil {
		record(sec, hasSecurity, c, agentType, agentName, localErr.Error(), started)
		deny(localErr.Error())
	}

	selfProtect := true
	if local != nil && local.SelfProtect != nil {
		selfProtect = *local.SelfProtect
	}
	if selfProtect {
		if reason := tamper.Check(c.Tool, c.Args, c.Cwd); reason != "" {
			record(sec, hasSecurity, c, agentType, agentName, reason, started)
			deny(reason)
		}
	}

	if reason := tamper.SandboxRequired(sec); reason != "" {
		record(sec, hasSecurity, c, agentType, agentName, reason, started)
		deny(reason)
	}
	if reason := tamper.UserProtectedCheck(c.Tool, c.Args, sec, c.Cwd); reason != "" {
		record(sec, hasSecurity, c, agentType, agentName, reason, started)
		deny(reason)
	}

	var pendingPatch map[string]interface{}

	if sec != nil {
		if reason := dlp.EgressSecretCheck(c.Args, sec, c.Cwd); reason != "" {
			record(sec, hasSecurity, c, agentType, agentName, reason, started)
			deny(reason)
		}
	}

	argsText := ""
	if b, err := json.Marshal(c.Args); err == nil {
		argsText = string(b)
	}

	if sec != nil && sec.DLPBlock != nil {
		if hit := shared.DLPScanViews(argsText, sec.DLPBlock); hit != "" {
			reason := "Security layer (DLP): blocked, arguments contain a " + hit +

				". Blocked by SolonGate (DLP). Edit ~/.solongate/policy.json to change what is refused."
			record(sec, hasSecurity, c, agentType, agentName, reason, started)
			deny(reason)
		}
	} else if cfg := observingDLP(sec); cfg != nil {

		if hit := shared.DLPScanViews(argsText, cfg.cfg); hit != "" {
			recordObserved(sec, hasSecurity, c, agentType, agentName,
				"Security layer (DLP): detected, arguments contain a "+hit+". Allowed: DLP is in "+cfg.mode+" mode.",
				started)
		}
	}

	if sec != nil && sec.RateLimitObserve != nil && !activeClient.ReportsAfter {
		if reason := ratelimit.Check(agentID, sec.RateLimitObserve); reason != "" {
			recordObserved(sec, hasSecurity, c, agentType, agentName,
				strings.Replace(reason, "Blocked by SolonGate (rate limit). Edit ~/.solongate/policy.json to review or adjust it.",
					"Allowed: the rate limit is in detect mode.", 1),
				started)
		}
	}

	if sec != nil && sec.RateLimit != nil {
		if reason := ratelimit.Check(agentID, sec.RateLimit); reason != "" {
			record(sec, hasSecurity, c, agentType, agentName, reason, started)
			deny(reason)
		}
	}

	var pol *shared.Policy
	if local != nil {
		pol = local.Policy
	}

	if pol != nil && !pol.AppliesTo(agentType) {
		pol = nil
	}
	policyReason := policy.EvaluatePolicy(pol, c.Args, c.Tool, c.Cwd)

	rec, _ := json.Marshal(map[string]interface{}{
		"ms":      elapsedMs(started),
		"ts":      time.Now().UnixMilli(),
		"tool":    c.Tool,
		"session": c.SessionID,
		"client":  agentType,

		"cwd":   c.Cwd,
		"perm":  shared.GuessPermission(c.Tool),
		"args":  policy.SortedKeys(c.Args),
		"paths": len(policy.ExtractPaths(c.Args, shared.GuessPermission(c.Tool) == "EXECUTE")),
		"cmds":  len(policy.ExtractCommands(c.Args)),
		"urls":  len(policy.ExtractURLs(c.Args)),

		"sandbox": os.Getenv(shared.SandboxEnv),
	})
	writeEvalRecord(shared.ProjectFlagDir(), rec)
	sweepLegacyScratch()

	if policyReason != "" {
		record(sec, hasSecurity, c, agentType, agentName, policyReason, started)
		deny(policyReason)
	}

	if sec != nil {
		blocking := sec.DLPBlock != nil
		dlpCfg := sec.DLPBlock
		if dlpCfg == nil {
			dlpCfg = sec.DLPRedact
		}
		if dlpCfg != nil && (blocking || !activeClient.RedactsOutput) {
			if plan := dlp.RedactReadPlan(c.Tool, c.Args, dlpCfg, c.Cwd); plan != nil {

				if plan.Block || blocking {
					reason := "Security layer (DLP): reading a file that contains a secret is blocked. Blocked by SolonGate."
					record(sec, hasSecurity, c, agentType, agentName, reason, started)
					deny(reason)
				}
				if len(plan.Rewrite) > 0 {
					if pendingPatch == nil {
						pendingPatch = map[string]interface{}{}
					}

					for k, v := range plan.Rewrite {
						pendingPatch[k] = v
					}
				}
			}
		}
	}

	if len(pendingPatch) > 0 {
		rewriteCall(pendingPatch)
	}

	allow()
}

func hookStart() time.Time {
	if v := os.Getenv("SOLONGATE_HOOK_ORIGIN_MS"); v != "" {
		if ms, err := strconv.ParseInt(v, 10, 64); err == nil {
			t := time.UnixMilli(ms)

			if d := time.Since(t); d >= 0 && d < time.Minute {
				return t
			}
		}
	}
	return time.Now()
}

func elapsedMs(started time.Time) float64 {
	return math.Round(float64(time.Since(started).Microseconds())/100) / 10
}
