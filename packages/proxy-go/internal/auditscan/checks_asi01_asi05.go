package auditscan

import (
	"fmt"
	"strings"
)

// ── ASI01: Agent Goal Hijacking ────────────────────────────────────────────
//
// Injection is looked for in tool ARGUMENTS and in tool RESULTS. The second is
// the one that matters: an instruction the agent read out of a file or a web
// page is indirect prompt injection, and it is the only place the agent's
// operator never sees it.

var injectionPatterns = []jsRegexp{
	ciLower(`ignore\s+(previous|above|all)\s+(instructions|rules)`),
	ciLower(`you\s+are\s+now\s+(a|an|the)`),
	ciLower(`\<\/?system\s*>`),
	ciLower(`\[\s*INST\s*\]`),
	ciLower(`act\s+as\s+(a|an|if)\s+you`),
	ciLower(`forget\s+(everything|all|your)\s+(instructions|rules|context)`),
	ciLower(`override\s+(your|the|all)\s+(instructions|rules|safety)`),
	ciLower(`new\s+instructions?\s*:`),
	ciLower(`do\s+not\s+follow\s+(any|your|the)\s+(previous|original)`),
	ciLower(`disregard\s+(all|any|your)\s+(previous|prior|original)`),
}

var (
	// A long run of base64 alphabet next to a word that suggests it is about to
	// be decoded. Either half alone is ordinary.
	rxBase64Blob = cs(`[A-Za-z0-9+/]{50,}={0,2}`)
	rxDecodeWord = ciLower(`base64|decode|eval`)
)

func checkGoalHijacking(data *AuditData, deep *DeepAnalysis) CheckResult {
	const code, title = "ASI01", "Goal Hijacking"
	var evidence evidenceList

	injectionAttempts := 0
	var examples []string

	for _, tc := range data.AllCalls() {
		argStr := tc.ArgsLower()
		resultStr := tc.ResultLower()

		for _, p := range injectionPatterns {
			if p.test(argStr) {
				injectionAttempts++
				if len(examples) < 3 {
					examples = append(examples, tc.ToolName+": arg matches "+p.sourceHead(30))
				}
				break
			}
		}

		for _, p := range injectionPatterns {
			if p.test(resultStr) {
				injectionAttempts++
				if len(examples) < 3 {
					examples = append(examples, tc.ToolName+": result contains injection pattern")
				}
				break
			}
		}
	}

	evidence.add(IconInfo, fmt.Sprintf("Scanned %d tool calls for prompt injection patterns", data.TotalToolCalls))

	if injectionAttempts == 0 {
		evidence.add(IconFound, "No prompt injection patterns detected in tool calls or results")
	} else {
		evidence.add(IconWarn, fmt.Sprintf("%d potential prompt injection pattern(s) detected", injectionAttempts))
		for _, ex := range examples {
			evidence.add(IconWarn, "  "+ex)
		}
	}

	encodedPayloads := 0
	for _, tc := range data.AllCalls() {
		// The keyword test runs first. Both have to hold, and scanning for a
		// fifty-character base64 run is the expensive half.
		r := tc.ResultLower()
		if rxDecodeWord.test(r) && rxBase64Blob.test(r) {
			encodedPayloads++
		}
	}
	if encodedPayloads > 0 {
		evidence.add(IconWarn, fmt.Sprintf(
			"%d tool result(s) contain encoded payloads (potential obfuscated injection)", encodedPayloads))
	}

	if deep != nil {
		hijackChains := chainsNamed(deep.Chains, "cross-contamination", "read-exec-chain")
		if len(hijackChains) > 0 {
			evidence.add(IconWarn, fmt.Sprintf(
				"%d hijacking chain(s): file content flowing into execution", len(hijackChains)))
			for _, chain := range headN(hijackChains, 3) {
				evidence.add(IconWarn, "  "+chainToolPath(chain)+" ("+chain.Description+")")
			}
			injectionAttempts += len(hijackChains)
		}
	}

	if injectionAttempts == 0 && encodedPayloads == 0 {
		return CheckResult{
			Code: code, Title: title, Status: StatusProtected, Evidence: evidence,
			Summary: "No prompt injection patterns found in agent logs.",
			Details: fmt.Sprintf("Scanned %d tool calls. No known injection patterns (delimiter injection, role hijacking, encoded payloads) detected in arguments or results.", data.TotalToolCalls),
		}
	}

	total := data.TotalToolCalls
	if total == 0 {
		total = 1
	}
	rate := toFixed(float64(injectionAttempts+encodedPayloads)/float64(total)*100, 2)

	if float64(injectionAttempts+encodedPayloads)/float64(total) < 0.005 {
		return CheckResult{
			Code: code, Title: title, Status: StatusPartial, Evidence: evidence,
			Summary:        fmt.Sprintf("%d potential injection pattern(s) in %d calls (%s%%).", injectionAttempts, total, rate),
			Details:        "Low-frequency injection patterns found. Could be false positives or minor attempts. Review the flagged calls.",
			Recommendation: "Enable input guard on MCP proxy to block injection patterns before tool execution.",
		}
	}

	return CheckResult{
		Code: code, Title: title, Status: StatusNotProtected, Evidence: evidence,
		Summary:        fmt.Sprintf("%d prompt injection patterns in %d calls (%s%%).", injectionAttempts, total, rate),
		Details:        "Injection patterns found in tool arguments or results. Agents may have processed malicious instructions from external content.",
		Recommendation: "Enable input guard + AI Judge for semantic prompt injection analysis.",
	}
}

// ── ASI02: Tool Misuse and Exploitation ────────────────────────────────────
//
// The lists here are deliberately narrow. An earlier version flagged every
// `.env` and every `rm -rf ./dist`, which meant the check was red on every
// machine and therefore told nobody anything.

var sensitiveFiles = []string{
	".env.production", "credentials.json", "id_rsa", "id_ed25519", ".pem",
	"/etc/shadow", "/etc/passwd", "service-account.json", ".npmrc",
}

var destructivePatterns = []jsRegexp{
	cs(`rm\s+-rf\s+[\/~$.]`),   // rm -rf on root, home, or the current directory
	cs(`rm\s+-rf\s+\*`),        // rm -rf *
	ciLower(`del\s+\/[sf]`),    // del /f or /s on Windows
	ciLower(`format\s+[a-z]:`), // format C:
	ciLower(`drop\s+(table|database)`),
	ciLower(`truncate\s+table`),
}

// Ordinary curl and wget are not here. What is here is the shape of moving data
// off the machine rather than fetching something onto it.
var exfilPatterns = []jsRegexp{
	cs(`\bnc\s+-[a-z]*\s+\S+\s+\d+`), // nc connecting to host:port
	cs(`\bncat\s+`),
	cs(`>\s*\/dev\/tcp`), // bash /dev/tcp redirect
	cs(`curl\s+.*--upload-file`),
	cs(`scp\s+\S+\s+\S+@`),
}

var wildcardQueries = []string{"SELECT *", "WHERE 1=1", "WHERE true", "OR 1=1"}

func checkToolMisuse(data *AuditData, deep *DeepAnalysis) CheckResult {
	const code, title = "ASI02", "Tool Misuse"
	var evidence evidenceList

	sensitiveAccess, destructiveCmds, exfilAttempts, wildcardCount := 0, 0, 0, 0
	var flagged []string

	for _, tc := range data.AllCalls() {
		argStr := tc.ArgsLower()
		toolLower := lowerName(tc)

		if strings.Contains(toolLower, "read") || strings.Contains(toolLower, "file") || strings.Contains(toolLower, "cat") {
			for _, sf := range sensitiveFiles {
				if strings.Contains(argStr, strings.ToLower(sf)) {
					sensitiveAccess++
					if len(flagged) < 5 {
						flagged = append(flagged, tc.ToolName+": accessed "+sf)
					}
					break
				}
			}
		}

		if strings.Contains(toolLower, "bash") || strings.Contains(toolLower, "shell") ||
			strings.Contains(toolLower, "exec") || strings.Contains(toolLower, "terminal") {
			for _, dp := range destructivePatterns {
				if dp.test(argStr) {
					destructiveCmds++
					if len(flagged) < 5 {
						flagged = append(flagged, tc.ToolName+": destructive command matching "+dp.sourceHead(30))
					}
					break
				}
			}

			for _, ep := range exfilPatterns {
				if ep.test(argStr) {
					exfilAttempts++
					if len(flagged) < 5 {
						flagged = append(flagged, tc.ToolName+": potential exfiltration via "+ep.sourceHead(25))
					}
					break
				}
			}
		}

		if strings.Contains(toolLower, "query") || strings.Contains(toolLower, "sql") || strings.Contains(toolLower, "db") {
			for _, wq := range wildcardQueries {
				if strings.Contains(argStr, strings.ToLower(wq)) {
					wildcardCount++
					if len(flagged) < 5 {
						flagged = append(flagged, tc.ToolName+`: wildcard query "`+wq+`"`)
					}
					break
				}
			}
		}
	}

	if deep != nil {
		exfilChains := chainsNamed(deep.Chains, "credential-exfiltration")
		if len(exfilChains) > 0 {
			exfilAttempts += len(exfilChains)
			for _, c := range headN(exfilChains, 2) {
				flagged = append(flagged, "Chain: "+chainToolPath(c)+" ("+c.Description+")")
			}
		}
		if len(deep.DataFlowLeaks) > 0 {
			exfilAttempts += len(deep.DataFlowLeaks)
			for _, leak := range headN(deep.DataFlowLeaks, 3) {
				flagged = append(flagged, fmt.Sprintf("Data flow: %s (%s) → %s",
					leak.SourceToolName, leak.DataType, leak.SinkToolName))
			}
		}
	}

	totalIssues := sensitiveAccess + destructiveCmds + exfilAttempts + wildcardCount

	evidence.add(IconInfo, fmt.Sprintf("Scanned %d tool calls for misuse patterns", data.TotalToolCalls))

	if sensitiveAccess > 0 {
		evidence.add(IconWarn, fmt.Sprintf("%d sensitive file access(es) (.env, credentials, keys)", sensitiveAccess))
	}
	if destructiveCmds > 0 {
		evidence.add(IconWarn, fmt.Sprintf("%d destructive command(s) (rm, del, drop, truncate)", destructiveCmds))
	}
	if exfilAttempts > 0 {
		evidence.add(IconWarn, fmt.Sprintf("%d potential data exfiltration attempt(s) (curl, wget, nc)", exfilAttempts))
	}
	if wildcardCount > 0 {
		evidence.add(IconWarn, fmt.Sprintf("%d wildcard database query(ies) (SELECT *, WHERE 1=1)", wildcardCount))
	}
	for _, f := range flagged {
		evidence.add(IconWarn, "  "+f)
	}

	if totalIssues == 0 {
		evidence.add(IconFound, "No tool misuse patterns detected")
		return CheckResult{
			Code: code, Title: title, Status: StatusProtected, Evidence: evidence,
			Summary: "No tool misuse detected in agent logs.",
			Details: fmt.Sprintf("Scanned %d tool calls. No sensitive file access, destructive commands, exfiltration attempts, or wildcard queries found.", data.TotalToolCalls),
		}
	}

	total := data.TotalToolCalls
	if total == 0 {
		total = 1
	}
	rate := toFixed(float64(totalIssues)/float64(total)*100, 2)

	// An exfiltration attempt is never "low frequency". One is the finding.
	if float64(totalIssues)/float64(total) < 0.01 && exfilAttempts == 0 {
		return CheckResult{
			Code: code, Title: title, Status: StatusPartial, Evidence: evidence,
			Summary:        fmt.Sprintf("%d tool misuse pattern(s) in %d calls (%s%%).", totalIssues, total, rate),
			Details:        "Low-frequency misuse patterns. May be legitimate development operations. Review flagged calls.",
			Recommendation: "Add policy.json with DENY rules for sensitive files and destructive commands.",
		}
	}

	return CheckResult{
		Code: code, Title: title, Status: StatusNotProtected, Evidence: evidence,
		Summary:        fmt.Sprintf("%d tool misuse pattern(s) in %d calls (%s%%).", totalIssues, total, rate),
		Details:        "Agents accessed sensitive files, ran destructive commands, or attempted data exfiltration. No policy enforcement prevented these actions.",
		Recommendation: "Create policy.json with DENY rules. Enforce via MCP proxy with argument constraints.",
	}
}

// ── ASI03: Identity and Privilege Abuse ────────────────────────────────────
//
// This check can never come back PROTECTED, and that is correct: a transcript
// records which model claimed to be acting, and nothing verifies the claim.
// The best available answer is PARTIAL — identity is tracked but self-reported.

var privPatterns = []string{
	"/etc/passwd", "/etc/shadow", "chmod ", "chown ", "sudo ", "runas ", "admin", "root",
}

var credentialDataTypes = map[string]bool{
	"api_key": true, "bearer_token": true, "aws_key": true, "private_key": true,
	"password": true, "openai_api_key": true, "stripe_key": true, "github_pat": true,
}

func checkIdentityAbuse(data *AuditData, deep *DeepAnalysis) CheckResult {
	const code, title = "ASI03", "Identity Abuse"
	var evidence evidenceList

	evidence.add(IconInfo, fmt.Sprintf("%d session(s) from %s", len(data.Sessions), strings.Join(data.Sources, ", ")))

	withModel := 0
	for _, s := range data.Sessions {
		if s.Model != "" {
			withModel++
		}
	}
	switch {
	case withModel == len(data.Sessions):
		evidence.add(IconFound, "All sessions have model identity recorded")
	case withModel > 0:
		evidence.add(IconWarn, fmt.Sprintf("%d session(s) missing model identity", len(data.Sessions)-withModel))
	default:
		evidence.add(IconMissing, "No sessions have model identity recorded")
	}

	// Which files each client touched, kept in first-seen order so the overlap
	// is computed against the same "first" source on every run.
	fileAccess := map[string]map[string]bool{}
	var accessOrder []string
	for _, tc := range data.AllCalls() {
		var file string
		for _, key := range []string{"file_path", "path", "filename"} {
			if v, ok := tc.Arguments.Get(key); ok && truthy(v) {
				if s, ok := v.(string); ok {
					file = s
					break
				}
			}
		}
		if file == "" {
			continue
		}
		src := string(tc.Source)
		if _, seen := fileAccess[src]; !seen {
			fileAccess[src] = map[string]bool{}
			accessOrder = append(accessOrder, src)
		}
		fileAccess[src][file] = true
	}

	if len(accessOrder) > 1 {
		overlap := map[string]bool{}
		for file := range fileAccess[accessOrder[0]] {
			for i := 1; i < len(accessOrder); i++ {
				if fileAccess[accessOrder[i]][file] {
					overlap[file] = true
				}
			}
		}
		if len(overlap) > 0 {
			evidence.add(IconWarn, fmt.Sprintf(
				"%d file(s) accessed by multiple agents without privilege separation", len(overlap)))
		}
	}

	privEscalation := 0
	for _, tc := range data.AllCalls() {
		argStr := tc.ArgsLower()
		for _, p := range privPatterns {
			if strings.Contains(argStr, p) {
				privEscalation++
				break
			}
		}
	}
	if privEscalation > 0 {
		evidence.add(IconWarn, fmt.Sprintf("%d potential privilege escalation attempt(s) in logs", privEscalation))
	}

	if deep != nil {
		var credFlows []DataFlowLeak
		for _, l := range deep.DataFlowLeaks {
			if credentialDataTypes[l.DataType] {
				credFlows = append(credFlows, l)
			}
		}
		if len(credFlows) > 0 {
			evidence.add(IconWarn, fmt.Sprintf(
				"%d credential(s) flowed through tool calls without identity verification", len(credFlows)))
			for _, cf := range headN(credFlows, 3) {
				evidence.add(IconWarn, fmt.Sprintf("  %s (%s) → %s", cf.SourceToolName, cf.DataType, cf.SinkToolName))
			}
			privEscalation += len(credFlows)
		}
	}

	evidence.add(IconMissing, "No principal binding — API keys not bound to agent identities in logs")
	evidence.add(IconMissing, "No verified principal in audit trail (identity is self-reported)")

	issues := privEscalation
	if len(accessOrder) > 1 {
		issues++
	}

	if issues == 0 && withModel == len(data.Sessions) {
		return CheckResult{
			Code: code, Title: title, Status: StatusPartial, Evidence: evidence,
			Summary:        "Agent identity tracked in logs, but no principal binding.",
			Details:        "Sessions record which model/agent ran. But identity is self-reported, not cryptographically verified. No per-agent privilege boundaries.",
			Recommendation: "Add principal binding. Enable strict identity mode. Add agentTrustMap for per-agent privileges.",
		}
	}

	total := data.TotalToolCalls
	if total == 0 {
		total = 1
	}
	privRate := toFixed(float64(privEscalation)/float64(total)*100, 2)

	if issues > 0 && float64(privEscalation)/float64(total) < 0.05 {
		return CheckResult{
			Code: code, Title: title, Status: StatusPartial, Evidence: evidence,
			Summary:        fmt.Sprintf("%d privilege escalation pattern(s) in %d calls (%s%%).", privEscalation, total, privRate),
			Details:        "Low-frequency privilege patterns found. May include legitimate admin operations. No principal binding or verified identity.",
			Recommendation: "Add principal binding. Enable strict identity mode. Implement per-agent privilege scoping.",
		}
	}

	if issues > 0 {
		return CheckResult{
			Code: code, Title: title, Status: StatusNotProtected, Evidence: evidence,
			Summary:        fmt.Sprintf("%d privilege escalation pattern(s) in %d calls (%s%%).", privEscalation, total, privRate),
			Details:        "High-frequency privilege escalation found. Multiple agents accessing same resources without separation. No principal binding or verified identity.",
			Recommendation: "Add principal binding. Enable strict identity mode. Implement per-agent privilege scoping.",
		}
	}

	return CheckResult{
		Code: code, Title: title, Status: StatusNotProtected, Evidence: evidence,
		Summary:        "No agent identity verification or privilege control in logs.",
		Details:        "Agent identity is not tracked or verified. No principal binding, no per-agent permissions. Any agent can act with full privileges.",
		Recommendation: "Set up MCP proxy (tracks identity). Add principal binding. Enable strict identity mode.",
	}
}

// ── ASI04: Agentic Supply Chain ────────────────────────────────────────────

var knownTools = []string{
	"read", "write", "edit", "glob", "grep", "bash", "shell", "exec", "list", "search",
	"file", "directory", "notebook", "web", "browser", "navigate", "screenshot", "mcp_filesystem",
	"mcp_playwright", "task", "todo", "memory", "ask",
}

var rxPinnedVersion = cs(`@\d+\.\d+`)

func checkSupplyChain(data *AuditData) CheckResult {
	const code, title = "ASI04", "Supply Chain"
	var evidence evidenceList

	latestInstalls, unpinnedInstalls, unknownTools := 0, 0, 0
	var flagged []string

	for _, tc := range data.AllCalls() {
		argStr := tc.ArgsLower()
		toolLower := lowerName(tc)

		if strings.Contains(toolLower, "bash") || strings.Contains(toolLower, "shell") || strings.Contains(toolLower, "exec") {
			isNodeInstall := strings.Contains(argStr, "npm install") || strings.Contains(argStr, "npm i ") ||
				strings.Contains(argStr, "pnpm add") || strings.Contains(argStr, "yarn add")
			if isNodeInstall {
				if strings.Contains(argStr, "@latest") {
					latestInstalls++
					if len(flagged) < 5 {
						flagged = append(flagged, tc.ToolName+": installed package with @latest")
					}
				}
				if !rxPinnedVersion.test(argStr) && !strings.Contains(argStr, "@latest") {
					unpinnedInstalls++
				}
			}
			if strings.Contains(argStr, "pip install") && !strings.Contains(argStr, "==") {
				unpinnedInstalls++
				if len(flagged) < 5 {
					flagged = append(flagged, tc.ToolName+": pip install without pinned version")
				}
			}
		}

		known := false
		for _, kt := range knownTools {
			if strings.Contains(toolLower, kt) {
				known = true
				break
			}
		}
		if !known {
			unknownTools++
		}
	}

	evidence.add(IconInfo, fmt.Sprintf("Scanned %d tool calls for supply chain risks", data.TotalToolCalls))

	if latestInstalls > 0 {
		evidence.add(IconWarn, fmt.Sprintf(
			"%d package install(s) with @latest — unpinned, can change without notice", latestInstalls))
	}
	if unpinnedInstalls > 0 {
		evidence.add(IconWarn, fmt.Sprintf("%d package install(s) without pinned version", unpinnedInstalls))
	}
	if unknownTools > 0 {
		evidence.add(IconInfo, fmt.Sprintf(
			"%d calls to non-standard tools (may include injected tools)", unknownTools))
	}
	for _, f := range flagged {
		evidence.add(IconWarn, "  "+f)
	}

	evidence.add(IconMissing, "No deny-undeclared-default rule — unknown tools are not blocked")
	evidence.add(IconMissing, "No tool allowlist verification in logs")

	totalIssues := latestInstalls + unpinnedInstalls

	if totalIssues == 0 {
		return CheckResult{
			Code: code, Title: title, Status: StatusPartial, Evidence: evidence,
			Summary:        "No risky package installs detected, but no tool allowlist.",
			Details:        "No @latest or unpinned package installs found in logs. But no deny-undeclared-default rule exists to block unknown tools.",
			Recommendation: "Add deny-undeclared-default rule. Add tool allowlist. Pin all package versions.",
		}
	}

	if totalIssues <= 5 {
		return CheckResult{
			Code: code, Title: title, Status: StatusPartial, Evidence: evidence,
			Summary:        fmt.Sprintf("%d risky package install(s) — low frequency.", totalIssues),
			Details:        "Some packages installed without pinned versions, but at low frequency. Review and pin specific versions.",
			Recommendation: "Pin all package versions. Add deny-undeclared-default rule. Add tool allowlist.",
		}
	}

	return CheckResult{
		Code: code, Title: title, Status: StatusNotProtected, Evidence: evidence,
		Summary:        fmt.Sprintf("%d risky package install(s) detected in logs.", totalIssues),
		Details:        "Agents installed packages without pinned versions. A compromised package could inject malicious tools. No tool allowlist blocks unknown tools.",
		Recommendation: "Pin all package versions. Add deny-undeclared-default rule. Add tool allowlist.",
	}
}

// ── ASI05: Unexpected Code Execution ───────────────────────────────────────
//
// `git status && git push` is not dangerous and used to be flagged. What is
// listed here is code arriving from somewhere else and being run.

var dangerousExecPatterns = []struct {
	p     jsRegexp
	label string
}{
	{cs(`eval\s*\(`), "eval() — arbitrary code execution"},
	{cs(`\bexec\s*\(`), "exec() — arbitrary code execution"},
	{cs(`python\s+-c\s+['"]`), "python -c inline code execution"},
	{cs(`node\s+-e\s+['"]`), "node -e inline code execution"},
	{cs(`curl\s+.*\|\s*(ba)?sh`), "curl pipe to shell — remote code execution"},
	{cs(`wget\s+.*\|\s*(ba)?sh`), "wget pipe to shell — remote code execution"},
	{cs(`base64\s+-d\s*\|`), "base64 decode piped to execution"},
	{ci(`powershell\s+-e(ncodedcommand)?`), "powershell encoded command"},
}

func checkCodeExecution(data *AuditData, deep *DeepAnalysis) CheckResult {
	const code, title = "ASI05", "Code Execution"
	var evidence evidenceList

	shellCalls, dangerousExec := 0, 0
	noSandbox := true
	var flagged []string

	for _, tc := range data.AllCalls() {
		toolLower := lowerName(tc)
		argStr := tc.ArgsJSON()

		if !(strings.Contains(toolLower, "bash") || strings.Contains(toolLower, "shell") ||
			strings.Contains(toolLower, "exec") || strings.Contains(toolLower, "terminal")) {
			continue
		}
		shellCalls++

		if strings.Contains(argStr, "docker ") || strings.Contains(argStr, "sandbox") || strings.Contains(argStr, "container") {
			noSandbox = false
		}

		for _, d := range dangerousExecPatterns {
			if d.p.test(argStr) {
				dangerousExec++
				if len(flagged) < 5 {
					flagged = append(flagged, tc.ToolName+": "+d.label)
				}
				break
			}
		}
	}

	evidence.add(IconInfo, fmt.Sprintf("%d shell/exec call(s) found in %d session(s)", shellCalls, len(data.Sessions)))

	if shellCalls == 0 {
		evidence.add(IconFound, "No shell execution calls detected in logs")
		return CheckResult{
			Code: code, Title: title, Status: StatusProtected, Evidence: evidence,
			Summary: "No code execution detected in agent logs.",
			Details: "No shell commands, eval, or script execution found in any session.",
		}
	}

	if dangerousExec > 0 {
		evidence.add(IconWarn, fmt.Sprintf("%d dangerous execution pattern(s) detected", dangerousExec))
		for _, f := range flagged {
			evidence.add(IconWarn, "  "+f)
		}
	} else {
		evidence.add(IconFound, "No dangerous execution patterns (injection, chaining) detected")
	}

	if noSandbox {
		evidence.add(IconMissing, "No sandbox/container execution detected — all commands run on host")
	} else {
		evidence.add(IconFound, "Some commands executed in container/sandbox environment")
	}

	if deep != nil {
		execChains := chainsNamed(deep.Chains, "privilege-escalation-sequence", "read-exec-chain")
		if len(execChains) > 0 {
			evidence.add(IconWarn, fmt.Sprintf(
				"%d execution chain(s): file content flowing into shell commands", len(execChains)))
			for _, chain := range headN(execChains, 3) {
				evidence.add(IconWarn, "  "+chainToolPath(chain))
			}
			dangerousExec += len(execChains)
		}
	}

	evidence.add(IconMissing, "No REVIEW decision — code execution not routed for human approval")

	if dangerousExec == 0 && !noSandbox {
		return CheckResult{
			Code: code, Title: title, Status: StatusProtected, Evidence: evidence,
			Summary: "Shell calls detected but executed in sandbox with no dangerous patterns.",
			Details: fmt.Sprintf("%d shell calls found. No command injection patterns. Container isolation detected.", shellCalls),
		}
	}

	if dangerousExec == 0 {
		return CheckResult{
			Code: code, Title: title, Status: StatusPartial, Evidence: evidence,
			Summary:        fmt.Sprintf("%d shell calls — no injection patterns, but no sandbox.", shellCalls),
			Details:        "Shell commands were executed on the host system without container isolation. No command injection patterns detected, but any bypass means full system access.",
			Recommendation: "Add REVIEW decision for code exec tools. Add Dockerfile for sandbox. Add input guard.",
		}
	}

	dangerRate := "0"
	if shellCalls > 0 {
		dangerRate = toFixed(float64(dangerousExec)/float64(shellCalls)*100, 2)
	}
	denom := shellCalls
	if denom == 0 {
		denom = 1
	}

	if float64(dangerousExec)/float64(denom) < 0.005 {
		return CheckResult{
			Code: code, Title: title, Status: StatusPartial, Evidence: evidence,
			Summary:        fmt.Sprintf("%d dangerous pattern(s) in %d shell calls (%s%%).", dangerousExec, shellCalls, dangerRate),
			Details:        "Very low-frequency dangerous patterns. Likely legitimate usage. No sandbox or human approval.",
			Recommendation: "Add REVIEW decision for code exec. Add sandbox (Dockerfile). Add input guard.",
		}
	}

	return CheckResult{
		Code: code, Title: title, Status: StatusNotProtected, Evidence: evidence,
		Summary:        fmt.Sprintf("%d dangerous pattern(s) in %d shell calls (%s%%).", dangerousExec, shellCalls, dangerRate),
		Details:        "Agents executed shell commands with dangerous patterns (command chaining, injection, eval). No sandbox, no human approval. Full RCE possible.",
		Recommendation: "Add REVIEW decision for code exec. Add sandbox (Dockerfile). Add input guard + command restrictions.",
	}
}
