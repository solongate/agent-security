// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tamper

import (
	"path"
	"regexp"
	"strings"

	"github.com/solongate/agent-security/packages/policy"
)

var cliBasenames = map[string]bool{
	"solongate": true, "solongate.exe": true,
	"solongate-proxy": true, "solongate-proxy.exe": true,
	"solongate-audit": true, "solongate-audit.exe": true,
}

var cliWrappers = map[string]bool{
	"sudo": true, "doas": true, "env": true, "nohup": true, "time": true,
	"command": true, "exec": true, "nice": true, "ionice": true, "stdbuf": true,
	"setsid": true, "xargs": true, "watch": true, "timeout": true, "builtin": true,

	"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true,
	"fish": true, "csh": true, "tcsh": true, "ash": true, "busybox": true, "eval": true,

	"script": true, "unbuffer": true, "expect": true, "socat": true,
	"flock": true, "chroot": true, "su": true, "runuser": true,
	"taskset": true, "strace": true, "ltrace": true, "proot": true,
	"fakeroot": true, "setarch": true, "nsenter": true, "systemd-run": true,
	"xvfb-run": true, "dbus-run-session": true,
}

var cliFlagTakesValue = map[string]bool{
	"-u": true, "-g": true, "-U": true, "-n": true, "-i": true, "-I": true,
	"-s": true, "-w": true, "-t": true, "-p": true, "-C": true,
	"--user": true, "--group": true, "--chdir": true,
}

var cliAlwaysRunners = map[string]bool{"npx": true, "pnpx": true, "bunx": true}

var cliMaybeRunners = map[string]bool{"npm": true, "pnpm": true, "yarn": true, "bun": true}

var cliRunSubcommands = map[string]bool{"exec": true, "dlx": true, "x": true}

var (
	reCLINumberish = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?[a-z]*$`)

	reCLIAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

	reCLIShellInterp    = regexp.MustCompile(`^(?:ba|z|da|k|fi|c|tc|a)?sh$|^busybox$|^pwsh$|^powershell$|^cmd$|^eval$|^source$|^\.$`)
	reCLIScriptInterp   = regexp.MustCompile(`^(?:python|pypy|node|nodejs|deno|bun|perl|ruby|php|lua|luajit|tclsh|wish|rscript|osascript)[0-9.]*$`)
	reCLIBacktickInterp = regexp.MustCompile(`^(?:perl|ruby|php)[0-9.]*$`)
	reCLIScriptExec     = regexp.MustCompile(
		`\b(?:subprocess|Popen|child_process|execSync|execFile(?:Sync)?|spawn(?:Sync)?|shell_exec|passthru|proc_open|Open3|qx)\b` +
			`|\b(?:os\.(?:system|popen|exec\w*|spawn\w*|execute)|pty\.spawn|Deno\.Command|Bun\.spawn(?:Sync)?|(?:IO|io)\.popen)\b` +
			`|\bKernel\.|Bun\.\$|\bdo\s+shell\s+script\b|%x[([\{/<|!]` +
			`|(?:^|[^\w.])(?:system|exec|popen|eval)\s*\(`,
	)
	reCLIScriptString   = regexp.MustCompile(`"""([\s\S]*?)"""|'''([\s\S]*?)'''|"([^"\n\\]*(?:\\.[^"\n\\]*)*)"|'([^'\n\\]*(?:\\.[^'\n\\]*)*)'|` + "`([^`]+)`")
	reCLIScriptBacktick = regexp.MustCompile("`([^`]+)`")
)

const (
	heredocModeInert    = 0
	heredocModeShell    = 1 << 0
	heredocModeScript   = 1 << 1
	heredocModeBacktick = 1 << 2
	maxCLISplitDepth    = 8
)

func commandInvokesCLI(cmd string) bool { return commandInvokesCLIDepth(cmd, 0) }

func commandInvokesCLIDepth(cmd string, depth int) bool {
	for _, fields := range splitCLICommands(cmd) {
		if fieldsInvokeCLI(fields, depth) {
			return true
		}
	}
	return false
}

func splitCLICommands(cmd string) [][]string { return splitCLICommandsDepth(cmd, 0, false) }

func splitCLICommandsDepth(cmd string, depth int, parentExecSub bool) [][]string {
	out := [][]string{}
	fields := []string{}
	tok := strings.Builder{}
	quote := byte(0)
	pending := []pendingHeredoc{}
	pipeStart := 0

	endToken := func() {
		if tok.Len() > 0 {
			fields = append(fields, tok.String())
			tok.Reset()
		}
	}
	endCommand := func() {
		endToken()
		if len(fields) > 0 {
			out = append(out, fields)
			fields = []string{}
		}
	}
	closePipe := func() {
		for k := range pending {
			if pending[k].pipeEnd < 0 {
				pending[k].pipeEnd = len(out)
			}
		}
		pipeStart = len(out)
	}

	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]
		if quote != 0 {
			switch {
			case ch == quote:
				quote = 0
			case ch == '\\' && quote == '"' && i+1 < len(cmd):
				if cmd[i+1] == '\n' {
					i++
					continue
				}
				if cmd[i+1] == '\r' && i+2 < len(cmd) && cmd[i+2] == '\n' {
					i += 2
					continue
				}
				i++
				tok.WriteByte(cmd[i])
			// Double-quoted $(...) executes immediately, so parse it recursively
			// with whether the enclosing command will execute its output.
			case quote == '"' && ch == '$' && i+1 < len(cmd) && cmd[i+1] == '(':
				sub, next := readCmdSub(cmd, i+2)
				if depth < maxCLISplitDepth {
					execSub := parentExecSub || cmdSubExecsOutput(fields, tok.String())
					out = append(out, splitCLICommandsDepth(sub, depth+1, execSub)...)
				}
				tok.WriteString(cmd[i:next])
				i = next - 1
			default:
				tok.WriteByte(ch)
			}
			continue
		}
		switch {
		case ch == '\'' || ch == '"':
			quote = ch
		// Collapse shell line continuations so a continued heredoc header
		// keeps its trailing pipeline stages before the body starts.
		case ch == '\\' && i+1 < len(cmd):
			if cmd[i+1] == '\n' {
				i++
				continue
			}
			if cmd[i+1] == '\r' && i+2 < len(cmd) && cmd[i+2] == '\n' {
				i += 2
				continue
			}
			i++
			tok.WriteByte(cmd[i])
		case ch == '$' && i+1 < len(cmd) && cmd[i+1] == '(':
			execSub := parentExecSub || cmdSubExecsOutput(fields, tok.String())
			sub, next := readCmdSub(cmd, i+2)
			if depth < maxCLISplitDepth {
				out = append(out, splitCLICommandsDepth(sub, depth+1, execSub)...)
			}
			endToken()
			i = next - 1
		case ch == '$' && i+1 < len(cmd) && cmd[i+1] == '{':
			i++
			endCommand()
			closePipe()

		// Queue heredocs until the unescaped newline so every pipeline stage
		// on the header line (and multiple heredocs) are resolved in shell order.
		case ch == '<' && i+1 < len(cmd) && cmd[i+1] == '<' && (i+2 >= len(cmd) || cmd[i+2] != '<'):
			endToken()
			delim, quoted, after := readHeredocDelimiter(cmd, i+2)
			if delim != "" || quoted {
				pending = append(pending, pendingHeredoc{
					delim:     delim,
					quoted:    quoted,
					stripTabs: i+2 < len(cmd) && cmd[i+2] == '-',
					pipeStart: pipeStart,
					pipeEnd:   -1,
					inCmdSub:  parentExecSub,
				})
			}
			i = after - 1
		case ch == '|':
			endCommand()
			if i+1 < len(cmd) && cmd[i+1] == '|' {
				i++
				closePipe()
			} else if i+1 < len(cmd) && cmd[i+1] == '&' {
				i++
			}
		// Keep fd redirections (2>&1, &>/dev/null) inside the current pipeline.
		case ch == '&' && ((i > 0 && (cmd[i-1] == '>' || cmd[i-1] == '<')) || (i+1 < len(cmd) && cmd[i+1] == '>')):
			tok.WriteByte(ch)
		case strings.IndexByte("&;\n\r`", ch) >= 0:
			if ch == '&' && i+1 < len(cmd) && cmd[i+1] == '&' {
				i++
			}
			endCommand()
			closePipe()
			if ch == '\n' && len(pending) > 0 {
				out, i = consumeHeredocs(cmd, i+1, pending, out, depth)
				pending, pipeStart = pending[:0], len(out)
			}
		case ch == ' ' || ch == '\t':
			endToken()
		default:
			tok.WriteByte(ch)
		}
	}
	endCommand()
	return out
}

func fieldsInvokeCLI(fields []string, depth int) bool {
	wrapped := false
	for i := 0; i < len(fields); i++ {
		tok := strings.Trim(fields[i], "(){}\"'")
		if tok == "" {
			continue
		}
		if reCLIAssignment.MatchString(tok) {
			wrapped = true
			continue
		}
		if wrapped {

			if strings.HasPrefix(tok, "-") {
				if cliFlagTakesValue[strings.ToLower(tok)] {
					i++
				}
				continue
			}
			if reCLINumberish.MatchString(tok) {
				continue
			}
		}

		if wrapped && depth < 8 && strings.ContainsAny(tok, " \t") {
			if commandInvokesCLIDepth(tok, depth+1) {
				return true
			}
		}

		base := strings.ToLower(path.Base(strings.ReplaceAll(tok, "\\", "/")))
		switch {
		case cliWrappers[base]:
			wrapped = true
		case cliBasenames[base]:
			return true
		case cliAlwaysRunners[base]:
			return restRunsCLIPackage(fields[i+1:])
		case cliMaybeRunners[base]:
			return maybeRunnerRunsCLI(fields[i+1:])
		default:

			if strings.ContainsAny(tok, "/\\") {
				continue
			}

			return false
		}
	}
	return false
}

func maybeRunnerRunsCLI(rest []string) bool {
	for j := 0; j < len(rest); j++ {
		if strings.HasPrefix(rest[j], "-") {
			continue
		}
		if cliRunSubcommands[strings.ToLower(rest[j])] {
			return restRunsCLIPackage(rest[j+1:])
		}
		return false
	}
	return false
}

func restRunsCLIPackage(rest []string) bool {
	for _, t := range rest {
		tl := strings.ToLower(t)
		if strings.Contains(tl, "solongate/proxy") || cliBasenames[tl] {
			return true
		}
	}
	return false
}

func readHeredocDelimiter(cmd string, i int) (delim string, quoted bool, after int) {
	if i < len(cmd) && cmd[i] == '-' {
		i++
	}
	for i < len(cmd) && (cmd[i] == ' ' || cmd[i] == '\t') {
		i++
	}
	if i >= len(cmd) {
		return "", false, i
	}
	var b strings.Builder
	for i < len(cmd) && !strings.ContainsRune(" \t\n\r;|&<>()", rune(cmd[i])) {
		if q := cmd[i]; q == '\'' || q == '"' {
			quoted = true
			for i++; i < len(cmd) && cmd[i] != q; i++ {
				b.WriteByte(cmd[i])
			}
		} else if cmd[i] == '\\' && i+1 < len(cmd) && cmd[i+1] != '\n' && cmd[i+1] != '\r' {
			quoted = true
			i++
			b.WriteByte(cmd[i])
		} else {
			b.WriteByte(cmd[i])
		}
		if i < len(cmd) {
			i++
		}
	}
	return b.String(), quoted, i
}

type pendingHeredoc struct {
	delim              string
	quoted, stripTabs  bool
	pipeStart, pipeEnd int
	inCmdSub           bool
}

func readHeredocBody(cmd string, start int, delim string, stripTabs bool) (string, int) {
	for i := start; i < len(cmd); {
		end := strings.IndexByte(cmd[i:], '\n')
		line, next := cmd[i:], len(cmd)
		if end >= 0 {
			line, next = cmd[i:i+end], i+end+1
		}
		check := strings.TrimRight(line, "\r")
		if stripTabs {
			check = strings.TrimLeft(check, "\t")
		}
		if check == delim {
			return cmd[start:i], next
		}
		i = next
	}
	return cmd[start:], len(cmd)
}

func consumeHeredocs(cmd string, pos int, pending []pendingHeredoc, out [][]string, depth int) ([][]string, int) {
	for _, h := range pending {
		body, next := readHeredocBody(cmd, pos, h.delim, h.stripTabs)
		pos = next
		mode := heredocModeInert
		if !h.quoted || h.inCmdSub {
			mode |= heredocModeShell
		}
		for _, stage := range out[h.pipeStart:h.pipeEnd] {
			mode |= commandHeredocMode(stage)
		}
		if mode == heredocModeInert || body == "" || depth >= maxCLISplitDepth {
			continue
		}
		if mode&heredocModeShell != 0 {
			out = append(out, splitCLICommandsDepth(body, depth+1, false)...)
		}
		if mode&heredocModeScript != 0 {
			out = append(out, extractScriptExecCommands(body, mode&heredocModeBacktick != 0, depth+1)...)
		}
	}
	return out, pos - 1
}

// extractScriptExecCommands only inspects strings inside script heredoc bodies
// that contain a command-execution construct (or backtick execution in
// Perl/Ruby/PHP), leaving ordinary print/log strings benign.
func extractScriptExecCommands(body string, backtickExec bool, depth int) [][]string {
	var out [][]string
	if reCLIScriptExec.MatchString(body) {
		for _, m := range reCLIScriptString.FindAllStringSubmatch(body, -1) {
			if s := m[1] + m[2] + m[3] + m[4] + m[5]; s != "" {
				out = append(out, splitCLICommandsDepth(s, depth, false)...)
			}
		}
		return out
	}
	if backtickExec {
		for _, m := range reCLIScriptBacktick.FindAllStringSubmatch(body, -1) {
			if m[1] != "" {
				out = append(out, splitCLICommandsDepth(m[1], depth, false)...)
			}
		}
	}
	return out
}

// readCmdSub extracts the inner text of $(...) starting after "$(", skipping
// quotes, escapes, and nested heredoc bodies so ')' inside them cannot close
// the substitution prematurely.
func readCmdSub(cmd string, start int) (string, int) {
	type subHeredoc struct {
		delim     string
		stripTabs bool
	}
	parens, q := 1, byte(0)
	var pending []subHeredoc
	for i := start; i < len(cmd); i++ {
		ch := cmd[i]
		if q != 0 {
			if ch == '\\' && q == '"' && i+1 < len(cmd) {
				i++
				continue
			}
			if ch == q {
				q = 0
			}
			continue
		}
		switch {
		case ch == '\'' || ch == '"':
			q = ch
		case ch == '\\' && i+1 < len(cmd):
			if cmd[i+1] == '\r' && i+2 < len(cmd) && cmd[i+2] == '\n' {
				i += 2
				continue
			}
			i++
		case ch == '<' && i+1 < len(cmd) && cmd[i+1] == '<' && (i+2 >= len(cmd) || cmd[i+2] != '<'):
			delim, quoted, after := readHeredocDelimiter(cmd, i+2)
			if delim != "" || quoted {
				pending = append(pending, subHeredoc{delim, i+2 < len(cmd) && cmd[i+2] == '-'})
			}
			i = after - 1
		case ch == '\n' && len(pending) > 0:
			pos := i + 1
			for _, h := range pending {
				_, pos = readHeredocBody(cmd, pos, h.delim, h.stripTabs)
			}
			pending = pending[:0]
			i = pos - 1
		case ch == '(':
			parens++
		case ch == ')':
			parens--
			if parens == 0 {
				return cmd[start:i], i + 1
			}
		}
	}
	return cmd[start:], len(cmd)
}

func cmdSubExecsOutput(fields []string, tokPrefix string) bool {
	if len(fields) == 0 {
		return tokPrefix == ""
	}
	if commandHeredocMode(fields)&heredocModeShell != 0 {
		return true
	}
	if tokPrefix != "" {
		return false
	}
	// Leading assignments or wrappers (e.g. "FOO=1 $(...)", "sudo $(...)")
	// leave the command substitution itself in command position.
	return fieldsExpectCommand(fields)
}

func fieldsExpectCommand(fields []string) bool {
	wrapped := false
	for i := 0; i < len(fields); i++ {
		tok := strings.Trim(fields[i], "(){}\"'")
		if tok == "" || reCLIAssignment.MatchString(tok) {
			wrapped = wrapped || tok != ""
			continue
		}
		if wrapped && (strings.HasPrefix(tok, "-") || reCLINumberish.MatchString(tok)) {
			if cliFlagTakesValue[strings.ToLower(tok)] && i+1 < len(fields) && commandHeredocMode(fields[i+1:i+2]) == 0 && !cliWrappers[cliBaseName(fields[i+1])] {
				i++
			}
			continue
		}
		if cliWrappers[cliBaseName(tok)] {
			wrapped = true
			continue
		}
		return false
	}
	return true
}

func commandHeredocMode(fields []string) int {
	wrapped := false
	for i := 0; i < len(fields); i++ {
		tok := strings.Trim(fields[i], "(){}\"'")
		if tok == "" || reCLIAssignment.MatchString(tok) {
			wrapped = wrapped || tok != ""
			continue
		}
		if wrapped && (strings.HasPrefix(tok, "-") || reCLINumberish.MatchString(tok)) {
			if cliFlagTakesValue[strings.ToLower(tok)] && i+1 < len(fields) && commandHeredocMode(fields[i+1:i+2]) == 0 && !cliWrappers[cliBaseName(fields[i+1])] {
				i++
			}
			continue
		}
		base := cliBaseName(tok)
		switch {
		case reCLIShellInterp.MatchString(base):
			return heredocModeShell
		case reCLIScriptInterp.MatchString(base):
			if reCLIBacktickInterp.MatchString(base) {
				return heredocModeScript | heredocModeBacktick
			}
			return heredocModeScript
		case cliWrappers[base]:
			wrapped = true
		default:
			return heredocModeInert
		}
	}
	return heredocModeInert
}

func cliBaseName(raw string) string {
	tok := strings.Trim(raw, "(){}\"'")
	return strings.TrimSuffix(strings.ToLower(path.Base(strings.ReplaceAll(tok, "\\", "/"))), ".exe")
}

func argsInvokeCLI(args map[string]interface{}) bool {
	for _, k := range policy.SortedKeys(args) {
		if !cliCommandFields[strings.ToLower(k)] {
			continue
		}
		if s, ok := args[k].(string); ok && commandInvokesCLI(s) {
			return true
		}
	}
	return false
}

var cliCommandFields = map[string]bool{
	"command": true, "cmd": true, "function": true, "script": true, "shell": true,
}
