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

	reCLIShellInterp  = regexp.MustCompile(`^(?:ba|z|da|k|fi|c|tc|a)?sh$|^busybox$|^pwsh$|^powershell$|^cmd$|^eval$|^source$|^\.$`)
	reCLIScriptInterp = regexp.MustCompile(`^(?:python|pypy|node|nodejs|deno|bun|perl|ruby|php|lua|luajit|tclsh|wish|rscript|osascript)[0-9.]*$`)
	reCLIScriptString = regexp.MustCompile(`"([^"\n\\]*(?:\\.[^"\n\\]*)*)"|'([^'\n\\]*(?:\\.[^'\n\\]*)*)'|` + "`([^`]+)`")
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

func splitCLICommands(cmd string) [][]string {
	out := [][]string{}
	fields := []string{}
	tok := strings.Builder{}
	quote := byte(0)
	inCmdSub := false

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

	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]
		if quote != 0 {
			switch {
			case ch == quote:
				quote = 0
			case ch == '\\' && quote == '"' && i+1 < len(cmd):

				i++
				tok.WriteByte(cmd[i])
			default:
				tok.WriteByte(ch)
			}
			continue
		}
		switch {
		case ch == '\'' || ch == '"':
			quote = ch
		case ch == '$' && i+1 < len(cmd) && (cmd[i+1] == '(' || cmd[i+1] == '{'):
			inCmdSub = len(fields) == 0 && tok.Len() == 0
			i++
			endCommand()

		// Inspect the heredoc's own pipeline before skipping a quoted body:
		// a quoted heredoc piped or fed into an interpreter still executes.
		case ch == '<' && i+1 < len(cmd) && cmd[i+1] == '<' && (i+2 >= len(cmd) || cmd[i+2] != '<'):
			endToken()
			delim, quoted, after := readHeredocDelimiter(cmd, i+2)
			nl := strings.IndexByte(cmd[after:], '\n')
			if !quoted || nl < 0 || inCmdSub {
				i = after - 1
				continue
			}
			rest := cmd[after : after+nl]
			mode := heredocExecMode(fields, rest)
			if mode == 1 {
				i = after - 1
				continue
			}
			endCommand()
			out = append(out, splitCLICommands(rest)...)
			next := skipHeredocBody(cmd, after, delim)
			if mode == 2 {
				for _, m := range reCLIScriptString.FindAllStringSubmatch(cmd[after+nl+1:next], -1) {
					if s := m[1] + m[2] + m[3]; s != "" {
						out = append(out, splitCLICommands(s)...)
					}
				}
			}
			i = next - 1
		case strings.IndexByte("|&;\n\r`", ch) >= 0:
			inCmdSub = false
			endCommand()
		case ch == ' ' || ch == '\t':
			endToken()
		default:
			if ch == ')' {
				inCmdSub = false
			}
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

// heredocExecMode reports how the pipeline owning a quoted heredoc handles its
// body: 0 (inert data), 1 (shell interpreter), or 2 (script interpreter).
func heredocExecMode(head []string, rest string) int {
	cut, q := len(rest), byte(0)
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if q != 0 {
			if c == q {
				q = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			q = c
		} else if c == ';' || (c == '|' && i+1 < len(rest) && rest[i+1] == '|') ||
			(c == '&' && !(i > 0 && (rest[i-1] == '>' || rest[i-1] == '<' || rest[i-1] == '|')) && !(i+1 < len(rest) && rest[i+1] == '>')) {
			cut = i
			break
		}
	}
	mode := commandHeredocMode(head)
	for _, stage := range splitCLICommands(rest[:cut]) {
		if m := commandHeredocMode(stage); m > mode {
			mode = m
		}
	}
	return mode
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
			return 1
		case reCLIScriptInterp.MatchString(base):
			return 2
		case cliWrappers[base]:
			wrapped = true
		default:
			return 0
		}
	}
	return 0
}

func cliBaseName(raw string) string {
	tok := strings.Trim(raw, "(){}\"'")
	return strings.TrimSuffix(strings.ToLower(path.Base(strings.ReplaceAll(tok, "\\", "/"))), ".exe")
}

func skipHeredocBody(cmd string, i int, delim string) int {
	if delim == "" {
		return len(cmd)
	}

	nl := strings.IndexByte(cmd[i:], '\n')
	if nl < 0 {
		return len(cmd)
	}
	i += nl + 1
	for i < len(cmd) {
		end := strings.IndexByte(cmd[i:], '\n')
		line := cmd[i:]
		next := len(cmd)
		if end >= 0 {
			line = cmd[i : i+end]
			next = i + end + 1
		}

		if strings.Trim(line, " \t\r") == delim {
			return next
		}
		i = next
	}
	return len(cmd)
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
