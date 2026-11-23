// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package policy

import (
	"regexp"
	"strings"
)

var (
	reStmtSplit = regexp.MustCompile(`\s*(?:;|&&|\|\|)\s*`)

	reCmdSplit = regexp.MustCompile(`\s*(?:&&|\|\||;|\|)\s*`)

	rePipelineSplit = regexp.MustCompile(`\s*(?:&&|\|\||;)\s*`)

	reVarAssign = regexp.MustCompile(`^(\w+)=(?:"([^"]*)"|'([^']*)'|([^\s;&|]*))\s*$`)
	reVarBrace  = regexp.MustCompile(`\$\{(\w+)\}`)
	reVarBare   = regexp.MustCompile(`\$(\w+)`)
	reDQuoted   = regexp.MustCompile(`"([^"]*)"`)
	reSQuoted   = regexp.MustCompile(`'([^']*)'`)

	rePathTokSplit = regexp.MustCompile("[\\s;|&><()`'\"]+")

	reWhitespace = regexp.MustCompile(`\s+`)
	reHasSpace   = regexp.MustCompile(`\s`)
)

var commandFields = map[string]bool{
	"command": true, "cmd": true, "function": true, "script": true, "shell": true, "code": true,
}

type heredocSpec struct {
	delimiter string
	stripTabs bool
}

type shellScopeRange struct {
	start int
	end   int
	id    int
}

type markedShellCommand struct {
	text   string
	scopes []shellScopeRange
}

type shellStatement struct {
	text    string
	scopeID int
}

func NormalizeShellCommand(cmd string) string {
	if cmd == "" {
		return cmd
	}
	// Preserve multi-line arguments while exposing actual shell statement boundaries.
	marked := markStatementNewlines(cmd)
	vars := map[string]string{}
	var bodyVars map[string]string
	currentScope := 0
	var out []string
	for _, statement := range splitShellStatements(marked) {
		part := statement.text
		if strings.TrimSpace(part) == "" {
			continue
		}
		activeVars := vars
		if statement.scopeID != 0 {
			if statement.scopeID != currentScope {
				bodyVars = cloneStringMap(vars)
				currentScope = statement.scopeID
			}
			activeVars = bodyVars
		} else {
			currentScope = 0
			bodyVars = nil
		}
		if idx := reVarAssign.FindStringSubmatchIndex(part); idx != nil {
			name := part[idx[2]:idx[3]]
			val := ""

			for _, g := range []int{2, 3, 4} {
				if idx[2*g] >= 0 {
					val = part[idx[2*g]:idx[2*g+1]]
					break
				}
			}
			activeVars[name] = val
			continue
		}
		part = replaceSubmatch(reVarBrace, part, func(g []string) string {
			if v, ok := activeVars[g[1]]; ok {
				return v
			}
			return "${" + g[1] + "}"
		})
		part = replaceSubmatch(reVarBare, part, func(g []string) string {
			if v, ok := activeVars[g[1]]; ok {
				return v
			}
			return "$" + g[1]
		})
		part = reDQuoted.ReplaceAllString(part, "${1}")
		part = reSQuoted.ReplaceAllString(part, "${1}")
		out = append(out, part)
	}
	return strings.Join(out, "; ")
}

func cloneStringMap(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func splitShellStatements(marked markedShellCommand) []shellStatement {
	var statements []shellStatement
	start := 0
	for _, separator := range reStmtSplit.FindAllStringIndex(marked.text, -1) {
		statements = append(statements, shellStatement{
			text:    marked.text[start:separator[0]],
			scopeID: shellScopeAt(marked, start, separator[0]),
		})
		start = separator[1]
	}
	statements = append(statements, shellStatement{
		text:    marked.text[start:],
		scopeID: shellScopeAt(marked, start, len(marked.text)),
	})
	return statements
}

func shellScopeAt(marked markedShellCommand, start, end int) int {
	for start < end && (marked.text[start] == ' ' || marked.text[start] >= '\t' && marked.text[start] <= '\r') {
		start++
	}
	for _, scope := range marked.scopes {
		if start >= scope.start && start < scope.end {
			return scope.id
		}
	}
	return 0
}

func markStatementNewlines(cmd string) markedShellCommand {
	var b strings.Builder
	b.Grow(len(cmd))
	inSingle, inDouble, inComment := false, false, false
	arithmeticDepth := 0
	var heredocs []heredocSpec
	var scopes []shellScopeRange
	nextScopeID := 1
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if inComment {
			if c == '\n' {
				b.WriteByte(';')
				inComment = false
				consumePendingHeredoc(cmd, &b, &i, &heredocs, &scopes, &nextScopeID)
				continue
			}
			b.WriteByte(c)
			continue
		}
		if c == '\\' && !inSingle && i+1 < len(cmd) {
			if cmd[i+1] == '\n' {
				i++
				continue
			}
			if cmd[i+1] == '\r' && i+2 < len(cmd) && cmd[i+2] == '\n' {
				i += 2
				continue
			}
			b.WriteByte(c)
			i++
			b.WriteByte(cmd[i])
			continue
		}
		if !inSingle && !inDouble && i+1 < len(cmd) {
			if c == '(' && cmd[i+1] == '(' {
				arithmeticDepth++
				b.WriteString("((")
				i++
				continue
			}
			if c == ')' && cmd[i+1] == ')' && arithmeticDepth > 0 {
				arithmeticDepth--
				b.WriteString("))")
				i++
				continue
			}
		}
		if c == '<' && arithmeticDepth == 0 && !inSingle && !inDouble && i+1 < len(cmd) && cmd[i+1] == '<' &&
			(i == 0 || cmd[i-1] != '<') && (i+2 >= len(cmd) || cmd[i+2] != '<') {
			start := i + 2
			stripTabs := start < len(cmd) && cmd[start] == '-'
			if stripTabs {
				start++
			}
			if delimiter, quoted := readHeredocDelimiter(cmd, start); delimiter != "" || quoted {
				heredocs = append(heredocs, heredocSpec{delimiter: delimiter, stripTabs: stripTabs})
			}
		}
		if c == '#' && !inSingle && !inDouble && (i == 0 || isShellWordBoundary(cmd[i-1])) {
			// Separate comments so an assignment before one remains independently resolvable.
			b.WriteByte(';')
			inComment = true
			b.WriteByte(c)
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
		} else if c == '"' && !inSingle {
			inDouble = !inDouble
		}
		if c == '\n' && !inSingle && !inDouble {
			b.WriteByte(';')
			consumePendingHeredoc(cmd, &b, &i, &heredocs, &scopes, &nextScopeID)
			continue
		}
		b.WriteByte(c)
	}
	return markedShellCommand{text: b.String(), scopes: scopes}
}

func consumePendingHeredoc(cmd string, b *strings.Builder, newlineIndex *int, heredocs *[]heredocSpec, scopes *[]shellScopeRange, nextScopeID *int) {
	for len(*heredocs) != 0 {
		scopeStart := b.Len()
		*newlineIndex = copyHeredocBody(cmd, b, *newlineIndex+1, (*heredocs)[0])
		*heredocs = (*heredocs)[1:]
		if scopeStart != b.Len() {
			*scopes = append(*scopes, shellScopeRange{start: scopeStart, end: b.Len(), id: *nextScopeID})
			(*nextScopeID)++
		}
	}
}

func copyHeredocBody(cmd string, b *strings.Builder, start int, h heredocSpec) int {
	for start < len(cmd) {
		var logicalLine strings.Builder
		lineEnd := start
		for {
			lineEnd = start + strings.IndexByte(cmd[start:], '\n')
			if lineEnd < start {
				lineEnd = len(cmd)
			}
			contentEnd := lineEnd
			if contentEnd > start && cmd[contentEnd-1] == '\r' {
				contentEnd--
			}
			trailing := contentEnd - start - len(strings.TrimRight(cmd[start:contentEnd], `\`))
			if lineEnd < len(cmd) && trailing%2 == 1 {
				// A heredoc body may be fed to a shell, which joins continuations itself, so conservatively join them here.
				logicalLine.WriteString(cmd[start : contentEnd-1])
				start = lineEnd + 1
				continue
			}
			logicalLine.WriteString(cmd[start:lineEnd])
			break
		}
		line := strings.TrimSuffix(logicalLine.String(), "\r")
		if h.stripTabs {
			line = strings.TrimLeft(line, "\t")
		}
		if line == h.delimiter {
			// Keep the terminator visible to policy checks, but consume it here so
			// quote and comment characters in the delimiter cannot affect parsing.
			b.WriteString(logicalLine.String())
			b.WriteByte(';')
			return lineEnd
		}
		// Heredoc data stays visible without affecting shell quote state.
		b.WriteString(logicalLine.String())
		if lineEnd == len(cmd) {
			return len(cmd)
		}
		b.WriteByte(';')
		start = lineEnd + 1
	}
	return len(cmd)
}

func readHeredocDelimiter(cmd string, start int) (string, bool) {
	for start < len(cmd) && (cmd[start] == ' ' || cmd[start] == '\t') {
		start++
	}
	var b strings.Builder
	var quote byte
	quoted := false
	for i := start; i < len(cmd); i++ {
		c := cmd[i]
		if quote == 0 && (c == ' ' || c >= '\t' && c <= '\r' || strings.ContainsRune(";&|()<>", rune(c))) {
			break
		}
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			} else {
				b.WriteByte(c)
			}
			continue
		}
		if quote == '"' {
			if c == '"' {
				quote = 0
				continue
			}
			if c == '\\' && i+1 < len(cmd) {
				next := cmd[i+1]
				if strings.ContainsRune("$`\"\\", rune(next)) {
					i++
					b.WriteByte(next)
					continue
				}
				if next == '\n' {
					i++
					continue
				}
			}
			b.WriteByte(c)
			continue
		}
		if c == '\\' {
			if i+1 < len(cmd) {
				i++
				b.WriteByte(cmd[i])
			}
			continue
		}
		if c == '\'' || c == '"' {
			quoted = true
			quote = c
			continue
		}
		b.WriteByte(c)
	}
	return b.String(), quoted
}

func isShellWordBoundary(c byte) bool {
	return c == ' ' || c >= '\t' && c <= '\r' || c == ';' || c == '&' || c == '|' || c == '(' || c == ')'
}

func NormalizeArgs(args map[string]interface{}) map[string]interface{} {
	if args == nil {
		return nil
	}
	copied := make(map[string]interface{}, len(args))
	for k, v := range args {
		if s, ok := v.(string); ok && commandFields[strings.ToLower(k)] {
			copied[k] = NormalizeShellCommand(s)
			continue
		}
		copied[k] = v
	}
	return copied
}

// dequote strips matched quote pairs from both ends of t. A trailing quote is only taken
// when it is the same character as the leading one, so a token like 'notes.txt" keeps its
// quotes instead of losing both ends to independent trims (#346).
func dequote(t string) string {
	for len(t) >= 2 {
		q := t[0]
		if (q != '"' && q != '\'' && q != '`') || t[len(t)-1] != q {
			break
		}
		t = t[1 : len(t)-1]
	}
	return t
}

func ExtractFilenames(args map[string]interface{}) []string {
	normalized := NormalizeArgs(args)
	var names []string
	seen := map[string]bool{}
	add := func(n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	for _, s := range ScanTargetStrings(normalized) {
		if HTTPPrefix.MatchString(s) {
			continue
		}
		var tokens []string
		if strings.Contains(s, " ") {
			tokens = reWhitespace.Split(s, -1)
		} else {
			tokens = []string{s}
		}
		single := len(tokens) == 1
		for _, tok := range tokens {
			tok = dequote(tok)
			if tok == "" || HTTPPrefix.MatchString(tok) {
				continue
			}
			if strings.ContainsAny(tok, "/\\") {
				slashed := strings.ReplaceAll(tok, "\\", "/")
				parts := strings.Split(slashed, "/")
				b := dequote(parts[len(parts)-1])
				if b != "" && (single || LooksLikeFilename(b)) {
					add(b)
				}
			} else if LooksLikeFilename(tok) {
				add(tok)
			}
		}
	}
	return names
}

func ExtractURLs(args map[string]interface{}) []string {
	var urls []string
	seen := map[string]bool{}
	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	for _, s := range ScanStrings(args) {
		s = dequote(s)
		if HTTPPrefix.MatchString(s) {
			add(s)
			continue
		}
		for _, tok := range reWhitespace.Split(s, -1) {
			for _, piece := range splitShellOperatorToken(tok) {
				piece = dequote(piece)
				if HTTPPrefix.MatchString(piece) {
					add(piece)
				}
			}
		}
	}
	return urls
}

func splitShellOperatorToken(token string) []string {
	var pieces []string
	start := 0
	inSingle, inDouble, escaped := false, false, false
	for i := 0; i < len(token); i++ {
		c := token[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && !inSingle {
			escaped = true
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if !inSingle && !inDouble && strings.ContainsRune(";&|()<>", rune(c)) {
			if start < i {
				pieces = append(pieces, token[start:i])
			}
			start = i + 1
		}
	}
	if start < len(token) {
		pieces = append(pieces, token[start:])
	}
	return pieces
}

func ExtractPipelines(args map[string]interface{}) []string {
	normalized := NormalizeArgs(args)
	out := []string{}
	for _, k := range SortedKeys(normalized) {
		if !commandFields[strings.ToLower(k)] {
			continue
		}
		v, ok := normalized[k].(string)
		if !ok {
			continue
		}
		for _, part := range rePipelineSplit.Split(v, -1) {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				out = append(out, trimmed)
			}
		}
	}
	return out
}

func ExtractCommands(args map[string]interface{}) []string {
	normalized := NormalizeArgs(args)
	cmds := []string{}
	for _, k := range SortedKeys(normalized) {
		if !commandFields[strings.ToLower(k)] {
			continue
		}
		v, ok := normalized[k].(string)
		if !ok {
			continue
		}
		for _, part := range reCmdSplit.Split(v, -1) {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				cmds = append(cmds, trimmed)
			}
		}
	}
	return cmds
}

func ExtractPaths(args map[string]interface{}, isExec bool) []string {
	paths := []string{}
	add := func(t string) {
		if t == "" || HTTPPrefix.MatchString(t) {
			return
		}
		if strings.ContainsAny(t, "/\\") || strings.HasPrefix(t, ".") {
			paths = append(paths, strings.ReplaceAll(t, "\\", "/"))
		}
	}
	for _, s := range ScanTargetStrings(args) {
		if HTTPPrefix.MatchString(s) {
			continue
		}
		if isExec && reHasSpace.MatchString(s) {
			for _, tok := range rePathTokSplit.Split(s, -1) {
				add(tok)
			}
			continue
		}
		add(s)
	}
	return paths
}
