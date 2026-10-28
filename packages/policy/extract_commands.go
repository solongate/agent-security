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
	"command": true, "cmd": true, "function": true, "script": true, "shell": true,
}

func NormalizeShellCommand(cmd string) string {
	if cmd == "" {
		return cmd
	}
	vars := map[string]string{}
	var out []string
	for _, part := range reStmtSplit.Split(cmd, -1) {
		if idx := reVarAssign.FindStringSubmatchIndex(part); idx != nil {
			name := part[idx[2]:idx[3]]
			val := ""

			for _, g := range []int{2, 3, 4} {
				if idx[2*g] >= 0 {
					val = part[idx[2*g]:idx[2*g+1]]
					break
				}
			}
			vars[name] = val
			continue
		}
		part = replaceSubmatch(reVarBrace, part, func(g []string) string {
			if v, ok := vars[g[1]]; ok {
				return v
			}
			return "${" + g[1] + "}"
		})
		part = replaceSubmatch(reVarBare, part, func(g []string) string {
			if v, ok := vars[g[1]]; ok {
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

func dequote(t string) string {
	return strings.TrimRight(strings.TrimLeft(t, "\"'`"), "\"'`")
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
		if HTTPPrefix.MatchString(s) {
			add(s)
			continue
		}
		if strings.Contains(s, " ") {
			for _, tok := range reWhitespace.Split(s, -1) {
				if HTTPPrefix.MatchString(tok) {
					add(tok)
				}
			}
		}
	}
	return urls
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
