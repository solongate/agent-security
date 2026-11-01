// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package policy

import (
	"regexp"
	"sort"
	"strings"
)

var (
	HTTPPrefix = regexp.MustCompile(`(?i)^https?://`)
	reFileExt  = regexp.MustCompile(`\.\w+$`)

	reExecTool = regexp.MustCompile(`bash|shell|exec|powershell|cmd|run|eval|^sh$|zsh|dash|terminal|monitor|worktree`)
)

var knownExtensionless = map[string]bool{
	"id_rsa": true, "id_dsa": true, "id_ecdsa": true, "id_ed25519": true,
	"authorized_keys": true, "known_hosts": true, "makefile": true, "dockerfile": true,
}

func IsExecTool(toolName string) bool {
	return reExecTool.MatchString(strings.ToLower(toolName))
}

func SortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func replaceSubmatch(re *regexp.Regexp, s string, fn func(groups []string) string) string {
	var b strings.Builder
	last := 0
	for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
		b.WriteString(s[last:m[0]])
		groups := make([]string, len(m)/2)
		for i := range groups {
			if m[2*i] >= 0 {
				groups[i] = s[m[2*i]:m[2*i+1]]
			}
		}
		b.WriteString(fn(groups))
		last = m[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

func ScanStrings(v interface{}) []string {
	var out []string
	var walk func(interface{})
	walk = func(v interface{}) {
		switch t := v.(type) {
		case string:
			if s := strings.TrimSpace(t); s != "" {
				out = append(out, s)
			}
		case []interface{}:
			for _, item := range t {
				walk(item)
			}
		case map[string]interface{}:
			for _, k := range SortedKeys(t) {
				walk(t[k])
			}
		}
	}
	walk(v)
	return out
}

var contentFields = map[string]bool{
	"content": true, "body": true, "text": true,
	"new_string": true, "old_string": true, "newstring": true, "oldstring": true,
	"replacement": true, "prompt": true, "instructions": true,
	"description": true, "message": true,
}

func ScanTargetStrings(v interface{}) []string {
	var out []string
	var walk func(interface{})
	walk = func(v interface{}) {
		switch t := v.(type) {
		case string:
			if s := strings.TrimSpace(t); s != "" {
				out = append(out, s)
			}
		case []interface{}:
			for _, item := range t {
				walk(item)
			}
		case map[string]interface{}:
			for _, k := range SortedKeys(t) {
				if contentFields[strings.ToLower(k)] {
					continue
				}
				walk(t[k])
			}
		}
	}
	walk(v)
	return out
}

func LooksLikeFilename(s string) bool {
	if strings.HasPrefix(s, ".") {
		return true
	}
	if reFileExt.MatchString(s) {
		return true
	}
	return knownExtensionless[strings.ToLower(s)]
}
