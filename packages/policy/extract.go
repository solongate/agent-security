// SPDX-License-Identifier: Apache-2.0

package policy

// The four extractors the policy input is built from, ported from the Node hook
// so both implementations see the same access targets for the same call.
//
// This is where the care goes. Each one exists because something got through:
// a command built out of quoted fragments, a glob standing in for the real
// filename, a path buried in a nested argument object. The comments name the
// dodge each layer closes, keep them if the code is touched, because none of
// this is guessable from the shape of the function.
//
// One deliberate difference from the Node original: wherever JavaScript walks
// object keys in insertion order, this walks them sorted. Go map iteration is
// randomised, and an extractor whose OUTPUT ORDER changes between runs makes a
// denial reproducible only by luck. Order never changes a decision, the
// generated Rego asks "does any item match" / "do all items match", so sorting
// buys determinism at no behavioural cost.
//
// Split across extract.go (this file: generic string/field scanning),
// extract_commands.go (shell normalisation and the command/filename/URL/path
// extractors) and extract_paths.go (glob and search-root expansion, reading
// referenced scripts).

import (
	"regexp"
	"sort"
	"strings"
)

var (
	HTTPPrefix = regexp.MustCompile(`(?i)^https?://`)
	reFileExt  = regexp.MustCompile(`\.\w+$`)

	// A tool whose call EXECUTES what it is given, rather than reading or
	// writing it. The distinction decides whether a file's contents are inlined
	// and whether body fields count as access targets.
	reExecTool = regexp.MustCompile(`bash|shell|exec|powershell|cmd|run|eval`)
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

// replaceSubmatch is JavaScript's String.replace(regexp, fn), the standard
// library only hands ReplaceAllStringFunc the whole match, and every callsite
// here needs the capture group.
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

// scanStrings collects every non-empty string anywhere in a value, however
// deeply nested. Rules apply to what a call touches, and a path or a URL is as
// dangerous three objects down as it is at the top level.
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

// WHAT A CALL ACTS ON, as opposed to what it says.
//
// ScanStrings walks every string in a tool call, which is what the scanners want: a
// secret can be anywhere, so DLP has to look everywhere. A PATH rule is a different
// question, it is about the file a call touches, and asking it of every string turned
// the TEXT of a file into a path:
//
//	Write { file_path: "notes.md", content: "keys live under the home key folder" }
//
// tripped a rule naming that folder, because the content mentions it. Writing
// documentation, a test, or a config example that merely NAMES a protected path was
// blocked, and the message quoted the whole file as the offending path.
//
// Tamper protection learned this first and says so in its own comment: it reads target
// path fields only, "never the free-form content/body, which would false-positive on any
// file that merely mentions a protected path in its text". Policy path rules mean the
// same thing and now behave the same way.
//
// A DENYLIST OF CONTENT FIELDS, not an allowlist of path fields, and the difference
// matters. An allowlist stops seeing a path that arrives in a field nobody listed, which
// is a hole; this only stops reading the fields that are prose by definition, so an
// unknown field carrying a path is still a path.
//
// `command` is deliberately absent: an exec call keeps its paths there and the caller
// already tokenises it. So are `patch` and `diff`, where Codex keeps the target of a
// file edit.
var contentFields = map[string]bool{
	"content": true, "body": true, "text": true,
	"new_string": true, "old_string": true, "newstring": true, "oldstring": true,
	"replacement": true, "prompt": true, "instructions": true,
	"description": true, "message": true,
}

// ScanTargetStrings is ScanStrings without the fields that hold prose.
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