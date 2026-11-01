// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package dlp

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/solongate/agent-security/packages/policy"
	"github.com/solongate/agent-security/packages/shared"
)

var (
	dlpTransferCmd = regexp.MustCompile(`\b(curl|wget|scp|rsync|sftp|ftp|nc|netcat)\b`)

	dlpHTTPAnywhere   = regexp.MustCompile(`https?://`)
	dlpUserHostTarget = regexp.MustCompile(`@[\w.-]+:`)
	dlpHostPathTarget = regexp.MustCompile(`\b\S+:\S`)

	dlpEgressFileRes = []*regexp.Regexp{
		regexp.MustCompile(`@([^\s'"|>&]+)`),
		regexp.MustCompile(`(?:-T|--upload-file|--data-binary|--data-raw|--data|-d|-F|--form)[=\s]+@?([^\s'"|>&]+)`),
		regexp.MustCompile(`\bcat\s+([^\s'"|>&]+)`),
		regexp.MustCompile(`<\s*([^\s'"|>&]+)`),
	}

	dlpNotAFileTok = regexp.MustCompile(`^[@{[]`)

	dlpPositionalCmd = regexp.MustCompile(`\b(scp|rsync|sftp)\b`)

	dlpRemoteTarget = regexp.MustCompile(`^[\w.-]*@?[\w.-]+:`)

	dlpReaderCmd = regexp.MustCompile(`\b(cat|less|more|head|tail|bat|nl|od|xxd|hexdump|strings|grep|egrep|fgrep|rg|ag|cut|awk|gawk|sed|tr|sort|uniq|paste|join|comm|column|fold|tac|rev|pr|expand|unexpand|base64|base32|dd|mapfile|readarray)\b`)
)

func EgressSecretCheck(args map[string]interface{}, sec *shared.Security, cwd string) (reason string) {

	defer func() {
		if recover() != nil {
			reason = ""
		}
	}()
	if sec == nil || sec.DLPBlock == nil {
		return ""
	}
	dlp := sec.DLPBlock

	base := cwd
	if base == "" {
		if wd, err := os.Getwd(); err == nil {
			base = wd
		}
	}

	for _, c := range policy.ExtractPipelines(args) {
		lc := strings.ToLower(c)
		if !dlpTransferCmd.MatchString(lc) {
			continue
		}

		if !dlpHTTPAnywhere.MatchString(lc) && !dlpUserHostTarget.MatchString(c) && !dlpHostPathTarget.MatchString(c) {
			continue
		}

		var files []string
		seen := map[string]bool{}
		add := func(f string) {
			if f == "" || f == "-" || policy.HTTPPrefix.MatchString(f) || dlpNotAFileTok.MatchString(f) {
				return
			}
			if !seen[f] {
				seen[f] = true
				files = append(files, f)
			}
		}
		for _, re := range dlpEgressFileRes {
			for _, m := range re.FindAllStringSubmatch(c, -1) {
				add(m[1])
			}
		}

		if dlpPositionalCmd.MatchString(lc) {
			toks := strings.Fields(c)
			if len(toks) > 1 {
				for _, tok := range toks[1:] {
					if strings.HasPrefix(tok, "-") || dlpRemoteTarget.MatchString(tok) {
						continue
					}
					add(strings.TrimPrefix(tok, "@"))
				}
			}
		}
		for _, f := range files {
			if strings.HasPrefix(f, "~") {
				home, err := os.UserHomeDir()
				if err != nil {
					continue
				}
				f = home + f[1:]
			}
			abs := f
			if !filepath.IsAbs(abs) {
				abs = filepath.Join(base, f)
			}

			if st, err := os.Stat(abs); err != nil || !st.Mode().IsRegular() || st.Size() > dlpMaxFileBytes {
				continue
			}
			content, err := os.ReadFile(abs)
			if err != nil || len(content) == 0 {
				continue
			}
			if hit := shared.DLPScanViews(string(content), dlp); hit != "" {
				return `DLP: outbound transfer of "` + f + `" is blocked - it contains a ` + hit + ` (egress protection)`
			}
		}
	}
	return ""
}

type redactSpan struct {
	text     string
	redacted bool
	label    string
}

func RedactText(text string, cfg *shared.DLPConfig) string {
	if cfg == nil || text == "" {
		return text
	}
	enabled := make(map[string]bool, len(cfg.Patterns))
	for _, n := range cfg.Patterns {
		enabled[n] = true
	}

	spans := []redactSpan{{text: text}}

	applyPattern := func(name string, re *regexp.Regexp) {
		var next []redactSpan
		for _, s := range spans {
			if s.redacted || s.text == "" {
				next = append(next, s)
				continue
			}

			locs := re.FindAllStringIndex(s.text, -1)
			if len(locs) == 0 {
				next = append(next, s)
				continue
			}

			last := 0
			for _, loc := range locs {
				start, end := loc[0], loc[1]
				if start > last {
					next = append(next, redactSpan{text: s.text[last:start]})
				}
				next = append(next, redactSpan{
					redacted: true,
					label:    "[REDACTED:" + name + "]",
				})
				last = end
			}
			if last < len(s.text) {
				next = append(next, redactSpan{text: s.text[last:]})
			}
		}
		spans = next
	}

	for i := 0; i < shared.DLPPatternCount(); i++ {
		name, re := shared.DLPPatternAt(i)
		if !enabled[name] {
			continue
		}
		applyPattern(name, re)
	}
	for _, c := range cfg.Custom {
		re, err := shared.GlobToRegexp(c.Re)
		if err != nil {
			continue
		}
		name := c.Name
		if name == "" {
			name = "custom"
		}
		applyPattern(name, re)
	}

	var b strings.Builder
	for _, s := range spans {
		if s.redacted {
			b.WriteString(s.label)
		} else {
			b.WriteString(dlpStashRe.ReplaceAllString(s.text, ""))
		}
	}
	return b.String()
}

var dlpStashRe = regexp.MustCompile("\x00\\d+\x00")

type redactPlan struct {
	Block   bool
	Rewrite map[string]string
}

const (
	redactSkip   = "SKIP"
	redactClean  = "CLEAN"
	redactFailed = "FAILED"
)

const dlpMaxFileBytes = 1048576

func RedactReadPlan(toolName string, args map[string]interface{}, dlp *shared.DLPConfig, cwd string) (plan *redactPlan) {

	defer func() {
		if recover() != nil {
			plan = &redactPlan{Block: true}
		}
	}()
	if dlp == nil || args == nil {
		return nil
	}
	base := cwd
	if base == "" {
		if wd, err := os.Getwd(); err == nil {
			base = wd
		}
	}

	for _, k := range policy.SortedKeys(args) {
		if k == "command" {
			continue
		}
		v, ok := args[k].(string)
		if !ok || v == "" || !strings.ContainsAny(v, "./") {
			continue
		}
		r := dlpRedactCopy(dlpAbsPath(v, base), dlp)
		if r == redactSkip || r == redactClean {
			continue
		}
		if r == redactFailed {
			return &redactPlan{Block: true}
		}
		return &redactPlan{Rewrite: map[string]string{k: r}}
	}

	cmd, _ := args["command"].(string)
	if cmd == "" || !dlpReaderCmd.MatchString(strings.ToLower(cmd)) {
		return nil
	}
	newCmd, changed := cmd, false

	for _, tok := range policy.GlobTokenSplit.Split(cmd, -1) {
		if tok == "" || strings.HasPrefix(tok, "-") || !strings.ContainsAny(tok, "./") {
			continue
		}

		if policy.GlobChars.MatchString(tok) {
			for _, f := range dlpExpandGlob(dlpAbsPath(tok, base)) {
				if rg := dlpRedactCopy(f, dlp); rg != redactSkip && rg != redactClean {
					return &redactPlan{Block: true}
				}
			}
			continue
		}
		r := dlpRedactCopy(dlpAbsPath(tok, base), dlp)
		if r == redactSkip || r == redactClean {
			continue
		}
		if r == redactFailed {
			return &redactPlan{Block: true}
		}
		newCmd = strings.ReplaceAll(newCmd, tok, r)
		changed = true
	}
	if changed {
		return &redactPlan{Rewrite: map[string]string{"command": newCmd}}
	}
	return nil
}

func dlpRedactCopy(abs string, dlp *shared.DLPConfig) string {
	if abs == "" {
		return redactSkip
	}
	st, err := os.Stat(abs)
	if err != nil || !st.Mode().IsRegular() || st.Size() > dlpMaxFileBytes {
		return redactSkip
	}
	content, err := os.ReadFile(abs)
	if err != nil {
		return redactSkip
	}
	if shared.DLPScanViews(string(content), dlp) == "" {
		return redactClean
	}

	dir := filepath.Join(shared.SGDir(), ".redacted")
	if err := os.MkdirAll(dir, shared.DirMode); err != nil {
		return redactFailed
	}
	sum := sha256.Sum256([]byte(abs))

	name := filepath.Base(abs)
	if name == "" || name == "." || name == string(filepath.Separator) {
		name = "f"
	}
	tmp := filepath.Join(dir, hex.EncodeToString(sum[:])[:24]+"-"+name)

	if err := os.WriteFile(tmp, []byte(RedactText(string(content), dlp)), 0o600); err != nil {
		return redactFailed
	}
	return tmp
}

func dlpExpandGlob(absGlob string) []string {
	if absGlob == "" {
		return nil
	}

	abs := filepath.Clean(absGlob)
	dir := filepath.Dir(abs)
	b := filepath.Base(abs)
	if !policy.GlobChars.MatchString(b) {
		return []string{absGlob}
	}

	pattern := policy.GlobStarRun.ReplaceAllString(b, "*")
	pattern = policy.GlobEscape.ReplaceAllString(pattern, `\${0}`)
	pattern = strings.ReplaceAll(pattern, "*", "[^/]*")
	pattern = strings.ReplaceAll(pattern, "?", "[^/]")
	re, err := regexp.Compile("^" + pattern + "$")
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if re.MatchString(e.Name()) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

func dlpAbsPath(f, base string) string {
	x := f
	if strings.HasPrefix(x, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		x = home + x[1:]
	}
	if filepath.IsAbs(x) {
		return x
	}
	return filepath.Join(base, x)
}