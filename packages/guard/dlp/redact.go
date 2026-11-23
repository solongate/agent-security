// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package dlp

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/solongate/agent-security/packages/policy"
	"github.com/solongate/agent-security/packages/shared"
)

var (
	dlpTransferCmd = regexp.MustCompile(`\b(curl|wget|scp|rsync|sftp|ftp|nc|netcat)\b`)
	dlpNetcatCmd   = regexp.MustCompile(`\b(nc|netcat)\b`)

	dlpHTTPAnywhere   = regexp.MustCompile(`https?://`)
	dlpUserHostTarget = regexp.MustCompile(`@[\w.-]+:`)
	dlpHostPathTarget = regexp.MustCompile(`\b\S+:\S`)

	dlpEgressFileRes = []*regexp.Regexp{
		regexp.MustCompile(`@([^\s'"|>&]+)`),
		regexp.MustCompile(`(?:-T|--upload-file|--data-binary|--data-raw|--data-urlencode|--data|-d|-F|--form|--post-file|--body-file)[=\s]+@?([^\s'"|>&]+)`),
		regexp.MustCompile(`\bcat\s+([^\s'"|>&]+)`),
		regexp.MustCompile(`<\s*([^\s'"|>&]+)`),
	}

	dlpNotAFileTok = regexp.MustCompile(`^[@{[]`)

	dlpPositionalCmd = regexp.MustCompile(`\b(scp|rsync|sftp)\b`)

	dlpRemoteTarget = regexp.MustCompile(`^[\w.-]*@?[\w.-]+:`)

	dlpReaderCmd = regexp.MustCompile(`\b(cat|less|more|head|tail|bat|nl|od|xxd|hexdump|strings|grep|egrep|fgrep|rg|ag|cut|awk|gawk|sed|tr|sort|uniq|paste|join|comm|column|fold|tac|rev|pr|expand|unexpand|base64|base32|dd|mapfile|readarray)\b`)

	// Non-URL file extensions so bare filenames like localfile.txt are not
	// mistaken for scheme-less DNS hostnames when no path or port is present.
	dlpLocalFileExts = map[string]bool{
		"txt": true, "env": true, "json": true, "yaml": true, "yml": true,
		"toml": true, "log": true, "csv": true, "xml": true,
		"sql": true, "key": true, "pem": true, "crt": true, "p12": true,
		"pfx": true, "pub": true, "go": true, "py": true, "js": true,
		"ts": true, "jsx": true, "tsx": true, "mjs": true, "cjs": true,
		"rb": true, "php": true, "java": true, "c": true, "h": true,
		"cpp": true, "rs": true, "sh": true, "bash": true, "zsh": true,
		"ps1": true, "bat": true, "cmd": true, "bak": true, "old": true,
		"tmp": true, "swp": true, "lock": true, "cfg": true, "conf": true,
		"ini": true, "tar": true, "gz": true, "bz2": true, "xz": true,
		"rar": true, "7z": true, "bin": true, "dat": true,
		"exe": true, "dll": true, "so": true, "dylib": true, "pdf": true,
		"doc": true, "docx": true, "xls": true, "xlsx": true, "png": true,
		"jpg": true, "jpeg": true, "gif": true, "svg": true, "ico": true,
		"html": true, "htm": true, "css": true, "map": true, "out": true,
		"err": true, "example": true, "sample": true, "dist": true,
	}

	dlpCurlOperandFlags = map[string]bool{
		"-T": true, "--upload-file": true,
		"-d": true, "--data": true, "--data-raw": true, "--data-binary": true, "--data-urlencode": true,
		"-F": true, "--form": true, "-o": true, "--output": true,
		"-b": true, "-c": true, "-e": true, "-H": true, "--header": true,
		"-A": true, "-u": true, "--user": true, "-X": true, "--request": true,
	}

	dlpWgetOperandFlags = map[string]bool{
		"--post-file": true, "--body-file": true, "--post-data": true,
		"-O": true, "--output-document": true, "-o": true, "--output-file": true,
		"-a": true, "--append-output": true, "--header": true,
		"-U": true, "--user-agent": true, "--user": true, "--password": true,
		"--http-user": true, "--http-password": true,
		"-i": true, "--input-file": true, "-P": true, "--directory-prefix": true,
	}

	dlpNetcatOperandFlags = map[string]bool{
		"-p": true, "-s": true, "-w": true, "-x": true, "-X": true, "-T": true,
	}

	dlpShellOperandTokens = map[string]bool{
		"cat": true, "<": true, ">": true, ">>": true,
	}
)

func trimShellQuotes(tok string) string {
	for len(tok) >= 2 {
		q := tok[0]
		if (q != '\'' && q != '"' && q != '`') || tok[len(tok)-1] != q {
			break
		}
		tok = tok[1 : len(tok)-1]
	}
	return tok
}

func consumesNextOperand(cmdName, raw string) bool {
	if eq := strings.IndexByte(raw, '='); eq >= 0 {
		return false
	}
	name := raw
	if strings.HasPrefix(name, "--") || !strings.HasPrefix(name, "-") {
		name = strings.ToLower(name)
	}
	if dlpShellOperandTokens[name] {
		return true
	}
	switch cmdName {
	case "curl":
		return dlpCurlOperandFlags[name]
	case "wget":
		return dlpWgetOperandFlags[name]
	case "nc", "netcat":
		return dlpNetcatOperandFlags[name]
	default:
		return dlpCurlOperandFlags[name] || dlpWgetOperandFlags[name]
	}
}

func parseTransferCommand(raw string) string {
	switch strings.ToLower(filepath.Base(trimShellQuotes(raw))) {
	case "curl", "wget", "scp", "rsync", "sftp", "ftp", "nc", "netcat":
		return strings.ToLower(filepath.Base(trimShellQuotes(raw)))
	default:
		return ""
	}
}

func primaryTransferCommand(toks []string) string {
	for _, raw := range toks {
		if cmd := parseTransferCommand(raw); cmd != "" {
			return cmd
		}
	}
	return ""
}

func hasRemoteTarget(c, lc string) bool {
	if dlpHTTPAnywhere.MatchString(lc) || dlpUserHostTarget.MatchString(c) || dlpHostPathTarget.MatchString(c) {
		return true
	}
	toks := strings.Fields(c)
	if len(toks) < 2 {
		return false
	}
	cmdName := primaryTransferCommand(toks)
	positionalOnly := cmdName == "scp" || cmdName == "rsync" || cmdName == "sftp"
	isHTTP := cmdName == "curl" || cmdName == "wget"
	isNetcat := cmdName == "nc" || cmdName == "netcat"

	skipNext := false
	for i, raw := range toks {
		if skipNext {
			skipNext = false
			continue
		}
		rawTok := trimShellQuotes(raw)
		if consumesNextOperand(cmdName, rawTok) {
			skipNext = true
			continue
		}
		if nextCmd := parseTransferCommand(rawTok); nextCmd != "" {
			cmdName = nextCmd
			positionalOnly = cmdName == "scp" || cmdName == "rsync" || cmdName == "sftp"
			isHTTP = cmdName == "curl" || cmdName == "wget"
			isNetcat = cmdName == "nc" || cmdName == "netcat"
		}
		tok := trimShellQuotes(strings.TrimPrefix(rawTok, "--url="))
		if tok == rawTok && strings.HasPrefix(rawTok, "-") {
			continue
		}
		if i == 0 {
			continue
		}
		if isSSHRemoteToken(tok, positionalOnly) {
			return true
		}
		if positionalOnly {
			continue
		}
		if isRemoteURLOrHostToken(tok, isHTTP) {
			return true
		}
		if isNetcat && i+1 < len(toks) && isValidHostLabel(tok) && isValidPort(trimShellQuotes(toks[i+1])) {
			return true
		}
	}
	return false
}

func isSSHRemoteToken(tok string, positionalCmd bool) bool {
	if strings.HasPrefix(tok, "@") || strings.Contains(tok, "=") {
		return false
	}
	if dlpRemoteTarget.MatchString(tok) {
		colon := strings.IndexByte(tok, ':')
		// Avoid mistaking a single-letter Windows drive (e.g. C:\...) for host:.
		return colon > 1 || strings.Contains(tok[:colon], "@")
	}
	if positionalCmd && !strings.ContainsAny(tok, "/\\") {
		if at := strings.IndexByte(tok, '@'); at > 0 && at < len(tok)-1 {
			return isPlausibleRemoteHost(tok[at+1:], false, false, false)
		}
	}
	return false
}

func isRemoteURLOrHostToken(tok string, allowSingleLabelPath bool) bool {
	if tok == "" {
		return false
	}
	if strings.Contains(tok, "://") {
		u, err := url.Parse(tok)
		return err == nil && u.Host != ""
	}
	if strings.HasPrefix(tok, "//") {
		u, err := url.Parse(tok)
		return err == nil && isPlausibleRemoteHost(u.Hostname(), u.Port() != "", u.Path != "", false)
	}
	if strings.HasPrefix(tok, "/") || strings.HasPrefix(tok, "./") || strings.HasPrefix(tok, "../") ||
		strings.HasPrefix(tok, "~/") || strings.HasPrefix(tok, "@") || strings.HasPrefix(tok, "{") ||
		strings.Contains(tok, "\\") {
		return false
	}
	if len(tok) >= 2 && tok[1] == ':' && isASCIIAlpha(tok[0]) {
		return false
	}
	if eq := strings.IndexByte(tok, '='); eq >= 0 {
		slash := strings.IndexByte(tok, '/')
		qmark := strings.IndexByte(tok, '?')
		if (slash < 0 || eq < slash) && (qmark < 0 || eq < qmark) {
			return false
		}
	}
	u, err := url.Parse("//" + tok)
	if err != nil {
		return false
	}
	return isPlausibleRemoteHost(u.Hostname(), u.Port() != "", u.Path != "", allowSingleLabelPath)
}

func isPlausibleRemoteHost(host string, hasPort, hasPath, allowSingleLabelPath bool) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if net.ParseIP(host) != nil || strings.EqualFold(host, "localhost") {
		return true
	}
	if (hasPort || (allowSingleLabelPath && hasPath)) && isValidHostLabel(host) {
		return true
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, lbl := range labels {
		if !isValidHostLabel(lbl) {
			return false
		}
	}
	tld := strings.ToLower(labels[len(labels)-1])
	if !hasPath && !hasPort && dlpLocalFileExts[tld] {
		return false
	}
	return (len(tld) >= 2 && isAllASCIIAlpha(tld)) || (strings.HasPrefix(tld, "xn--") && len(tld) > 4)
}

func isValidHostLabel(lbl string) bool {
	if len(lbl) == 0 || len(lbl) > 63 || lbl[0] == '-' || lbl[len(lbl)-1] == '-' {
		return false
	}
	for i := 0; i < len(lbl); i++ {
		c := lbl[i]
		if !isASCIIAlpha(c) && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func isValidPort(tok string) bool {
	n, err := strconv.Atoi(tok)
	return err == nil && n >= 1 && n <= 65535
}

func isASCIIAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isAllASCIIAlpha(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isASCIIAlpha(s[i]) {
			return false
		}
	}
	return len(s) > 0
}

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

		if !hasRemoteTarget(c, lc) {
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
	enabled := enabledPatternSet(cfg)

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

	rewrite := map[string]string{}
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
		rewrite[k] = r
	}

	if cmd, _ := args["command"].(string); cmd != "" && dlpReaderCmd.MatchString(strings.ToLower(cmd)) {
		newCmd, changed, block := redactReaderCommand(cmd, dlp, base)
		if block {
			return &redactPlan{Block: true}
		}
		if changed {
			rewrite["command"] = newCmd
		}
	}

	if len(rewrite) > 0 {
		return &redactPlan{Rewrite: rewrite}
	}
	return nil
}

// redactReaderCommand rewrites every secret-bearing path token inside a shell
// reader command in a single delimiter-preserving pass so replacing one path
// cannot mutate a subsequent token or an earlier redacted path.
func redactReaderCommand(cmd string, dlp *shared.DLPConfig, base string) (string, bool, bool) {
	seps := policy.GlobTokenSplit.FindAllStringIndex(cmd, -1)
	var b strings.Builder
	b.Grow(len(cmd))

	changed := false
	cached := map[string]string{}
	rewriteTok := func(tok string) (string, bool) {
		if tok == "" || strings.HasPrefix(tok, "-") || !strings.ContainsAny(tok, "./") {
			return tok, false
		}
		if policy.GlobChars.MatchString(tok) {
			for _, f := range dlpExpandGlob(dlpAbsPath(tok, base)) {
				if rg := dlpRedactCopy(f, dlp); rg != redactSkip && rg != redactClean {
					return "", true
				}
			}
			return tok, false
		}
		if r, ok := cached[tok]; ok {
			if r == redactSkip || r == redactClean {
				return tok, false
			}
			changed = true
			return r, false
		}
		r := dlpRedactCopy(dlpAbsPath(tok, base), dlp)
		cached[tok] = r
		if r == redactSkip || r == redactClean {
			return tok, false
		}
		if r == redactFailed {
			return "", true
		}
		changed = true
		return r, false
	}

	last := 0
	for _, sep := range seps {
		rep, block := rewriteTok(cmd[last:sep[0]])
		if block {
			return "", false, true
		}
		b.WriteString(rep)
		b.WriteString(cmd[sep[0]:sep[1]])
		last = sep[1]
	}
	rep, block := rewriteTok(cmd[last:])
	if block {
		return "", false, true
	}
	b.WriteString(rep)

	if !changed {
		return cmd, false, false
	}
	return b.String(), true, false
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

	dir := redactedDir()
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

// redactedTTL is how long a redacted copy outlives the call that made it. The
// rewritten call reads the copy as soon as the client runs it, but a client can
// hold that call behind a permission prompt first, so the margin is a day, not
// seconds.
const redactedTTL = 24 * time.Hour

func redactedDir() string {
	return filepath.Join(shared.SGDir(), ".redacted")
}

// SweepRedacted removes redacted copies older than redactedTTL. The directory
// is one per machine and every distinct file that ever tripped redact mode adds
// a copy to it, so without this it grows for the life of the machine and keeps
// whatever the redaction left of each file long after the read that needed it.
// A copy that is read again is rewritten in place, which renews its age.
func SweepRedacted() {
	dir := redactedDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-redactedTTL)
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
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
