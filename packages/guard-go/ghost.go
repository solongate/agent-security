package main

// The ghost layer: paths the agent must not be able to see, read, write or
// count. Ported from the Node hook (guard.mjs) function for function so the two
// can still be diffed side by side.
//
// There are two enforcement points and they are NOT redundant:
//
//   - ghostCheck runs on the fast path, before the policy is resolved, and is
//     the only ghost enforcement possible on a client that never runs a
//     PostToolUse hook (Antigravity). It denies a call that names a hidden path
//     and additionally blocks aggregate SIZE commands (du/df), whose directory
//     totals leak a hidden file's existence and size without ever naming it.
//   - ghostBlock runs on the slow path and seals direct access — read AND write
//     — for the tools that carry an explicit path argument, plus any exec tool
//     whose command line contains a token naming a ghost.
//
// Neither of them blocks a plain LISTING of a parent directory: no token equals
// the ghost, so nothing to deny. That case falls through to ghostListingRewrite,
// which rewrites the command to filter the hidden entries out of its own output.
// The rewrite path matters as much as the block path — it is what makes the file
// invisible rather than merely inaccessible.
//
// Every deny reason is a bare OS-style "X: No such file or directory". Never a
// branded or policy-shaped message: the point is that the path looks like it
// simply is not there.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/codeyevsky/solongate/sgpolicy"
	"github.com/codeyevsky/solongate/sgshared"
)

// ghostVerdict is what one pass over a tool call yields.
//
// Deny and AuditReason differ on purpose. Deny is what the CLIENT is told, and
// it must stay a bare not-found string. AuditReason is what the audit log
// records, and for the slow-path block the Node hook deliberately writes the
// branded "ghost path (hidden from agent)" there instead — the operator needs to
// know why the call was refused even though the agent must not.
type ghostVerdict struct {
	Deny        string
	AuditReason string
	Rewrite     string
}

// ── ECMAScript whitespace ────────────────────────────────────────────────────
//
// JavaScript's \s is Unicode-aware; Go's is [\t\n\f\r ] and nothing else. Every
// place the original splits or trims on whitespace here can change a decision —
// a `du` command separated by a non-breaking space would tokenise differently
// and stop blocking, a pattern carrying a BOM would silently never match — so
// the exact ECMAScript set is spelled out rather than approximated.
//
// Note U+0085 is absent: it is category Cc, not Zs, so JS does NOT treat it as
// whitespace, while Go's strings.TrimSpace does. Using TrimSpace here would trim
// a character the original keeps, which is the opposite error but still an
// error.
const jsWSClass = `\t\n\v\f\r \x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{feff}\x{3000}`

// The same set as a cutset for trimming. Written as code points, not as literal
// characters: most of them are invisible and would not survive a copy-paste of
// this file, and a silently dropped one is a pattern that silently stops
// matching.
var jsWSCutset = func() string {
	var b strings.Builder
	for _, r := range []rune{'\t', '\n', '\v', '\f', '\r', ' ', 0x00a0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0xfeff, 0x3000} {
		b.WriteRune(r)
	}
	for r := rune(0x2000); r <= 0x200a; r++ {
		b.WriteRune(r)
	}
	return b.String()
}()

// ghostTrim is String.prototype.trim(), not strings.TrimSpace. See jsWSClass.
func ghostTrim(s string) string { return strings.Trim(s, jsWSCutset) }

// ghostUTF16Len is String.prototype.length — UTF-16 code units, not bytes and
// not runes. It only feeds the `> 2` minimum-length guard below, but that guard
// is what stops a two-character pattern from matching half the command line, so
// counting bytes there would loosen it for every non-ASCII pattern.
func ghostUTF16Len(s string) int { return len(utf16.Encode([]rune(s))) }

var (
	reGhostWSPlus = regexp.MustCompile(`[` + jsWSClass + `]+`)

	// du/df are matched as whole words so a path containing "du" is not one.
	reGhostDuDf = regexp.MustCompile(`\b(du|df)\b`)

	// A command carrying any of these is composed shell, and rewriting it by
	// appending a pipe would attach the filter to the wrong stage.
	reGhostComposed = regexp.MustCompile("[|>;&\n`]")

	// Only bare listing commands are rewritten. Richer output formats are left to
	// the PostToolUse filter on the clients that honour it.
	reGhostListingCmd = regexp.MustCompile(`^[` + jsWSClass + `]*(ls|ll|dir|find|tree|exa|lsd|fd|grep|egrep|fgrep|rg)([` + jsWSClass + `]|$)`)

	reGhostLeadRedirect = regexp.MustCompile(`^\d*>>?`)
	reGhostLeadShellOp  = regexp.MustCompile(`^[<>|;&(]+`)
	reGhostTailShellOp  = regexp.MustCompile(`[);&|]+$`)
	reGhostLeadQuote    = regexp.MustCompile(`^['"]+`)
	reGhostTailQuote    = regexp.MustCompile(`['"]+$`)
	reGhostTrailSlashes = regexp.MustCompile(`/+$`)
	reGhostWild         = regexp.MustCompile(`[*?]`)
)

// Compiling a glob is not free and the du/df branch tests every entry of a
// directory against every pattern, which is the one place this becomes hot: a
// 2000-entry directory times four patterns is 8000 compiles per call without
// this. A nil VALUE is a remembered failure — the original returns null for a
// glob that will not compile and skips it, so a bad pattern must not be retried.
var ghostReCache = map[string]*regexp.Regexp{}

func ghostCompile(pattern string) *regexp.Regexp {
	if re, seen := ghostReCache[pattern]; seen {
		return re
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		re = nil
	}
	ghostReCache[pattern] = re
	return re
}

// ── Glob translation ─────────────────────────────────────────────────────────

// ghostGlobToRe translates a hidden-path glob into an anchored regexp.
//
// `**` crosses directory separators, a single `*` and `?` do not. Everything in
// the escape set is punctuation, so the generated pattern only ever contains
// `.*`, `[^/]*`, `[^/]`, escaped punctuation and literal text — none of which
// RE2 rejects, and no lookaround or backreference is involved. A glob that still
// will not compile yields nil and is skipped, exactly as the original's
// try/catch does.
func ghostGlobToRe(glob string) *regexp.Regexp {
	var re strings.Builder
	runes := []rune(glob)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case c == '*':
			if i+1 < len(runes) && runes[i+1] == '*' {
				re.WriteString(".*")
				i++
			} else {
				re.WriteString("[^/]*")
			}
		case c == '?':
			re.WriteString("[^/]")
		case strings.ContainsRune(`\^$.|+()[]{}`, c):
			re.WriteByte('\\')
			re.WriteRune(c)
		default:
			re.WriteRune(c)
		}
	}
	return ghostCompile("^" + re.String() + "$")
}

// ghostGlobToRegExp is the slow path's copy of the same translation.
//
// It is byte-for-byte the same logic as ghostGlobToRe in the Node hook — two
// names for one function, the fast path and the slow path each having grown
// their own. Both are kept, under both names, so the port diffs cleanly against
// the original; do not collapse them here without collapsing them there first,
// or the next person diffing the two files will read the merge as a behaviour
// change. The genuinely DIFFERENT translator is ghostGlobToEre below, which
// additionally escapes `/` and emits an unanchored fragment for grep.
func ghostGlobToRegExp(glob string) *regexp.Regexp { return ghostGlobToRe(glob) }

// ── Fast path (ghostCheck) ───────────────────────────────────────────────────

// ghostPathMatch is the fast path's matcher: CASE-INSENSITIVE, and it tests the
// whole normalised path as well as its basename.
//
// The slow path's ghostMatch is case-SENSITIVE and segment-aware instead. The
// asymmetry is in the original and is deliberate here: the fast path is the only
// enforcement on clients with no PostToolUse hook, so it errs towards matching.
func ghostPathMatch(p string, patterns []string) bool {
	if p == "" {
		return false
	}
	norm := strings.ToLower(reGhostTrailSlashes.ReplaceAllString(strings.ReplaceAll(p, `\`, "/"), ""))
	if norm == "" {
		return false
	}
	base := norm
	if segs := ghostSegments(norm); len(segs) > 0 {
		base = segs[len(segs)-1]
	}
	for _, raw := range patterns {
		pat := strings.ToLower(ghostTrim(raw))
		if pat == "" {
			continue
		}
		if re := ghostGlobToRe(pat); re != nil && (re.MatchString(norm) || re.MatchString(base)) {
			return true
		}
		patBase := pat[strings.LastIndex(pat, "/")+1:]
		if patBase != "" && patBase != pat {
			if rb := ghostGlobToRe(patBase); rb != nil && rb.MatchString(base) {
				return true
			}
		}
	}
	return false
}

// segments of a `/`-joined path with the empty ones dropped — `split('/')
// .filter(Boolean)`.
func ghostSegments(norm string) []string {
	var out []string
	for _, s := range strings.Split(norm, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// The argument fields that carry a path rather than data. Same list as the
// tamper layer's TAMPER_PATH_FIELDS, including the Antigravity camelCase names
// (lowercased here) its file tools use — without those the ghost layer never
// sees a path on the one client that has no PostToolUse hook to fall back on.
var ghostPathFields = map[string]bool{
	"file_path": true, "path": true, "target_file": true, "notebook_path": true,
	"dest": true, "destination": true, "source": true, "src": true, "from": true, "to": true,
	"directory": true, "dir": true, "folder": true,
	"targetfile": true, "absolutepath": true, "filepath": true,
}

// ghostTargetPaths is the Node hook's extractTargetPaths: the TARGET path fields
// only, never the free-form content, which would false-positive on any file
// whose text merely mentions a hidden name.
//
// Keys are walked SORTED, not in payload order. Go map iteration is randomised
// and the order decides which path ends up named in the deny message — same
// determinism trade the extractors in extract.go make, and for the same reason:
// the set of matches is unchanged, only which one is reported first.
func ghostTargetPaths(args map[string]interface{}) []string {
	out := []string{}
	if args == nil {
		return out
	}
	for _, k := range sgpolicy.SortedKeys(args) {
		v := args[k]
		if ghostPathFields[strings.ToLower(k)] {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		arr, ok := v.([]interface{})
		if !ok {
			continue
		}
		// An edits[]/files[] array of objects: Codex and MultiEdit carry the real
		// targets one level down, so a top-level-only walk misses every one.
		for _, item := range arr {
			obj, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			for _, k2 := range sgpolicy.SortedKeys(obj) {
				if !ghostPathFields[strings.ToLower(k2)] {
					continue
				}
				if s, ok := obj[k2].(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

func ghostNotFound(p string) string { return p + ": No such file or directory" }

// ghostCheck is the fast-path enforcement, run before the policy is resolved.
//
// toolName is unused, as in the original — kept in the signature so the two
// functions still line up when diffed.
//
// Returns a bare not-found message, or "" for no hit. It fails OPEN on anything
// unexpected: a panic here would exit 2, and 2 is the deny signal, so an
// arbitrarily shaped payload could otherwise block a call it has no business
// blocking.
func ghostCheck(toolName string, args map[string]interface{}, ghost *sgshared.GhostConfig, ghostCwd string) (reason string) {
	defer func() {
		if recover() != nil {
			reason = ""
		}
	}()
	if ghost == nil || len(ghost.Patterns) == 0 {
		return ""
	}
	pats := ghost.Patterns

	for _, p := range ghostTargetPaths(args) {
		if ghostPathMatch(p, pats) {
			return ghostNotFound(p)
		}
	}

	// A shell command that names the hidden file (cat/less/head/open <path>).
	for _, cmd := range sgpolicy.ExtractCommands(args) {
		c := strings.ToLower(cmd)
		for _, raw := range pats {
			// The slice offset is taken from the RAW pattern while the slice is
			// applied to the trimmed, lowercased one — that is what the original
			// does, so a pattern written with leading whitespace cuts at the wrong
			// place. Preserved deliberately: correcting it here would make the Go
			// guard hide a file the Node guard leaves visible, and the two have to
			// agree before either is changed.
			lowered := strings.ToLower(ghostTrim(raw))
			idx := strings.LastIndex(raw, "/") + 1
			if idx > len(lowered) {
				idx = len(lowered) // JS slice past the end yields "", it does not throw
			}
			patBase := reGhostWild.ReplaceAllString(lowered[idx:], "")
			// Under three characters a basename is short enough to appear inside an
			// unrelated word, and a false not-found is indistinguishable from a real
			// one to the agent, so short patterns are not substring-matched at all.
			if patBase != "" && ghostUTF16Len(patBase) > 2 && strings.Contains(c, patBase) {
				return ghostNotFound(patBase)
			}
		}
	}

	// Aggregate SIZE commands (du/df) over a DIRECTORY don't name the hidden file,
	// but their totals leak its size + existence. Block them when a target dir
	// holds a ghosted entry (checks direct children — the demonstrated leak).
	// du/df cannot be filtered by a command rewrite the way a listing can, so they
	// are blocked outright on both platforms. Plain LISTINGS (ls/find/tree) are
	// NOT blocked here — they fall through to ghostListingRewrite, which drops the
	// hidden entry from the output so it stays invisible instead.
	for _, cmd := range sgpolicy.ExtractCommands(args) {
		if !reGhostDuDf.MatchString(strings.ToLower(cmd)) {
			continue
		}
		toks := reGhostWSPlus.Split(cmd, -1)
		var dirs []string
		for i := 1; i < len(toks); i++ {
			if t := toks[i]; t != "" && !strings.HasPrefix(t, "-") {
				dirs = append(dirs, t)
			}
		}
		if len(dirs) == 0 {
			dirs = append(dirs, ".") // bare `du` means the working directory
		}
		base := ghostCwd
		if base == "" {
			if wd, err := os.Getwd(); err == nil {
				base = wd
			}
		}
		for _, d := range dirs {
			resolved := d
			if strings.HasPrefix(resolved, "~") {
				home, err := os.UserHomeDir()
				if err != nil {
					continue
				}
				resolved = home + resolved[1:]
			}
			abs := resolved
			if !filepath.IsAbs(abs) {
				abs = filepath.Join(base, resolved)
			}
			st, err := os.Stat(abs)
			if err != nil || !st.IsDir() {
				continue
			}
			entries, err := os.ReadDir(abs)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if ghostPathMatch(filepath.Join(abs, e.Name()), pats) || ghostPathMatch(e.Name(), pats) {
					// The DIRECTORY is named in the message, never the hidden entry.
					return ghostNotFound(d)
				}
			}
		}
	}
	return ""
}

// ── Slow path (ghostBlock) ───────────────────────────────────────────────────

// ghostMatch reports whether targetPath is ghosted by any pattern.
//
// A bare name (`.data`) matches that entry anywhere in the path; a trailing `/`
// (`secrets/`) ghosts a whole directory subtree; a pattern containing `/` is
// matched against the full path.
//
// Unlike ghostPathMatch this is case-SENSITIVE — see the note there.
func ghostMatch(targetPath string, patterns []string) bool {
	if targetPath == "" || len(patterns) == 0 {
		return false
	}
	norm := reGhostTrailSlashes.ReplaceAllString(strings.ReplaceAll(targetPath, `\`, "/"), "")
	if norm == "" {
		return false
	}
	segments := ghostSegments(norm)
	base := norm
	if len(segments) > 0 {
		base = segments[len(segments)-1]
	}
	for _, raw := range patterns {
		pat := ghostTrim(raw)
		if pat == "" {
			continue
		}
		dirOnly := false
		if strings.HasSuffix(pat, "/") {
			dirOnly = true
			pat = pat[:len(pat)-1] // one slash only, as in the original
		}
		if pat == "" {
			continue
		}
		hasSlash := strings.Contains(pat, "/")
		hasWild := reGhostWild.MatchString(pat)
		re := ghostGlobToRegExp(pat)
		if re == nil {
			continue
		}
		if dirOnly {
			// Directory: ghost the dir itself and everything under it.
			if !hasSlash && !hasWild {
				for _, s := range segments {
					if s == pat {
						return true
					}
				}
				continue
			}
			acc := ""
			for _, s := range segments {
				if acc == "" {
					acc = s
				} else {
					acc = acc + "/" + s
				}
				if re.MatchString(acc) || re.MatchString(s) {
					return true
				}
			}
			continue
		}
		if !hasSlash {
			// Name glob: match basename or any single path segment.
			if re.MatchString(base) {
				return true
			}
			matched := false
			for _, s := range segments {
				if re.MatchString(s) {
					matched = true
					break
				}
			}
			if matched {
				return true
			}
			continue
		}
		// Path glob (contains '/'): match the full normalised path.
		if re.MatchString(norm) {
			return true
		}
	}
	return false
}

// ghostCleanToken strips shell decoration from a token so it can be tested as a
// path: surrounding quotes, redirection operators, trailing punctuation.
func ghostCleanToken(tok string) string {
	t := ghostTrim(tok)
	t = reGhostLeadShellOp.ReplaceAllString(t, "")
	t = reGhostTailShellOp.ReplaceAllString(t, "")
	t = reGhostLeadQuote.ReplaceAllString(t, "")
	t = reGhostTailQuote.ReplaceAllString(t, "")
	t = reGhostLeadRedirect.ReplaceAllString(t, "") // strip leading redirection like 2>
	return ghostTrim(t)
}

// ghostFirstString is the `a || b || c || ”` chain the original uses to find a
// tool's path argument: the first field present and non-empty wins.
func ghostFirstString(args map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if s, ok := args[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// ghostBlock returns a plain not-found message if a tool DIRECTLY targets a
// ghost path — read OR write — else "".
//
// Reads are sealed too: a hidden file must be inaccessible, not merely unlisted,
// so `cat A/Y/.data` looks as absent as `rm A/Y`. Listing a PARENT dir that only
// CONTAINS a ghost child is NOT a direct hit (no token equals the ghost) and
// falls through to ghostListingRewrite. Never returns a branded/policy string.
func ghostBlock(toolName string, args map[string]interface{}, ghost *sgshared.GhostConfig) (reason string) {
	defer func() {
		if recover() != nil {
			reason = "" // fail open: a panic would exit 2, and 2 means deny
		}
	}()
	if ghost == nil || len(ghost.Patterns) == 0 {
		return ""
	}
	pats := ghost.Patterns
	if args == nil {
		args = map[string]interface{}{}
	}
	name := toolName

	// Tools that carry an explicit path argument.
	switch name {
	case "Write", "Edit", "MultiEdit", "NotebookEdit", "Read", "NotebookRead", "LS":
		p := ghostFirstString(args, "file_path", "notebook_path", "path")
		if p != "" && ghostMatch(p, pats) {
			return ghostNotFound(p)
		}
		return ""
	case "Glob", "Grep":
		p := ghostFirstString(args, "path")
		pat := ghostFirstString(args, "pattern", "glob")
		if p != "" && ghostMatch(p, pats) {
			return ghostNotFound(p)
		}
		// The search PATTERN is tested too: `Grep pattern:".data"` is an attempt to
		// find the hidden file by name, and answering it truthfully confirms it
		// exists.
		if pat != "" && ghostMatch(pat, pats) {
			return ghostNotFound(pat)
		}
		return ""
	}

	// Bash & other exec: deny if any token directly names a ghost path. Seals
	// direct reads (cat/head/less/…) and mutations (rm/mv/…) alike. A listing of
	// a parent dir has no ghost token and falls through to the rewrite.
	if name == "Bash" || name == "BashOutput" || sgshared.GuessPermission(name) == "EXECUTE" {
		cmd := ghostFirstString(args, "command")
		if cmd == "" {
			return ""
		}
		for _, raw := range reGhostWSPlus.Split(cmd, -1) {
			tok := ghostCleanToken(raw)
			if tok != "" && !strings.HasPrefix(tok, "-") && ghostMatch(tok, pats) {
				return ghostNotFound(tok)
			}
		}
	}
	return ""
}

// ── Listing rewrite ──────────────────────────────────────────────────────────

// ghostShq shell single-quotes a string. Unused in the original too — kept so
// the port stays a complete mirror of the layer rather than an edited one.
func ghostShq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// ghostGlobToEre is the THIRD glob translator and the only one that genuinely
// differs: it escapes `/` as well, and returns an unanchored fragment rather
// than a compiled anchored regexp, because the result is spliced into a POSIX
// ERE alternation handed to an external `grep -vE`. Nothing here is ever
// compiled by Go, so RE2's restrictions do not apply to its output — the pattern
// only has to be something GNU grep accepts.
func ghostGlobToEre(g string) string {
	var re strings.Builder
	runes := []rune(g)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case c == '*':
			if i+1 < len(runes) && runes[i+1] == '*' {
				re.WriteString(".*")
				i++
			} else {
				re.WriteString("[^/]*")
			}
		case c == '?':
			re.WriteString("[^/]")
		case strings.ContainsRune(`.^$+(){}[]|\/`, c):
			re.WriteByte('\\')
			re.WriteRune(c)
		default:
			re.WriteRune(c)
		}
	}
	return re.String()
}

// ghostListingRewrite turns a simple directory listing into the same listing
// with the ghost entries filtered out of its output, so the agent never sees
// them. Returns "" when there is nothing to rewrite.
//
// Only bare listings are touched (no pipe, redirect or compound) to stay safe;
// richer output formats are handled by the PostToolUse filter on the clients
// that honour it.
func ghostListingRewrite(args map[string]interface{}, ghost *sgshared.GhostConfig) string {
	if ghost == nil || len(ghost.Patterns) == 0 {
		return ""
	}
	if args == nil {
		return ""
	}
	cmd := ghostFirstString(args, "command")
	if cmd == "" {
		return ""
	}
	if reGhostComposed.MatchString(cmd) {
		return "" // no shell composition
	}
	if !reGhostListingCmd.MatchString(cmd) {
		return ""
	}
	// Translate each hidden glob to an ERE alternative, then match it as a whole
	// path component, the whole line, or the trailing token — covers `ls`,
	// `ls -la`, `find`, `tree` AND `grep -rn` (whose `path:line:content` output has
	// the path followed by a colon, so ':' is a valid trailing delimiter too).
	//
	// The patterns are NOT trimmed here, unlike everywhere else in this layer.
	// That is the original's behaviour and it is load-bearing in the other
	// direction: trimming would change the generated ERE, and the block path and
	// the rewrite path have to agree on what is hidden or a file gets blocked on
	// read while still showing up in a listing.
	var alts []string
	for _, raw := range ghost.Patterns {
		p := strings.TrimSuffix(raw, "/")
		if p == "" {
			continue
		}
		alts = append(alts, ghostGlobToEre(p))
		// Also hide the BARE basename: a slash-glob like `*/secret-plan.txt` is
		// slash-anchored, but `ls` / `ls -la` print entry names with NO path prefix
		// (just `secret-plan.txt`), so the anchored form above never matches them.
		// Adding the trailing name (minus a leading `*`) closes that leak.
		bn := strings.TrimLeft(p[strings.LastIndex(p, "/")+1:], "*")
		if bn != "" && bn != p {
			alts = append(alts, ghostGlobToEre(bn))
		}
	}
	if len(alts) == 0 {
		return ""
	}
	// grep -vE drops any line where a hidden name appears as a path component, the
	// whole line, or the final token. Single-quoted so the shell leaves it intact.
	ere := "(^|/| )(" + strings.Join(alts, "|") + ")(/|$|:)"
	return cmd + " | grep -vE '" + strings.ReplaceAll(ere, "'", `'\''`) + "'"
}

// ── Entry point ──────────────────────────────────────────────────────────────

// ghostLayer runs the whole layer over one call and reports what to do with it.
//
// Order matches the Node hook: the fast-path check first (it is the one that
// catches du/df and the Antigravity path fields), then the direct-access block,
// and only if neither fired does a listing get rewritten — a command that was
// going to be denied must not also be rewritten.
//
// A non-empty Deny must be delivered to the client as a STEALTH block: the bare
// string, with no ROUTE line and no SolonGate wording added by the adapter, or
// the agent learns the path exists from the shape of the refusal. AuditReason,
// not Deny, is what belongs in the audit log.
//
// The `ghost` argument being nil is the normal state for a project with no
// hidden paths, and also the state when the policy cache could not be read — the
// Node hook gates its fast-path ghostCheck on a successful cache read for the
// same reason, so passing sec.Ghost straight through reproduces that gate.
func ghostLayer(toolName string, args map[string]interface{}, ghost *sgshared.GhostConfig, cwd string) ghostVerdict {
	if ghost == nil || len(ghost.Patterns) == 0 {
		return ghostVerdict{}
	}
	if hit := ghostCheck(toolName, args, ghost, cwd); hit != "" {
		// The fast path records the not-found string itself, as the Node hook does.
		return ghostVerdict{Deny: hit, AuditReason: hit}
	}
	if hit := ghostBlock(toolName, args, ghost); hit != "" {
		// The slow path records the branded reason instead: the operator has to be
		// able to see WHY a call was refused, even though the agent must not.
		return ghostVerdict{Deny: hit, AuditReason: "ghost path (hidden from agent)"}
	}
	// No direct hit: if this is a listing command, rewrite it so hidden entries
	// are filtered out of its output. Works on both Claude (updatedInput) and
	// Antigravity (overwrite.CommandLine), since agy's PreToolUse `overwrite`
	// replaces the command before it runs.
	if toolName == "Bash" || toolName == "run_command" || sgshared.GuessPermission(toolName) == "EXECUTE" {
		if rw := ghostListingRewrite(args, ghost); rw != "" {
			return ghostVerdict{Rewrite: rw}
		}
	}
	return ghostVerdict{}
}
