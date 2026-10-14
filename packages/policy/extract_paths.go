// SPDX-License-Identifier: Apache-2.0

package policy

// Split from extract.go: glob and search-root expansion, reading referenced
// scripts, and absolutizing relative path tokens.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/solongate/agent-security/packages/shared"
)

var (
	GlobTokenSplit = regexp.MustCompile("[\\s'\"|<>;&()]+")
	reRefTokSplit  = regexp.MustCompile(`[\s'"();|&<>]+`)

	GlobChars = regexp.MustCompile(`[*?\[]`)
	// GlobStarRun collapses `**` and longer to a single star. Exported because
	// both glob expanders normalise with it before building a pattern.
	// ONE DEFINITION, in shared. The DLP scanner moved there so the MCP proxy could
	// use it, and its glob converter needs this same rule, shared cannot import this
	// module (this one imports shared), so the regexp lives there and this is the
	// alias. Two copies of "how many stars is one star" is exactly the kind of pair that
	// drifts.
	GlobStarRun = shared.GlobStarRun
	GlobEscape  = regexp.MustCompile(`[.+^${}()|\\]`)

	reInterpreter = regexp.MustCompile(`(?i)^(?:bash|sh|zsh|ksh|dash|ash|python3?|node|deno|bun|ruby|perl|php|pwsh|powershell|source|\.)$`)
)

// expandCommandGlobs resolves a globbed token in an exec command to the real
// files it names, in that one directory.
//
// A filename or path rule matches literally, so `*.env` never matches the token
// `staging.e*`, which means `cut config/staging.e*` sails past a rule that
// `cat config/staging.env` trips, with no cleverness required. Resolving the
// glob here lets the rule see the real file whichever reader the model reached
// for. Bounded to one directory level, and it fails open: this is hardening on
// top of the literal match, never the thing standing between a call and a
// decision.
func ExpandCommandGlobs(args map[string]interface{}, cwd string) []string {
	var out []string
	base := cwd
	if base == "" {
		if wd, err := os.Getwd(); err == nil {
			base = wd
		}
	}
	for _, cmd := range ExtractCommands(args) {
		for _, tok := range GlobTokenSplit.Split(cmd, -1) {
			if tok == "" || strings.HasPrefix(tok, "-") || !GlobChars.MatchString(tok) || HTTPPrefix.MatchString(tok) {
				continue
			}
			g := tok
			if strings.HasPrefix(g, "~") {
				home, err := os.UserHomeDir()
				if err != nil {
					continue
				}
				g = home + g[1:]
			}
			// Clean BEFORE splitting, and take the basename rather than slicing at
			// the directory's length. filepath.Dir cleans its result, so on an
			// uncleaned path (`/srv/./app/staging.e*`, `/srv//app/x*`) the slice
			// offset was wrong and produced a fragment containing a `/`, which no
			// directory entry can ever match, so the token was silently dropped and
			// the glob dodge this function exists to close reopened.
			abs := g
			if !filepath.IsAbs(abs) {
				abs = filepath.Join(base, g)
			}
			abs = filepath.ToSlash(filepath.Clean(abs))
			dir := filepath.ToSlash(filepath.Dir(abs))
			b := filepath.Base(abs)
			if !GlobChars.MatchString(b) {
				continue
			}
			// The run of `*` collapses first, matching the JavaScript twin, where
			// it is load-bearing: this token came off the AGENT's command line,
			// and `[^/]*[^/]*…` backtracks catastrophically there, then gets
			// tested once per directory entry. RE2 does not backtrack, so here it
			// only keeps the two identical.
			pattern := GlobStarRun.ReplaceAllString(b, "*")
			pattern = GlobEscape.ReplaceAllString(pattern, `\${0}`)
			pattern = strings.ReplaceAll(pattern, "*", "[^/]*")
			pattern = strings.ReplaceAll(pattern, "?", "[^/]")
			re, err := regexp.Compile("^" + pattern + "$")
			if err != nil {
				continue // an unbalanced bracket is not a glob we can resolve
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if re.MatchString(e.Name()) {
					out = append(out, filepath.ToSlash(filepath.Join(dir, e.Name())))
				}
			}
		}
	}
	return out
}

// A script the call hands to an interpreter, and what is in it.
type refFile struct {
	Name    string
	Content string
}

// readReferencedFiles returns the contents of scripts the call would EXECUTE,
// in the order the command mentions them.
//
// Only a file actually handed to an interpreter counts, `bash x.sh`,
// `python x.py`, `source x`. A file that is merely an argument (`rm x`, `cp x
// y`, a read target) is not run, and inlining its text there would block
// deleting a file whose contents happen to mention a protected name.
//
// The ORDER is part of the contract, which is why this returns a slice and not
// a map. The contents are concatenated into one command string and then run
// through normalizeShellCommand, which resolves variable assignments
// left-to-right, so re-ordering two inlined scripts can change what `$x`
// resolves to, and with it which rule fires. Discovery order is what the Node
// hook uses; sorting the names would have been deterministic and still wrong.
func ReadReferencedFiles(args map[string]interface{}, cwd string) []refFile {
	const maxFiles, maxBytes = 3, 65536
	var out []refFile
	var cands []string
	seen := map[string]bool{}
	for _, f := range []string{"command", "cmd", "script", "shell", "code"} {
		v, ok := args[f].(string)
		if !ok {
			continue
		}
		var toks []string
		for _, t := range reRefTokSplit.Split(v, -1) {
			if t != "" {
				toks = append(toks, t)
			}
		}
		for i := 0; i < len(toks)-1; i++ {
			if !reInterpreter.MatchString(toks[i]) {
				continue
			}
			// The first non-flag token after the interpreter is the script it runs.
			j := i + 1
			for j < len(toks) && strings.HasPrefix(toks[j], "-") {
				j++
			}
			if j < len(toks) && !seen[toks[j]] {
				seen[toks[j]] = true
				cands = append(cands, toks[j])
			}
		}
	}
	base := cwd
	if base == "" {
		if wd, err := os.Getwd(); err == nil {
			base = wd
		}
	}
	n := 0
	for _, c := range cands {
		if n >= maxFiles {
			break
		}
		p := c
		if !filepath.IsAbs(p) {
			p = filepath.Join(base, c)
		}
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() || st.Size() > maxBytes {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if len(b) > maxBytes {
			b = b[:maxBytes]
		}
		out = append(out, refFile{Name: c, Content: string(b)})
		n++
	}
	return out
}

// ── content-returning searches ──────────────────────────────────────────────

// A grep-style tool is a READ of every file under its root, and its arguments
// say none of that. They carry a search ROOT and a query; the files whose
// contents come back are never named. So a path rule that denies one file under
// that root matches nothing, the search runs, and the file's contents are
// returned, the rule holds against the read tool and is walked straight past by
// the search tool beside it.
//
// Measured on Antigravity: `view_file` on a denied path is refused, and
// `grep_search` rooted at the workspace returns the same file's contents. The
// agent found that on its own, one refusal later.
//
// This is the same move ExpandCommandGlobs makes for `cut staging.e*`: resolve
// what the call will actually reach so the existing rules can see it. Hardening
// on top of the literal match, never the thing standing between a call and a
// decision, so every bound below fails OPEN.
const (
	searchWalkMaxFiles = 2000
	searchWalkMaxDepth = 8
)

// searchSkipDirs are directories a search tool is asked about constantly and
// which no policy is ever written against. Walking them is pure cost.
var searchSkipDirs = map[string]bool{
	".git": true, "node_modules": true, ".venv": true, "venv": true,
	"vendor": true, "dist": true, "build": true, "target": true,
	"__pycache__": true, ".next": true, ".turbo": true,
}

// IsContentSearchTool reports whether a tool name reads file CONTENTS in bulk.
//
// `websearch` is excluded by name: it reaches the network, not the disk, and
// GuessPermission already puts it in NETWORK.
func IsContentSearchTool(tool string) bool {
	n := strings.ToLower(tool)
	if strings.Contains(n, "websearch") || strings.Contains(n, "web_search") {
		return false
	}
	return strings.Contains(n, "grep") || strings.Contains(n, "search") || strings.Contains(n, "ripgrep")
}

// ExpandSearchRoots returns the files a content search rooted at these arguments
// could return. Empty for anything that is not such a tool.
func ExpandSearchRoots(tool string, args map[string]interface{}, cwd string) []string {
	if !IsContentSearchTool(tool) || args == nil {
		return nil
	}
	base := cwd
	if base == "" {
		if wd, err := os.Getwd(); err == nil {
			base = wd
		}
	}

	var out []string
	budget := searchWalkMaxFiles
	for _, s := range ScanStrings(args) {
		if budget <= 0 {
			break
		}
		if HTTPPrefix.MatchString(s) || !strings.ContainsAny(s, "/\\") {
			continue
		}
		root := s
		if !filepath.IsAbs(root) {
			root = filepath.Join(base, root)
		}
		st, err := os.Stat(root)
		if err != nil || !st.IsDir() {
			continue
		}
		out = append(out, walkSearchRoot(root, &budget)...)
	}
	return out
}

func walkSearchRoot(root string, budget *int) []string {
	var out []string
	rootDepth := strings.Count(filepath.Clean(root), string(filepath.Separator))

	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || *budget <= 0 {
			// Unreadable or over budget: stop descending rather than guess. This
			// layer never denies on its own, so an early stop only means the
			// literal match is on its own for the rest of the tree.
			if *budget <= 0 {
				return fs.SkipAll
			}
			return nil
		}
		if d.IsDir() {
			if p == root {
				return nil
			}
			if searchSkipDirs[d.Name()] || strings.Count(filepath.Clean(p), string(filepath.Separator))-rootDepth >= searchWalkMaxDepth {
				return fs.SkipDir
			}
			return nil
		}
		*budget--
		out = append(out, filepath.ToSlash(p))
		return nil
	})
	return out
}

// AbsolutizePaths resolves relative path tokens against the call's cwd, and
// returns the absolute forms to be matched ALONGSIDE the originals.
//
// THE HOLE THIS CLOSES. ExtractPaths returns what the call said, verbatim. A
// file tool sends an absolute path, because the client resolves it before the
// hook ever sees the call -- but a shell command carries whatever the model
// typed, and a model in the directory types `cat forbidden/notes.txt`. That
// token is relative, an absolute path rule never matches it, and the same file
// the Read tool is refused for is handed over by `cat`. The rule looked like it
// covered a directory; it covered one way of reaching it.
//
// ExpandCommandGlobs already resolved against cwd, but only for tokens
// containing a glob character -- so `cat forbidden/note*.txt` was caught and
// `cat forbidden/notes.txt` was not, which is the wrong way round.
//
// Both forms are kept. A rule may legitimately be written relative, and
// dropping the original would break it. No filesystem access: resolution is
// lexical, so a path that does not exist still matches a pattern that names it.
func AbsolutizePaths(paths []string, cwd string) []string {
	base := cwd
	if base == "" {
		if wd, err := os.Getwd(); err == nil {
			base = wd
		}
	}
	if base == "" {
		return nil
	}
	base = filepath.ToSlash(base)
	out := make([]string, 0, len(paths))
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		// Already absolute, a home-relative path nothing here can resolve, or a
		// Windows drive path: leave them to the literal match.
		if p == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || winDrive.MatchString(p) {
			continue
		}
		abs := filepath.ToSlash(filepath.Clean(base + "/" + p))
		if abs == "" || abs == p || seen[abs] {
			continue
		}
		seen[abs] = true
		out = append(out, abs)
	}
	return out
}

// winDrive is "C:/..." and friends, which are absolute on the platform that
// writes them even though they do not start with a slash.
var winDrive = regexp.MustCompile(`^[A-Za-z]:[\\/]`)