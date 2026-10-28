// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package policy

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

	GlobStarRun = shared.GlobStarRun
	GlobEscape  = regexp.MustCompile(`[.+^${}()|\\]`)

	reInterpreter = regexp.MustCompile(`(?i)^(?:bash|sh|zsh|ksh|dash|ash|python3?|node|deno|bun|ruby|perl|php|pwsh|powershell|source|\.)$`)
)

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

			pattern := GlobStarRun.ReplaceAllString(b, "*")
			pattern = GlobEscape.ReplaceAllString(pattern, `\${0}`)
			pattern = strings.ReplaceAll(pattern, "*", "[^/]*")
			pattern = strings.ReplaceAll(pattern, "?", "[^/]")
			re, err := regexp.Compile("^" + pattern + "$")
			if err != nil {
				continue
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

type refFile struct {
	Name    string
	Content string
}

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

const (
	searchWalkMaxFiles = 2000
	searchWalkMaxDepth = 8
)

var searchSkipDirs = map[string]bool{
	".git": true, "node_modules": true, ".venv": true, "venv": true,
	"vendor": true, "dist": true, "build": true, "target": true,
	"__pycache__": true, ".next": true, ".turbo": true,
}

func IsContentSearchTool(tool string) bool {
	n := strings.ToLower(tool)
	if strings.Contains(n, "websearch") || strings.Contains(n, "web_search") {
		return false
	}
	return strings.Contains(n, "grep") || strings.Contains(n, "search") || strings.Contains(n, "ripgrep")
}

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

var winDrive = regexp.MustCompile(`^[A-Za-z]:[\\/]`)
