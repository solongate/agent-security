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
	"mvdan.cc/sh/v3/syntax"
)

var (
	GlobTokenSplit = regexp.MustCompile("[\\s'\"|<>;&()]+")

	GlobChars = regexp.MustCompile(`[*?\[]`)

	GlobStarRun = shared.GlobStarRun
	GlobEscape  = regexp.MustCompile(`[.+^${}()|\[\]\\]`)

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
	for f := range commandFields {
		v, ok := args[f].(string)
		if !ok {
			continue
		}
		// Parse command positions: ordinary arguments, comments, and quoted
		// command-like text must not consume the bounded file-reading budget.
		// Keep complete statements before a syntax error, without falling back
		// to treating arbitrary words in malformed input as commands.
		for stmt, err := range syntax.NewParser().StmtsSeq(strings.NewReader(v)) {
			if err != nil {
				break
			}
			syntax.Walk(stmt, func(node syntax.Node) bool {
				call, ok := node.(*syntax.CallExpr)
				if !ok || len(call.Args) < 2 {
					return true
				}
				words := referencedInvocation(call.Args)
				if len(words) < 2 {
					return true
				}
				name, ok := referencedLiteral(words[0].Parts, false)
				if !ok || !reInterpreter.MatchString(filepath.Base(name)) {
					return true
				}
				for _, word := range words[1:] {
					target, ok := referencedLiteral(word.Parts, false)
					if !ok {
						break
					}
					if strings.HasPrefix(target, "-") {
						continue
					}
					if target != "" && !seen[target] {
						seen[target] = true
						cands = append(cands, target)
					}
					break
				}
				return true
			})
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

// Known execution wrappers have their own command operand. Only skip options
// with known arity, so an option's value cannot masquerade as an interpreter.
var referencedWrappers = map[string]map[string]bool{
	"command": {"-p": false},
	"exec":    {"-c": false, "-l": false, "-a": true},
	"nohup":   {},
	"env":     {"-i": false, "--ignore-environment": false, "-u": true, "--unset": true},
	"sudo": {
		"-E": false, "-H": false, "-n": false, "-S": false, "-k": false,
		"--non-interactive": false, "--preserve-env": false,
		"-u": true, "--user": true, "-g": true, "--group": true,
	},
}

func referencedInvocation(words []*syntax.Word) []*syntax.Word {
	for len(words) > 0 {
		name, ok := referencedLiteral(words[0].Parts, false)
		options, wrapper := referencedWrappers[filepath.Base(name)]
		if !ok || !wrapper {
			return words
		}
		i, flags := 1, true
		for i < len(words) {
			arg, ok := referencedLiteral(words[i].Parts, false)
			if !ok {
				return nil
			}
			if key, _, assigned := strings.Cut(arg, "="); filepath.Base(name) == "env" && assigned && syntax.ValidName(key) {
				i++
				continue
			}
			if !flags || !strings.HasPrefix(arg, "-") {
				break
			}
			i++
			if arg == "--" {
				flags = false
				continue
			}
			option, _, inline := strings.Cut(arg, "=")
			value, known := options[option]
			if !known || (inline && !strings.HasPrefix(option, "--")) {
				return nil
			}
			if value && !inline {
				i++
			}
		}
		if i >= len(words) {
			return nil
		}
		words = words[i:]
	}
	return nil
}

// referencedLiteral removes shell quoting without evaluating substitutions or
// reading the agent's environment. Dynamic words cannot identify a static file.
func referencedLiteral(parts []syntax.WordPart, doubleQuoted bool) (string, bool) {
	var out strings.Builder
	for _, part := range parts {
		switch p := part.(type) {
		case *syntax.Lit:
			for i := 0; i < len(p.Value); i++ {
				if p.Value[i] == '\\' && i+1 < len(p.Value) {
					next := p.Value[i+1]
					if !doubleQuoted || strings.ContainsRune("$`\"\\\n", rune(next)) {
						i++
						if next == '\n' {
							continue
						}
					}
				}
				out.WriteByte(p.Value[i])
			}
		case *syntax.SglQuoted:
			if p.Dollar {
				return "", false
			}
			out.WriteString(p.Value)
		case *syntax.DblQuoted:
			value, ok := referencedLiteral(p.Parts, true)
			if !ok || p.Dollar {
				return "", false
			}
			out.WriteString(value)
		default:
			return "", false
		}
	}
	return out.String(), true
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
