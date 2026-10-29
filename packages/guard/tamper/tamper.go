// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tamper

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/solongate/agent-security/packages/policy"
)

var GuardToolsExec = map[string]bool{
	"bash": true, "powershell": true, "shell": true, "exec": true, "run": true,
	"eval": true, "cmd": true,
	"sh": true, "zsh": true, "dash": true, "terminal": true,
	"monitor": true, "worktree": true, "enterworktree": true, "exitworktree": true,
}

const (
	tamperSG = "/.solongate"
	tamperCC = "/.claude"

	tamperCX  = "/.codex"
	tamperAGY = "/.gemini/config"
	tamperOC  = "/.config/opencode"

	tamperInstall = "/solongate"
)

var tamperHome = func() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.Getenv("HOME")
	}
	if home == "" && runtime.GOOS == "windows" {
		home = os.Getenv("USERPROFILE")
	}
	abs, err := filepath.Abs(home)
	if err != nil {
		abs = filepath.Clean(home)
	}
	return strings.ToLower(filepath.ToSlash(abs))
}()

var tamperProtectedAbs = []string{
	tamperHome + tamperCC + "/settings.json",
	tamperHome + tamperCC + "/settings.local.json",
	tamperHome + tamperCX + "/hooks.json",
	tamperHome + tamperCX + "/config.toml",
	tamperHome + tamperAGY + "/hooks.json",
	tamperHome + tamperSG + "/hooks",
	tamperHome + tamperSG + "/policy.json",
	tamperHome + tamperSG + "/.policy-cache.json",
	// The whole key directory, not just machine.pub: machine.key is the
	// private key that signs policy.json, and an agent holding it can sign a
	// forged policy that VerifyDocument accepts.
	tamperHome + tamperSG + "/crypto",

	tamperHome + tamperSG + "/cloud-guard.json",

	tamperHome + tamperSG + "/accounts.json",

	tamperHome + tamperOC + "/plugins/solongate.js",
}

var tamperProtectedGlobs = []string{
	"**" + tamperCC + "/settings.json",
	"**" + tamperCC + "/settings.local.json",
	"**" + tamperCX + "/hooks.json",
	"**" + tamperCX + "/config.toml",
	"**" + tamperAGY + "/hooks.json",
	"**" + tamperSG + "/hooks/**",
	"**" + tamperSG + "/policy.json",
	"**" + tamperSG + "/.policy-cache.json",
	"**" + tamperSG + "/.policy-cache-*.json",
	"**" + tamperSG + "/crypto/**",
	"**" + tamperSG + "/cloud-guard.json",

	"**" + tamperSG + "/.ratelimit-*",

	"**" + tamperSG + "/bin/**",

	"**" + tamperSG + "/data/**",

	"**" + tamperOC + "/plugins/solongate.js",
	"**" + tamperOC + "/plugins/solongate/**",

	"**" + tamperInstall + "/compose/**",
	"**" + tamperInstall + "/data/**",
	"**" + tamperInstall + "/images/**",
	"**" + tamperInstall + "/helm/**",
	"**" + tamperInstall + "/solongate.exe",
	"**" + tamperInstall + "/setup.sh",
}

var tamperBasenames = []string{
	"policy.json",

	".policy-cache", ".ratelimit-",

	"solongate-guard",
	"cloud-guard.json",

	"accounts.json",
	"solongate.db", "solongate.exe",

	"machine.key", "machine.pub",
}

var tamperPathFields = map[string]bool{
	"file_path": true, "path": true, "target_file": true, "notebook_path": true,
	"dest": true, "destination": true, "source": true, "src": true,
	"from": true, "to": true,
	"directory": true, "dir": true, "folder": true,

	"targetfile": true, "absolutepath": true, "filepath": true,
	"directorypath": true, "searchpath": true, "file": true,
	"paths": true, "files": true,
}

const tamperJSSpace = `[\t\n\v\f\r \x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]`

var (
	reTamperCCSettings = regexp.MustCompile(`/\.claude/settings(\.local)?\.json$`)
	reTamperSGHooks    = regexp.MustCompile(`/\.solongate/hooks(/|$)`)

	reTamperSGBin    = regexp.MustCompile(`/\.solongate/bin(/|$)`)
	reTamperSGCrypto = regexp.MustCompile(`/\.solongate/crypto(/|$)`)
	reTamperCXHooks  = regexp.MustCompile(`/\.codex/(hooks\.json|config\.toml)$`)
	reTamperAGYHooks = regexp.MustCompile(`/\.gemini/config/hooks\.json$`)
	reTamperOCPlugin = regexp.MustCompile(`/\.config/opencode/plugins/solongate\b`)

	reTamperCmdCCSettings = regexp.MustCompile(`\.claude[\\/]+settings(\.local)?\.json`)
	reTamperCmdSGHooks    = regexp.MustCompile(`\.solongate[\\/]+hooks`)
	reTamperCmdSGBin      = regexp.MustCompile(`\.solongate[\\/]+bin`)
	reTamperCmdSGCrypto   = regexp.MustCompile(`\.solongate[\\/]+crypto`)
	reTamperCmdCXHooks    = regexp.MustCompile(`\.codex[\\/]+(hooks\.json|config\.toml)`)
	reTamperCmdAGYHooks   = regexp.MustCompile(`\.gemini[\\/]+config[\\/]+hooks\.json`)
	reTamperCmdOCPlugin   = regexp.MustCompile(`opencode[\\/]+plugins[\\/]+solongate`)
	reTamperInstallDirs   = regexp.MustCompile(`[\\/]solongate[\\/]+(compose|data|images|helm)[\\/]`)

	// reTamperCdSplit detects commands that change into a protected directory
	// before operating on filenames (e.g. "cd ~/.claude && rm settings.json").
	reTamperCdSplit = regexp.MustCompile(`(?i)\bcd\s+[^;&|]*(\.claude|\.solongate|\.codex|\.gemini/config|\.config/opencode)\b`)
)

func NormPath(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	p = filepath.Clean(p)
	p = filepath.ToSlash(p)
	return strings.ToLower(p)
}

func isProtectedPath(p string) string {
	if p == "" {
		return ""
	}
	np := NormPath(p)
	for _, abs := range tamperProtectedAbs {

		if np == abs || strings.HasPrefix(np, abs+"/") {
			return abs
		}
	}
	for _, g := range tamperProtectedGlobs {
		if policy.MatchPathGlob(np, g) {
			return g
		}
	}
	if reTamperCCSettings.MatchString(np) {
		return "settings.json"
	}
	if reTamperSGHooks.MatchString(np) {
		return "solongate-hooks"
	}
	if reTamperSGBin.MatchString(np) {
		return "solongate-bin"
	}
	if reTamperSGCrypto.MatchString(np) {
		return "solongate-crypto"
	}
	if reTamperCXHooks.MatchString(np) {
		return "codex-hooks"
	}
	if reTamperAGYHooks.MatchString(np) {
		return "antigravity-hooks"
	}
	if reTamperOCPlugin.MatchString(np) {
		return "opencode-plugin"
	}

	if strings.Contains(np, "/.solongate/") || strings.HasPrefix(np, ".solongate/") {
		base := np[strings.LastIndex(np, "/")+1:]
		for _, b := range tamperBasenames {
			if strings.HasPrefix(base, strings.ToLower(b)) {
				return b
			}
		}
	}
	return ""
}

func commandTargetsProtected(cmd string) string {
	c := strings.ToLower(cmd)
	if c == "" {
		return ""
	}
	for _, b := range tamperBasenames {
		if strings.Contains(c, strings.ToLower(b)) {
			return b
		}
	}
	if reTamperCmdCCSettings.MatchString(c) {
		return "settings.json"
	}
	if reTamperCmdSGHooks.MatchString(c) {
		return "solongate-hooks"
	}
	if reTamperCmdSGBin.MatchString(c) {
		return "solongate-bin"
	}
	if reTamperCmdSGCrypto.MatchString(c) {
		return "solongate-crypto"
	}
	if reTamperCmdCXHooks.MatchString(c) {
		return "codex-hooks"
	}
	if reTamperCmdAGYHooks.MatchString(c) {
		return "antigravity-hooks"
	}
	if reTamperCmdOCPlugin.MatchString(c) {
		return "opencode-plugin"
	}

	if reTamperInstallDirs.MatchString(c) {
		return "solongate-install"
	}

	// Detect cd-based evasion: "cd ~/.claude && rm settings.json" splits the
	// directory from the filename across shell operators, evading the joined
	// path regexes above. If the command changes into a protected directory,
	// block it.
	if reTamperCdSplit.MatchString(c) {
		return "cd-into-protected-dir"
	}

	return ""
}

func ExtractTargetPaths(args map[string]interface{}) []string {
	out := []string{}
	if args == nil {
		return out
	}
	for _, k := range policy.SortedKeys(args) {
		v := args[k]
		if tamperPathFields[strings.ToLower(k)] {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}

		if arr, ok := v.([]interface{}); ok {
			for _, item := range arr {
				// Handle string items in arrays (e.g. paths: ["~/.solongate/policy.json"]).
				if s, ok := item.(string); ok {
					if tamperPathFields[strings.ToLower(k)] {
						out = append(out, s)
					}
					continue
				}
				obj, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				for _, k2 := range policy.SortedKeys(obj) {
					if !tamperPathFields[strings.ToLower(k2)] {
						continue
					}
					if s, ok := obj[k2].(string); ok {
						out = append(out, s)
					}
				}
			}
		}
		if arr, ok := v.([]string); ok {
			if tamperPathFields[strings.ToLower(k)] {
				out = append(out, arr...)
			}
		}

		// Traverse nested maps to find path fields one level deeper
		// (e.g. {"params": {"file_path": "/..."}} ).
		if nested, ok := v.(map[string]interface{}); ok {
			for _, k2 := range policy.SortedKeys(nested) {
				if !tamperPathFields[strings.ToLower(k2)] {
					continue
				}
				if s, ok := nested[k2].(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

func Check(toolName string, args map[string]interface{}, cwd ...string) string {
	tn := strings.ToLower(toolName)

	isExec := GuardToolsExec[tn] || policy.IsExecTool(toolName)

	resolveCwd := ""
	if len(cwd) > 0 {
		resolveCwd = cwd[0]
	}

	for _, p := range ExtractTargetPaths(args) {
		if hit := isProtectedPath(p); hit != "" {
			return `Tamper protection: access to "` + p + `" is blocked (protected: ` + hit + `)`
		}
		// If the path is relative and we have a cwd, resolve and re-check.
		if resolveCwd != "" && !filepath.IsAbs(p) && p != "" {
			absP := filepath.Join(resolveCwd, p)
			if hit := isProtectedPath(absP); hit != "" {
				return `Tamper protection: access to "` + p + `" is blocked (protected: ` + hit + `)`
			}
		}
	}
	if isExec {
		for _, cmd := range policy.ExtractCommands(args) {
			if hit := commandTargetsProtected(cmd); hit != "" {
				return `Tamper protection: command references protected resource "` + hit + `", blocked`
			}
		}
		if argsInvokeCLI(args) {
			return `Tamper protection: command references protected resource "solongate-cli", blocked`
		}
	}
	return ""
}
