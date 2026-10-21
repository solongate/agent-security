// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/solongate/agent-security/packages/policy"
)

var tamperGuardToolsExec = map[string]bool{
	"bash": true, "powershell": true, "shell": true, "exec": true, "run": true,
	"eval": true, "cmd": true,
}

const (
	tamperSG = "/.solongate"
	tamperCC = "/.claude"

	tamperCX  = "/.codex"
	tamperAGY = "/.gemini/config"

	tamperInstall = "/solongate"
)

var tamperHome = func() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.Getenv("HOME")
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
	tamperHome + tamperSG + "/crypto/machine.pub",

	tamperHome + tamperSG + "/cloud-guard.json",

	tamperHome + tamperSG + "/accounts.json",
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
	"**" + tamperSG + "/crypto/machine.pub",
	"**" + tamperSG + "/cloud-guard.json",

	"**" + tamperSG + "/.ratelimit-*",

	"**" + tamperSG + "/bin/**",

	"**" + tamperSG + "/data/**",

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
}

var tamperPathFields = map[string]bool{
	"file_path": true, "path": true, "target_file": true, "notebook_path": true,
	"dest": true, "destination": true, "source": true, "src": true,
	"from": true, "to": true,
	"directory": true, "dir": true, "folder": true,

	"targetfile": true, "absolutepath": true, "filepath": true,
}

const tamperJSSpace = `[\t\n\v\f\r \x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]`

var (
	reTamperCCSettings = regexp.MustCompile(`/\.claude/settings(\.local)?\.json$`)
	reTamperSGHooks    = regexp.MustCompile(`/\.solongate/hooks(/|$)`)

	reTamperSGBin    = regexp.MustCompile(`/\.solongate/bin(/|$)`)
	reTamperCXHooks  = regexp.MustCompile(`/\.codex/(hooks\.json|config\.toml)$`)
	reTamperAGYHooks = regexp.MustCompile(`/\.gemini/config/hooks\.json$`)

	reTamperCmdCCSettings = regexp.MustCompile(`\.claude[\\/]+settings(\.local)?\.json`)
	reTamperCmdSGHooks    = regexp.MustCompile(`\.solongate[\\/]+hooks`)
	reTamperCmdSGBin      = regexp.MustCompile(`\.solongate[\\/]+bin`)
	reTamperCmdCXHooks    = regexp.MustCompile(`\.codex[\\/]+(hooks\.json|config\.toml)`)
	reTamperCmdAGYHooks   = regexp.MustCompile(`\.gemini[\\/]+config[\\/]+hooks\.json`)
	reTamperInstallDirs   = regexp.MustCompile(`[\\/]solongate[\\/]+(compose|data|images|helm)[\\/]`)

	reTamperMutatingVerb = regexp.MustCompile(`\b(post|put|delete|patch)\b`)
	reTamperMutatingFlag = regexp.MustCompile(`(-x|--request|-method)` + tamperJSSpace + `+(post|put|delete|patch)\b`)
	reTamperAPIEndpoint  = regexp.MustCompile(`api/v1/(policies|audit-logs)`)
)

func normTamperPath(p string) string {
	return strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
}

func isProtectedPath(p string) string {
	if p == "" {
		return ""
	}
	np := normTamperPath(p)
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
	if reTamperCXHooks.MatchString(np) {
		return "codex-hooks"
	}
	if reTamperAGYHooks.MatchString(np) {
		return "antigravity-hooks"
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
	if reTamperCmdCXHooks.MatchString(c) {
		return "codex-hooks"
	}
	if reTamperCmdAGYHooks.MatchString(c) {
		return "antigravity-hooks"
	}

	if reTamperInstallDirs.MatchString(c) {
		return "solongate-install"
	}

	mutating := reTamperMutatingVerb.MatchString(c) || reTamperMutatingFlag.MatchString(c)
	if mutating && reTamperAPIEndpoint.MatchString(c) {
		return "api-policies-mutation"
	}
	return ""
}

func extractTargetPaths(args map[string]interface{}) []string {
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
	}
	return out
}

func tamperCheck(toolName string, args map[string]interface{}) string {
	tn := strings.ToLower(toolName)

	isExec := tamperGuardToolsExec[tn] || policy.IsExecTool(toolName)

	for _, p := range extractTargetPaths(args) {
		if hit := isProtectedPath(p); hit != "" {
			return `Tamper protection: access to "` + p + `" is blocked (protected: ` + hit + `)`
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