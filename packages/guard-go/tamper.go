package main

// Hardcoded tamper protection.
//
// Runs BEFORE policy evaluation. Cannot be disabled by editing policies.
// Even if all policy rules are removed, these stay enforced. The only switch is
// the per-project cloud `selfProtect` flag, applied by the caller — and that
// fails safe: it stays ON when the cache cannot be read.
//
// Ported from the Node hook line for line so both implementations deny the same
// call for the same reason. Nothing here is allowed to be "tightened up" in
// translation: a path form this misses is a disarm vector, so the three shapes
// of check — absolute prefix, glob, and a regex fallback that ignores where in
// the tree the file sits — are all kept, even where they overlap.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/codeyevsky/solongate/sgpolicy"
)

// Kept from the original even though nothing reads it: the write/exec split is
// the documented shape of this layer, and the write set is what a future
// write-only variant of the check would key off. The exec set IS live, in
// tamperCheck.
var tamperGuardToolsWrite = map[string]bool{
	"write": true, "edit": true, "multiedit": true, "notebookedit": true,
	"create": true, "update": true, "delete": true, "remove": true, "move": true,
	"rename": true, "copy": true,
	"filesystem": true, "fs_write": true, "fs_edit": true, "str_replace_editor": true,
}

var tamperGuardToolsExec = map[string]bool{
	"bash": true, "powershell": true, "shell": true, "exec": true, "run": true,
	"eval": true, "cmd": true,
}

const (
	tamperSG = "/.solongate"
	tamperCC = "/.claude"
	// The OTHER two guarded clients register the guard in their own config, so those
	// files are disarm vectors exactly like ~/.claude/settings.json: deleting our
	// entry from ~/.codex/hooks.json (or setting `[features] hooks = false` /
	// flipping a hook's trust state in ~/.codex/config.toml) turns the guard off for
	// Codex; the same holds for ~/.gemini/config/hooks.json and Antigravity.
	tamperCX  = "/.codex"
	tamperAGY = "/.gemini/config"

	tamperInstall = "/solongate"
)

// resolve(homedir()) in the original: absolute, separator-normalised, lowered.
// filepath.Abs is Node's resolve — it joins a relative value onto the working
// directory and cleans the result, so a trailing slash or a `.` segment cannot
// shift every prefix comparison below by one character.
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
	// The cloud credential (contains the API key) — never readable via a tool.
	tamperHome + tamperSG + "/cloud-guard.json",
}

// Matched with matchPathGlob, shared with the policy layer. Note what that
// means for the `*` entries below: once a pattern contains `**`, matchPathGlob
// splits on `**` and asks whether the path CONTAINS each remaining segment, so
// the `*` in `.policy-cache-*.json` is a literal asterisk there, not a wildcard.
// `~/.solongate/.policy-cache-claude-code.json` therefore does not match as a
// PATH — it is caught by tamperBasenames on the command side only. That is the
// Node hook's behaviour exactly, gap included; reproduced rather than fixed so
// the two implementations cannot disagree. Widening it is a change to make in
// both at once.
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
	"**" + tamperSG + "/.pi-config-cache.json",
	"**" + tamperSG + "/cloud-guard.json",
	"**" + tamperSG + "/.opa-wasm-*.json",
	"**" + tamperSG + "/.ratelimit-*.json",
	// The guard BINARY. The hook runs whatever is at this path once it prints
	// the expected version for --sg-version, and then honours its exit code, so
	// a two-line stub here allows every call while `solongate doctor` still
	// reports a native guard in use. It was the one file in this directory the
	// tamper check did not cover.
	"**" + tamperSG + "/bin/**",
	// Whether this machine is under somebody else's policy. Everything the
	// guard hardens for a guest is decided from this file, so it is the file to
	// rewrite if you wanted the hardening off.
	"**" + tamperSG + "/.fleet.json",
	// Persistent host data (DB + audit JSONL) at ~/.solongate/data
	"**" + tamperSG + "/data/**",
	// Customer install layout (zip extracted as solongate/)
	"**" + tamperInstall + "/compose/**",
	"**" + tamperInstall + "/data/**",
	"**" + tamperInstall + "/images/**",
	"**" + tamperInstall + "/helm/**",
	"**" + tamperInstall + "/solongate.exe",
	"**" + tamperInstall + "/setup.sh",
}

// Matched as SUBSTRINGS of a shell command, not as path components, which is
// why the entries are already lowercase — the command is lowered before the
// comparison.
var tamperBasenames = []string{
	"guard.mjs", "audit.mjs", "stop.mjs", "shield.mjs",
	"policy.json",
	// Prefixes (substring match) so per-agent runtime state can't be deleted or
	// rewritten via a shell command either — `.policy-cache-<agent>.json`,
	// `.ratelimit-<agent>.json`, `.opa-wasm-<agent>.json`. Editing these could
	// otherwise flip enforcement off until the next cloud refresh; deleting just
	// forces a refetch, but neither should be reachable from an agent tool call.
	".policy-cache", ".ratelimit-", ".opa-wasm-", ".pi-config-cache",
	// The guard binary and the fleet marker, on the command side too. The path
	// globs above catch a Write or an Edit; this catches `cp /bin/true
	// ~/.solongate/bin/solongate-guard`, which is the same disarm through a
	// different tool.
	"solongate-guard", ".fleet.json",
	"cloud-guard.json",
	// Customer install: DB and wizard exe
	"solongate.db", "solongate.exe",
}

var tamperPathFields = map[string]bool{
	"file_path": true, "path": true, "target_file": true, "notebook_path": true,
	"dest": true, "destination": true, "source": true, "src": true,
	"from": true, "to": true,
	"directory": true, "dir": true, "folder": true,
	// Antigravity CLI file-tool arg names (camelCase, lowercased here): its
	// write/read/list tools carry the path in these, so tamper protection sees it.
	"targetfile": true, "absolutepath": true, "filepath": true,
}

// JavaScript's `\s`, spelled out. Go's `\s` is only [\t\n\f\r ], so porting the
// class verbatim would let `curl -X<U+00A0>POST …/api/v1/policies` through a
// check the Node hook catches. This layer must never get LOOSER in translation,
// so the wider class is reproduced exactly (U+180E is excluded: it left `\s` in
// Unicode 6.3 and modern JS engines follow).
const tamperJSSpace = `[\t\n\v\f\r \x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]`

// Fallbacks for a protected file living anywhere, not just under $HOME: a
// checkout, a container mount, another user's tree. All operate on an
// already-lowercased, forward-slash path, so no (?i) is needed.
var (
	reTamperCCSettings = regexp.MustCompile(`/\.claude/settings(\.local)?\.json$`)
	reTamperSGHooks    = regexp.MustCompile(`/\.solongate/hooks(/|$)`)
	reTamperCXHooks    = regexp.MustCompile(`/\.codex/(hooks\.json|config\.toml)$`)
	reTamperAGYHooks   = regexp.MustCompile(`/\.gemini/config/hooks\.json$`)

	// The command forms accept a run of EITHER separator, because a command
	// string is never normalised the way a path field is: `~\.claude\\settings.json`
	// has to hit the same rule as `~/.claude/settings.json`.
	reTamperCmdCCSettings = regexp.MustCompile(`\.claude[\\/]+settings(\.local)?\.json`)
	reTamperCmdSGHooks    = regexp.MustCompile(`\.solongate[\\/]+hooks`)
	reTamperCmdCXHooks    = regexp.MustCompile(`\.codex[\\/]+(hooks\.json|config\.toml)`)
	reTamperCmdAGYHooks   = regexp.MustCompile(`\.gemini[\\/]+config[\\/]+hooks\.json`)
	reTamperInstallDirs   = regexp.MustCompile(`[\\/]solongate[\\/]+(compose|data|images|helm)[\\/]`)

	// Mutating API calls against policies / audit-logs endpoints. The verb can
	// appear bare (`curl -XPOST`, a method argument) or behind a flag.
	reTamperMutatingVerb = regexp.MustCompile(`\b(post|put|delete|patch)\b`)
	reTamperMutatingFlag = regexp.MustCompile(`(-x|--request|-method)` + tamperJSSpace + `+(post|put|delete|patch)\b`)
	reTamperAPIEndpoint  = regexp.MustCompile(`api/v1/(policies|audit-logs)`)
)

func normTamperPath(p string) string {
	return strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
}

// isProtectedPath returns the pattern that matched, or "" for no hit. The
// returned string goes into the deny reason, so it names the RULE rather than
// repeating the path.
func isProtectedPath(p string) string {
	if p == "" {
		return ""
	}
	np := normTamperPath(p)
	for _, abs := range tamperProtectedAbs {
		// `+ "/"` and not a plain prefix: `~/.solongate/hooks` must protect the
		// directory's contents without also swallowing `~/.solongate/hooks-backup`,
		// which is not ours.
		if np == abs || strings.HasPrefix(np, abs+"/") {
			return abs
		}
	}
	for _, g := range tamperProtectedGlobs {
		if sgpolicy.MatchPathGlob(np, g) {
			return g
		}
	}
	if reTamperCCSettings.MatchString(np) {
		return "settings.json"
	}
	if reTamperSGHooks.MatchString(np) {
		return "solongate-hooks"
	}
	if reTamperCXHooks.MatchString(np) {
		return "codex-hooks"
	}
	if reTamperAGYHooks.MatchString(np) {
		return "antigravity-hooks"
	}
	return ""
}

// commandTargetsProtected returns the protected resource a shell command names,
// or "" for none. Substring matching, deliberately: a command has no argument
// structure this layer can trust, and `rm -rf ~/.solongate/hooks` has to be
// caught whether it arrives as one token, three, or spelled through a variable.
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
	if reTamperCmdCXHooks.MatchString(c) {
		return "codex-hooks"
	}
	if reTamperCmdAGYHooks.MatchString(c) {
		return "antigravity-hooks"
	}
	// Customer install dirs
	if reTamperInstallDirs.MatchString(c) {
		return "solongate-install"
	}
	// Mutating API calls against policies / audit-logs endpoints
	mutating := reTamperMutatingVerb.MatchString(c) || reTamperMutatingFlag.MatchString(c)
	if mutating && reTamperAPIEndpoint.MatchString(c) {
		return "api-policies-mutation"
	}
	return ""
}

// extractTargetPaths collects the paths a call declares as its TARGET — never
// the free-form body, which would false-positive on any file that merely
// mentions a protected path in its text.
//
// Keys are walked SORTED rather than in payload order. Go map iteration is
// randomised, and the first hit decides which path is quoted in the deny reason,
// so insertion order would make the same denial read differently run to run.
// Whether a call is denied does not depend on the order: every candidate is
// checked until one hits.
func extractTargetPaths(args map[string]interface{}) []string {
	out := []string{}
	if args == nil {
		return out
	}
	for _, k := range sgpolicy.SortedKeys(args) {
		v := args[k]
		if tamperPathFields[strings.ToLower(k)] {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		// Claude Code's MultiEdit and the Antigravity batch tools carry their real
		// targets one level down, in an array of {file_path: …} objects. Only that
		// one level, as in the original — a path buried deeper is the policy
		// layer's business, not this one's.
		if arr, ok := v.([]interface{}); ok {
			for _, item := range arr {
				obj, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				for _, k2 := range sgpolicy.SortedKeys(obj) {
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

// tamperCheck returns the deny reason, or "" when the call is clear of the
// protection files.
func tamperCheck(toolName string, args map[string]interface{}) string {
	tn := strings.ToLower(toolName)
	// Both halves are kept: the exact-name set catches `run` and `cmd`, which the
	// substring pattern would also catch, but the pattern is what catches
	// `bash_tool`, `mcp__shell__exec` and the rest of the long tail of vendor
	// names. isExecTool is that same pattern, shared with the policy layer.
	isExec := tamperGuardToolsExec[tn] || sgpolicy.IsExecTool(toolName)
	// ANY tool that targets a protected path is blocked — READ as well as write.
	// An AI must not even read SolonGate's own protection files. This is enforced
	// at the tool boundary; the hooks themselves are run by node directly (not via
	// a Claude Code tool), so node still loads/executes them normally.
	// Check the tool's TARGET PATH fields only (file_path, path, …) — never the
	// free-form content/body, which would false-positive on any file that merely
	// mentions a protected path in its text.
	for _, p := range extractTargetPaths(args) {
		if hit := isProtectedPath(p); hit != "" {
			return `Tamper protection: access to "` + p + `" is blocked (protected: ` + hit + `)`
		}
	}
	if isExec {
		for _, cmd := range sgpolicy.ExtractCommands(args) {
			if hit := commandTargetsProtected(cmd); hit != "" {
				return `Tamper protection: command references protected resource "` + hit + `" — blocked`
			}
		}
	}
	return ""
}
