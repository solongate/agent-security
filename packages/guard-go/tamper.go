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

// Matched with MatchPathGlob, shared with the policy layer, which compiles the
// pattern to a regex — so the `*` in the per-agent entries below is a real
// wildcard here and those files match by path.
//
// THE JAVASCRIPT TWIN'S matchPathGlob DOES NOT DO THAT. It splits on `**` and
// substring-tests each remaining piece, which leaves that `*` literal, so the
// per-agent files did not match by path there at all. isProtectedPath now covers
// them by basename in both, which is what closed it — see the block at the end
// of that function.
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
	"**" + tamperSG + "/cloud-guard.json",
	// `.opa-wasm-*.json` and `.pi-config-cache.json` were listed here. Nothing writes
	// either -- the WASM bundle came from a service, and the prompt-injection layer is not
	// in this build -- so a lock on a file that cannot exist reads as protection and is not.
	// The rate-limit counter. The extension is `.log`, not `.json` — this glob said
	// `.ratelimit-*.json` and matched nothing the limiter writes. Protected anyway by
	// the basename prefix rule, but a glob matching no real file is a line somebody will
	// one day rely on.
	"**" + tamperSG + "/.ratelimit-*",
	// The guard BINARY. The hook runs whatever is at this path once it prints
	// the expected version for --sg-version, and then honours its exit code, so
	// a two-line stub here allows every call while `solongate doctor` still
	// reports a native guard in use. It was the one file in this directory the
	// tamper check did not cover.
	"**" + tamperSG + "/bin/**",
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
	// rewritten via a shell command either — `.policy-cache-<agent>.json` and
	// `.ratelimit-<agent>.log`. Deleting the counter resets the rate-limit window, so a
	// limit of N calls/minute becomes N per deletion.
	".policy-cache", ".ratelimit-",
	// The guard binary, on the command side too. The path
	// globs above catch a Write or an Edit; this catches `cp /bin/true
	// ~/.solongate/bin/solongate-guard`, which is the same disarm through a
	// different tool.
	"solongate-guard",
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
	// The binary's DIRECTORY, for the same reason the hooks one above is covered:
	// `rm -rf ~/.solongate/bin` names no protected basename and matches no `/bin/**`
	// glob. Not a disarm on its own — with no binary the hook decides for itself — but
	// an agent should not be able to take the fast path away silently.
	reTamperSGBin    = regexp.MustCompile(`/\.solongate/bin(/|$)`)
	reTamperCXHooks  = regexp.MustCompile(`/\.codex/(hooks\.json|config\.toml)$`)
	reTamperAGYHooks = regexp.MustCompile(`/\.gemini/config/hooks\.json$`)

	// The command forms accept a run of EITHER separator, because a command
	// string is never normalised the way a path field is: `~\.claude\\settings.json`
	// has to hit the same rule as `~/.claude/settings.json`.
	reTamperCmdCCSettings = regexp.MustCompile(`\.claude[\\/]+settings(\.local)?\.json`)
	reTamperCmdSGHooks    = regexp.MustCompile(`\.solongate[\\/]+hooks`)
	reTamperCmdSGBin      = regexp.MustCompile(`\.solongate[\\/]+bin`)
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
	if reTamperSGBin.MatchString(np) {
		return "solongate-bin"
	}
	if reTamperCXHooks.MatchString(np) {
		return "codex-hooks"
	}
	if reTamperAGYHooks.MatchString(np) {
		return "antigravity-hooks"
	}
	// Anything in ~/.solongate whose name the command side already protects.
	//
	// BELT AND BRACES HERE, AND THE ACTUAL FIX IN THE JAVASCRIPT TWIN. The two
	// path-glob implementations do not agree, which is the thing worth knowing:
	//
	//   Go   MatchPathGlob compiles the pattern to a regex, so the `*` in the
	//        per-agent entry above is a real wildcard and the file matches.
	//   JS   matchPathGlob splits the pattern on `**` and then asks whether the
	//        path CONTAINS each remaining piece, so that `*` stays a literal
	//        asterisk — and no real filename contains one.
	//
	// So the hook was reachable by PATH where this binary was not. Deleting the
	// policy cache through a shell command was refused on both sides; a Write tool
	// aimed at the same path went through on the hook, and every coding agent has
	// one. Overwriting it with `{}` leaves the guard with no policy to apply, so
	// the next call is allowed, and the refresh that would repair it is debounced
	// for three seconds. Measured on the hook: Write, Edit and Read all allowed
	// before this, all refused after.
	//
	// This block is here anyway, for two reasons. The pair is meant to decide
	// alike and a machine gets whichever one it has. And resting a protection on
	// a subtlety of a glob engine that the policy layer also uses — and may
	// legitimately change — is not where it should rest.
	//
	// Scoped to the directory on purpose. The names are matched as PREFIXES, and
	// `policy.json` is one somebody's own project may well use; protecting it
	// everywhere would block a file that has nothing to do with this product.
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
	if reTamperCmdSGBin.MatchString(c) {
		return "solongate-bin"
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
