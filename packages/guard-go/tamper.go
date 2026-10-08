// SPDX-License-Identifier: Apache-2.0

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
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/solongate/agent-security/packages/sgpolicy"
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
		if argsInvokeCLI(args) {
			return `Tamper protection: command references protected resource "solongate-cli" — blocked`
		}
	}
	return ""
}

// ── the CLI, invoked ───────────────────────────────────────────────

// `solongate policy delete`, `solongate dlp disable` and the rest change what is enforced,
// so an AGENT running one is disarming the guard through the front door.
//
// It used to be stopped by the CLI itself, which refused whenever an agent marker was in
// the environment. That refused the wrong people: an integrated terminal inherits the
// agent's environment, so a HUMAN typing `solongate` in VS Code or Cursor was turned away
// from their own tool. Here it is a fact about the caller — this check runs on a tool call
// and nowhere else — rather than a guess about its environment, and it holds even if the
// agent allocated a pseudo-terminal, which a TTY check alone does not.
//
// MATCHED AS AN INVOCATION, NOT AS A WORD, and that distinction is the whole design. Every
// other check in this file tests a substring, which is right for a path and wrong here:
//
//	git commit -m "fix the solongate integration docs"
//	python3 -c "print('solongate')"
//	npm install @solongate/proxy
//
// Not one of those runs anything. A substring rule refused all three, which would leave an
// agent unable to so much as mention the product it is working on — a wall rather than a
// guard, and the kind of wall that gets a whole layer switched off. So this asks the only
// question that matters: IS THE CLI THE PROGRAM BEING RUN?
//
// Answering it takes three things, and each one is here because leaving it out was wrong:
//
//   - QUOTE-AWARE SPLITTING. Splitting on `(` to catch `$(solongate policy delete)` also
//     tears `"print('solongate')"` into a fake command whose first token is the CLI. Quotes
//     have to be honoured, and their contents kept as one token stream.
//   - WRAPPERS, AND THEIR ARGUMENTS. `sudo solongate` is the same invocation wearing a hat,
//     and so are `timeout 5 solongate`, `sudo -u root solongate` and `bash -c "solongate
//     policy delete"` — so a wrapper's own flags, flag values and numeric operands are
//     stepped over to reach the program behind them.
//   - RUNNERS THAT ACTUALLY RUN. `pnpm dlx @solongate/proxy policy delete` reaches the CLI
//     without installing it; `npm install @solongate/proxy` names the same package and
//     changes nothing enforced. The subcommand is the difference.
//
// The twin of commandInvokesCLI in the Node hook. The tables below are the same tables, in
// the same order, and a name added to one belongs in the other. One set of cases used to
// drive both, and the half that mattered was the one listing commands a person would
// reasonably ask an agent for while working on this repository: the allowed half, not the
// blocked half. Those cases are gone, so adding a name to one table and not the other is
// now a silent divergence.

var cliBasenames = map[string]bool{
	"solongate": true, "solongate.exe": true,
	"solongate-proxy": true, "solongate-proxy.exe": true,
	"solongate-audit": true, "solongate-audit.exe": true,
}

// Programs that run another program named in their own arguments.
var cliWrappers = map[string]bool{
	"sudo": true, "doas": true, "env": true, "nohup": true, "time": true,
	"command": true, "exec": true, "nice": true, "ionice": true, "stdbuf": true,
	"setsid": true, "xargs": true, "watch": true, "timeout": true, "builtin": true,
	// Shell interpreters belong here for the same reason: `bash -c "solongate policy
	// delete"` runs it as surely as a bare call does, and once quotes are honoured the
	// command sits in the argument list like any other program name.
	"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true,
	"fish": true, "csh": true, "tcsh": true, "ash": true, "busybox": true,
	// AND THE ONES THAT HAND A PROGRAM A TERMINAL. `script -c "solongate policy delete"`
	// allocates a pty and runs the command inside it, which is how an agent would fake the
	// interactive terminal the CLI asks for — the exact case the TTY check cannot see and
	// the reason this guard rule exists at all. A rule that missed `script` would leave the
	// product protected by nothing but the env sniff it replaced.
	"script": true, "unbuffer": true, "expect": true, "socat": true,
	"flock": true, "chroot": true, "su": true, "runuser": true,
	"taskset": true, "strace": true, "ltrace": true, "proot": true,
	"fakeroot": true, "setarch": true, "nsenter": true, "systemd-run": true,
	"xvfb-run": true, "dbus-run-session": true,
	//
	// THE TAIL IS REAL AND THIS DOES NOT CLOSE IT. `screen -dmS name solongate policy
	// delete` bundles its flags, so the scan stops on `name` and reads it as the program;
	// so does any wrapper whose value-taking flag is not in the table below. Enumeration
	// cannot win this outright — what it does is raise the cost, in front of a CLI that
	// still refuses to run without a terminal, and beside the path and basename rules
	// above that catch what such a command would have to touch.
}

// Flags that consume the token after them. Without this, `sudo -u root solongate policy
// delete` stops on `root` and reads it as the program being run.
//
// `-c` is deliberately absent. Its value is a command, which is exactly what the scan needs
// to look at next.
var cliFlagTakesValue = map[string]bool{
	"-u": true, "-g": true, "-U": true, "-n": true, "-i": true, "-I": true,
	"-s": true, "-w": true, "-t": true, "-p": true, "-C": true,
	"--user": true, "--group": true, "--chdir": true,
}

// Runners that exist only to run something: whatever package they are given, they run it.
var cliAlwaysRunners = map[string]bool{"npx": true, "pnpx": true, "bunx": true}

// Package managers, which run something only when asked to. `npm install @solongate/proxy`
// installs a package and enforces nothing; `npm exec @solongate/proxy policy delete` runs
// the CLI. The subcommand is the whole difference.
var cliMaybeRunners = map[string]bool{"npm": true, "pnpm": true, "yarn": true, "bun": true}

var cliRunSubcommands = map[string]bool{"exec": true, "dlx": true, "x": true}

var (
	// A number, with or without a unit: `timeout 5`, `timeout 1.5s`, `nice -n 10`.
	reCLINumberish = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?[a-z]*$`)
	// `VAR=value` in command position is environment, not a program.
	reCLIAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
)

func commandInvokesCLI(cmd string) bool { return commandInvokesCLIDepth(cmd, 0) }

// depth bounds the recursion into a wrapper's quoted argument. `bash -c "sh -c
// 'solongate x'"` is two levels deep and legitimate; the bound is there so a
// pathological nesting cannot spend the guard's whole time budget on one call.
func commandInvokesCLIDepth(cmd string, depth int) bool {
	for _, fields := range splitCLICommands(cmd) {
		if fieldsInvokeCLI(fields, depth) {
			return true
		}
	}
	return false
}

// splitCLICommands breaks a command line into the commands it would run, HONOURING QUOTES,
// and returns each one already split into tokens.
//
// The quotes are the point. sgpolicy.ExtractCommands splits on `&&`, `||`, `;` and `|`
// without looking at them, which is right for a policy rule and wrong here: this also has
// to split on `(`, `)`, `$(` and backticks to catch `$(solongate policy delete)`, and doing
// that blindly turns the inside of `python3 -c "print('solongate')"` into a command whose
// first token is the CLI.
//
// Quote characters are dropped rather than kept, so `bash -c "solongate policy delete"`
// arrives as an ordinary argument list and the wrapper logic can walk straight into it.
// A QUOTED HEREDOC BODY IS TEXT, and reading it as commands is how this rule first
// refused a person writing documentation about the product it protects.
//
// The splitter breaks on backticks, because `solongate policy delete` in backticks IS
// a command substitution. Inside a heredoc whose delimiter is quoted it is not: the
// shell expands nothing there, so backticks are punctuation — which is exactly how
// anybody writing markdown uses them. The command that caught it was a script being
// written to a file:
//
//	cat <<'USAGE'
//	Afterwards `solongate` is a command. Open a new terminal before testing it.
//	USAGE
//
// The backticks around the product's own name made a command out of a sentence, and
// the guard refused to let the file be written. An agent cannot document this product
// if naming it in a code span is a blocked tool call.
//
// AN UNQUOTED DELIMITER STILL COUNTS, because then the shell really does expand: in
// `cat <<EOF` the body is live, `$(solongate policy delete)` in it runs, and skipping
// it would be a hole rather than a fix. The quoting is the whole signal.//
// THE QUOTES MAY ALREADY BE GONE when this runs: extractCommands normalises a command before
// the tamper rules see it, and normalising strips quoting. That is why brackets are TRIMMED
// FROM TOKENS rather than split on. Splitting on a bare `(` turned the stripped form of
// `python3 -c "print('solongate')"` — which arrives as `python3 -c print(solongate)` — into a
// second command whose only token was the CLI's name. Trimming reaches `(solongate policy
// delete)` just as well and leaves `print(solongate)` alone, and it gives the same answer
// whether the quotes survived or not.
//
// What this does NOT catch is a non-shell interpreter asked to spawn a shell:
// `ruby -e 'system("solongate policy delete")'` reads as an ordinary `ruby` invocation. The
// alternative is matching the name anywhere in any argument, which is the wall this whole
// design exists to avoid, and the file paths such a command would have to touch are covered
// by the substring rules above.
func splitCLICommands(cmd string) [][]string {
	out := [][]string{}
	fields := []string{}
	tok := strings.Builder{}
	quote := byte(0)

	endToken := func() {
		if tok.Len() > 0 {
			fields = append(fields, tok.String())
			tok.Reset()
		}
	}
	endCommand := func() {
		endToken()
		if len(fields) > 0 {
			out = append(out, fields)
			fields = []string{}
		}
	}

	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]
		if quote != 0 {
			switch {
			case ch == quote:
				quote = 0
			case ch == '\\' && quote == '"' && i+1 < len(cmd):
				// Keep an escaped character as itself; the shell would.
				i++
				tok.WriteByte(cmd[i])
			default:
				tok.WriteByte(ch)
			}
			continue
		}
		switch {
		case ch == '\'' || ch == '"':
			quote = ch
		case ch == '$' && i+1 < len(cmd) && (cmd[i+1] == '(' || cmd[i+1] == '{'):
			i++
			endCommand()
		// A heredoc: `<<WORD`, `<<'WORD'`, `<<-WORD`. Only the quoted forms are
		// skipped — see the note above — and `<<<` is a herestring, not a heredoc.
		case ch == '<' && i+1 < len(cmd) && cmd[i+1] == '<' && (i+2 >= len(cmd) || cmd[i+2] != '<'):
			delim, quoted, after := readHeredocDelimiter(cmd, i+2)
			if !quoted {
				i = after - 1 // the body is live; carry on reading it as commands
				continue
			}
			endCommand()
			i = skipHeredocBody(cmd, after, delim) - 1
		case strings.IndexByte("|&;\n\r`", ch) >= 0:
			endCommand()
		case ch == ' ' || ch == '\t':
			endToken()
		default:
			tok.WriteByte(ch)
		}
	}
	endCommand()
	return out
}

// fieldsInvokeCLI decides whether one command's token list runs the CLI.
func fieldsInvokeCLI(fields []string, depth int) bool {
	wrapped := false
	for i := 0; i < len(fields); i++ {
		tok := strings.Trim(fields[i], "(){}\"'")
		if tok == "" {
			continue
		}
		if reCLIAssignment.MatchString(tok) {
			wrapped = true // environment, and the program is further along
			continue
		}
		if wrapped {
			// A wrapper's own flags and operands are not the program it runs.
			if strings.HasPrefix(tok, "-") {
				if cliFlagTakesValue[strings.ToLower(tok)] {
					i++
				}
				continue
			}
			if reCLINumberish.MatchString(tok) {
				continue
			}
		}
		// filepath.ToSlash is NOT used here, and that is deliberate: it converts only on
		// Windows, so on Linux `..\\bin\\solongate policy delete` kept its backslashes,
		// filepath.Base returned the whole string, and the invocation went unseen — while
		// the Node twin, which replaces unconditionally, caught it. A guard has to give the
		// same answer on every platform, and a Windows-shaped path in a command is a real
		// shape whoever is typing it.
		// A WRAPPER'S QUOTED ARGUMENT IS A COMMAND, and now that this reads the raw
		// text rather than the normalised one, it arrives whole:
		//
		//	bash -c "solongate policy delete"
		//
		// splits to `bash`, `-c`, and the single token `solongate policy delete`,
		// because the quotes keep the spaces. Its basename is the whole string and
		// matches nothing. While the quotes were being stripped upstream this worked by
		// accident; on the raw text it has to be done on purpose.
		//
		// Only after a wrapper, which is what keeps it from being a substring rule
		// wearing a disguise: `git commit -m "fix the solongate docs"` stops at `git`
		// and never looks inside the message, and so does `sudo git commit -m "…"`.
		if wrapped && depth < 8 && strings.ContainsAny(tok, " \t") {
			if commandInvokesCLIDepth(tok, depth+1) {
				return true
			}
		}

		base := strings.ToLower(path.Base(strings.ReplaceAll(tok, "\\", "/")))
		switch {
		case cliWrappers[base]:
			wrapped = true
		case cliBasenames[base]:
			return true
		case cliAlwaysRunners[base]:
			return restRunsCLIPackage(fields[i+1:])
		case cliMaybeRunners[base]:
			return maybeRunnerRunsCLI(fields[i+1:])
		default:
			// AN UNQUOTED PATH SPLITS ON ITS OWN SPACES. `C:\\Program Files\\SolonGate\\solongate
			// policy delete` arrives (quotes already normalised away) as the tokens `C:\\Program`
			// and `Files\\SolonGate\\solongate`, and stopping at the first of them misses the
			// second, where the program name actually is.
			//
			// So a PATH-SHAPED token is not the end of the scan. The continuation stops at the
			// first token that is not path-shaped, which is what keeps it narrow:
			// `/usr/bin/git commit -m "fix the solongate docs"` stops at `commit`, and
			// `./scripts/build.sh solongate` stops at its argument rather than reading it as a
			// program.
			if strings.ContainsAny(tok, "/\\") {
				continue
			}
			// An ordinary program. Its arguments are its own business, and that is what
			// keeps `git commit -m "fix the solongate docs"` running.
			return false
		}
	}
	return false
}

// maybeRunnerRunsCLI looks past a package manager's flags for the subcommand that decides
// whether anything is being run at all.
func maybeRunnerRunsCLI(rest []string) bool {
	for j := 0; j < len(rest); j++ {
		if strings.HasPrefix(rest[j], "-") {
			continue
		}
		if cliRunSubcommands[strings.ToLower(rest[j])] {
			return restRunsCLIPackage(rest[j+1:])
		}
		return false // install, add, view — naming the package is not running it
	}
	return false
}

// restRunsCLIPackage reports whether a runner was pointed at this product.
func restRunsCLIPackage(rest []string) bool {
	for _, t := range rest {
		tl := strings.ToLower(t)
		if strings.Contains(tl, "solongate/proxy") || cliBasenames[tl] {
			return true
		}
	}
	return false
}

// readHeredocDelimiter reads the word after `<<` and reports whether it was quoted.
// It returns the index just past the delimiter.
func readHeredocDelimiter(cmd string, i int) (delim string, quoted bool, after int) {
	if i < len(cmd) && cmd[i] == '-' { // <<-DELIM strips leading tabs from the body
		i++
	}
	for i < len(cmd) && (cmd[i] == ' ' || cmd[i] == '\t') {
		i++
	}
	if i >= len(cmd) {
		return "", false, i
	}
	if q := cmd[i]; q == '\'' || q == '"' {
		i++
		start := i
		for i < len(cmd) && cmd[i] != q {
			i++
		}
		delim = cmd[start:i]
		if i < len(cmd) {
			i++ // past the closing quote
		}
		return delim, true, i
	}
	start := i
	for i < len(cmd) && !strings.ContainsRune(" \t\n\r;|&", rune(cmd[i])) {
		i++
	}
	return cmd[start:i], false, i
}

// skipHeredocBody returns the index just past the line that closes the heredoc, or the
// end of the string when nothing closes it — an unterminated heredoc has no commands
// after it either way.
func skipHeredocBody(cmd string, i int, delim string) int {
	if delim == "" {
		return len(cmd)
	}
	// The body starts on the line after the redirect.
	nl := strings.IndexByte(cmd[i:], '\n')
	if nl < 0 {
		return len(cmd)
	}
	i += nl + 1
	for i < len(cmd) {
		end := strings.IndexByte(cmd[i:], '\n')
		line := cmd[i:]
		next := len(cmd)
		if end >= 0 {
			line = cmd[i : i+end]
			next = i + end + 1
		}
		// <<- allows the closing delimiter to be indented with tabs.
		if strings.Trim(line, " \t\r") == delim {
			return next
		}
		i = next
	}
	return len(cmd)
}

// argsInvokeCLI reports whether any command field in a tool call runs the CLI.
// ON THE RAW COMMAND, WHICH IS WHY THIS DOES NOT LIVE WITH THE RULES ABOVE.
//
// Every other tamper rule reads the NORMALISED command, and normalising strips
// quoting — which is right for them, because a path is the same path whether or not
// somebody quoted it. This check cannot use it. Two signals it depends on are
// destroyed by the time the normalised text arrives:
//
//	<<'EOF'   becomes   <<EOF
//
// and a heredoc's quoting is the entire difference between a body that is text and a
// body the shell expands. Reading the stripped form, the installer's own usage text —
// a quoted heredoc with the product named in a markdown code span — looked like a
// command substitution, and writing that file was a blocked tool call.
//
// So this runs on the field values as the caller sent them.
func argsInvokeCLI(args map[string]interface{}) bool {
	for _, k := range sgpolicy.SortedKeys(args) {
		if !cliCommandFields[strings.ToLower(k)] {
			continue
		}
		if s, ok := args[k].(string); ok && commandInvokesCLI(s) {
			return true
		}
	}
	return false
}

// The same fields sgpolicy treats as commands. Named here rather than imported
// because that list is unexported, and a copy that drifts is a rule that stops
// seeing a whole class of tool call — so the conformance suite drives both.
var cliCommandFields = map[string]bool{
	"command": true, "cmd": true, "function": true, "script": true, "shell": true,
}
