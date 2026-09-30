package install

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Where the hook programs come from, and which node runs them.
//
// The TypeScript has neither question to answer: its hooks sit next to it in the
// package, and the node running the installer is the node the hooks will run
// under (process.execPath). This binary is not node and does not carry a copy of
// the hooks — a second copy of a 297 KB bundle that self-updates from the cloud
// is a guarantee of drift — so both have to be found, and a failure to find
// either has to fail the install rather than register something that cannot run.

// ErrNoHookSource means this binary could not find the hook programs it is
// supposed to install. It is a refusal, not a fallback: writing a registration
// that points at a file this install cannot produce is the half-install the
// whole package exists to avoid.
var ErrNoHookSource = errors.New(
	"the packaged hook files were not found next to this binary — run `npx @solongate/proxy repair` (the npm package carries them)")

// ErrNoNode means no node binary could be found. The hooks are .mjs programs;
// without node they cannot run at all, so a registration naming one would be a
// registration that silently never fires.
var ErrNoNode = errors.New(
	"node was not found on PATH — the guard hooks run under node; install Node 20+ (or set SOLONGATE_NODE) and try again")

// hookSourceDir finds the npm package's hooks folder.
//
// Deliberately several candidates, tried in the order they can be trusted: an
// explicit override, then the binary's own folder, then the npm package the
// binary ships beside, then a development checkout. A directory only qualifies
// if it holds ALL of the files an install writes — a folder with half of them is
// the state that produces a half-install, so it is not a candidate at all.
func hookSourceDir() (string, bool) {
	for _, dir := range hookSourceCandidates() {
		if hasAllHookSources(dir) {
			return dir, true
		}
	}
	return "", false
}

func hookSourceCandidates() []string {
	var out []string
	if v := os.Getenv("SOLONGATE_HOOKS_DIR"); v != "" {
		out = append(out, v)
	}
	if exe, err := os.Executable(); err == nil {
		// The npm bin folder is a symlink farm, so the executable's own path says
		// nothing about where its package is until the link is resolved.
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		dir := filepath.Dir(exe)
		out = append(out,
			filepath.Join(dir, "hooks"),
			filepath.Join(dir, "..", "hooks"),
			// A platform package (@solongate/guard-<os>-<cpu>) sits beside the main
			// package in the same scope folder.
			filepath.Join(dir, "..", "proxy", "hooks"),
			filepath.Join(dir, "..", "@solongate", "proxy", "hooks"),
		)
		out = append(out, packageCandidates(dir)...)
	}
	// The working directory matters for a checkout: `go run ./...` leaves the
	// binary in a build cache that is nowhere near the source tree.
	if cwd, err := os.Getwd(); err == nil {
		out = append(out, packageCandidates(cwd)...)
	}
	return out
}

// packageCandidates walks up from a directory looking for the npm package: an
// installed copy under node_modules, or the checkout it is built from.
func packageCandidates(start string) []string {
	var out []string
	dir := start
	for i := 0; i < 8; i++ {
		out = append(out,
			filepath.Join(dir, "node_modules", "@solongate", "proxy", "hooks"),
			filepath.Join(dir, "packages", "proxy", "hooks"),
		)
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return out
}

func hasAllHookSources(dir string) bool {
	for _, name := range []string{auditHookName, stopHookName, tokensHookName, shieldHookName, dlpModuleName, opencodePluginName} {
		if !Exists(filepath.Join(dir, name)) {
			return false
		}
	}
	return Exists(filepath.Join(dir, bundledGuardName)) || Exists(filepath.Join(dir, GuardHookName))
}

// readGuardSource prefers the pre-bundled guard so the one installed file works
// with no node_modules beside it, and falls back to the source in a dev tree.
func readGuardSource(dir string) ([]byte, error) {
	if b, err := os.ReadFile(filepath.Join(dir, bundledGuardName)); err == nil {
		return b, nil
	}
	return os.ReadFile(filepath.Join(dir, GuardHookName))
}

// staged is every byte an install will write, read and assembled BEFORE
// anything on disk is touched. A missing source or an unreadable file is then a
// refusal with the machine untouched, rather than a guard.mjs that landed and an
// audit.mjs that did not.
type staged struct {
	// hooks maps a basename under ~/.solongate/hooks to its contents. Empty when
	// the sources could not be found and the install is re-registering hooks that
	// are already on disk.
	hooks map[string][]byte
	// plugin is the OpenCode module with the node path baked in, nil when there
	// is no source for it.
	plugin []byte
	// sourceMissing records that the hook programs were not rewritten, so the
	// report can say so instead of implying they were.
	sourceMissing bool
}

// stageHooks reads everything the install needs.
//
// The one branch worth explaining is what happens when the sources are missing.
// A repair whose most common cause is a deleted REGISTRATION can still be done
// with the hooks that are already installed, and refusing it would leave a
// machine unguarded to protect a rule about file provenance. So the hooks are
// left as they are, the registration is rewritten, and the caller is told the
// programs were not refreshed. If the guard itself is gone there is nothing to
// register and the install refuses.
func stageHooks(p Paths, node string) (staged, error) {
	st := staged{hooks: map[string][]byte{}}

	dir, ok := hookSourceDir()
	if !ok {
		for _, name := range []string{GuardHookName, auditHookName, stopHookName} {
			if !Exists(filepath.Join(p.HooksDir, name)) {
				return staged{}, ErrNoHookSource
			}
		}
		st.sourceMissing = true
		return st, nil
	}

	guard, err := readGuardSource(dir)
	if err != nil {
		return staged{}, err
	}
	st.hooks[GuardHookName] = guard
	for _, name := range []string{auditHookName, stopHookName, tokensHookName, shieldHookName, dlpModuleName} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return staged{}, err
		}
		st.hooks[name] = b
	}

	plugin, err := os.ReadFile(filepath.Join(dir, opencodePluginName))
	if err != nil {
		return staged{}, err
	}
	st.plugin = bakeNodePath(plugin, node)
	return st, nil
}

// bakeNodePath writes the node binary into the OpenCode plugin.
//
// The path goes in in its NATIVE form with the backslashes escaped, not
// forward-slashed the way the hook command strings are, because that is what the
// npm installer bakes in and the plugin file is replaced wholesale by whichever
// implementation ran last. Both forms work; writing a different one would make
// the two rewrite the file on every install for no reason.
//
// It cannot use its own process.execPath: OpenCode loads plugins inside its own
// Bun-based executable, so execPath there is the opencode binary, and spawning
// THAT with the guard as an argument re-runs opencode with nonsense arguments,
// which exits non-2, which the shim reads as "allowed". The result was a guard
// that never guarded and never said so.
//
// The value is escaped for a JavaScript string literal — a Windows path is full
// of backslashes and an unescaped one turns the plugin into a syntax error,
// which OpenCode skips silently.
func bakeNodePath(src []byte, node string) []byte {
	escaped := strings.ReplaceAll(node, `\`, `\\`)
	return []byte(strings.Replace(string(src), "__SOLONGATE_NODE__", escaped, 1))
}

// resolveNode finds the node binary the registrations will name.
//
// It has to be an ABSOLUTE path, never bare `node`. Clients run hooks in a
// non-interactive environment whose PATH frequently lacks node on macOS (nvm,
// fnm, homebrew) and Linux; bare `node` then fails with "command not found" and
// the guard silently never runs.
//
// PATH comes first because that is the node the npm package would have recorded
// — process.execPath is whatever node ran it — so both implementations end up
// naming the same binary and neither keeps rewriting the other's registration.
// A node already recorded in a registration is the fallback, not the preference:
// it is proof that node existed once, which is worth more than nothing when PATH
// has none, but it can also be a version that has since been removed.
// The value is the OS-native path: process.execPath is native too, and the
// callers that need forward slashes (every hook command string) convert at the
// point of use.
func resolveNode(p Paths) (string, error) {
	if v := os.Getenv("SOLONGATE_NODE"); v != "" && Exists(v) {
		return v, nil
	}
	if found, err := exec.LookPath("node"); err == nil {
		// process.execPath is the resolved path of the running binary, so a
		// homebrew or alternatives symlink resolves the same way here.
		if real, err := filepath.EvalSymlinks(found); err == nil {
			found = real
		}
		if abs, err := filepath.Abs(found); err == nil {
			found = abs
		}
		return found, nil
	}
	if n := nodeFromRegistration(p); n != "" {
		return n, nil
	}
	return "", ErrNoNode
}

// nodeFromRegistration reads the node binary out of a registration already on
// disk. Every client's command string starts with the quoted interpreter, so the
// first quoted token is it.
func nodeFromRegistration(p Paths) string {
	for _, cmd := range []string{
		claudeRegisteredCommand(p),
		codexRegisteredCommand(p),
		antigravityRegisteredCommand(p),
	} {
		if n := firstQuoted(cmd); n != "" && Exists(n) {
			return filepath.FromSlash(n)
		}
	}
	return ""
}

func firstQuoted(s string) string {
	start := strings.IndexByte(s, '"')
	if start < 0 {
		return ""
	}
	rest := s[start+1:]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}
