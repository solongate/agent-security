// SPDX-License-Identifier: Apache-2.0

package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// The auto-shield `claude` shim.
//
// Secret redaction on the LLM path, made automatic for every TERMINAL Claude
// session: a marked block in the shell config redefines `claude` to run through
// the shield, which masks secrets in the request body — including the typed
// prompt and any file or tool text in context — before it reaches the model. The
// hooks cannot do that; they only ever see tool calls, never the prompt.
//
// This is the SECONDARY layer. The main protection is the hook-based
// guard/policy, which is why installing the shim prints nothing and why an
// install that cannot find `claude` on PATH is not a failed install.

const (
	shimBegin = "# >>> SolonGate shield (auto secret redaction) >>>"
	shimEnd   = "# <<< SolonGate shield <<<"
)

var shimBlockRe = regexp.MustCompile(`(?s)` + regexp.QuoteMeta(shimBegin) + `.*?` + regexp.QuoteMeta(shimEnd) + `\r?\n?`)

// InstallClaudeShim wires the shim into every shell config on this machine.
// It reports false when Claude Code is not on PATH — there is nothing to wrap,
// which is a reason to skip the shim and not a reason to fail an install.
func InstallClaudeShim(shieldPath string) bool {
	real := resolveRealClaude()
	if real == "" {
		return false
	}
	p := GlobalPaths()
	node, err := resolveNode(p)
	if err != nil {
		return false
	}
	node = filepath.ToSlash(node)
	shield := filepath.ToSlash(shieldPath)

	// THROUGH `solongate run` WHEN THERE IS ONE, because this is the only
	// moment SolonGate can become the agent's parent, and being its parent is
	// the only way the protected paths are enforced by the kernel rather than
	// by matching strings in a tool call.
	//
	// The order is run -> shield -> claude. The confinement goes on outermost,
	// so it covers the shield and everything the agent starts; the shield sits
	// between because it has to be the thing holding the HTTP connection.
	//
	// `|| exec` is the fallback and it is deliberate: an install whose CLI has
	// gone missing should still get the prompt shield rather than losing the
	// `claude` command altogether. `solongate run` refuses to start anything
	// unconfined on its own account, so the weaker path is only ever taken when
	// the strong one is not on the machine at all. And with nothing protected,
	// `run` prints nothing and costs one exec.
	sg := filepath.ToSlash(filepath.Join(BinDir(), "solongate"))
	block := `claude() {
  if [ -x "` + sg + `" ]; then
    "` + sg + `" run -- "` + node + `" "` + shield + `" -- "` + real + `" "$@"
  else
    "` + node + `" "` + shield + `" -- "` + real + `" "$@"
  fi
}`
	if runtime.GOOS == "windows" {
		// PowerShell needs the call operator to run a quoted path, the same reason
		// the hook commands carry one.
		block = `function claude {
  if (Test-Path "` + sg + `.exe") { & "` + sg + `.exe" run -- "` + node + `" "` + shield + `" -- "` + real + `" @args }
  else { & "` + node + `" "` + shield + `" -- "` + real + `" @args }
}`
	}
	block = shimBegin + "\n" + block + "\n" + shimEnd

	targets := shimTargets()
	if len(targets) == 0 {
		return false
	}
	for _, file := range targets {
		_ = writeShimBlock(file, block)
	}
	return true
}

// RemoveClaudeShim strips the block cleanly, leaving the rest of the shell
// config as it was.
func RemoveClaudeShim() {
	for _, file := range shimTargets() {
		_ = writeShimBlock(file, "")
	}
}

// writeShimBlock removes any block already there before appending, so running an
// install twice cannot leave two definitions of `claude` in one file.
func writeShimBlock(file, block string) error {
	var content string
	if b, err := os.ReadFile(file); err == nil {
		content = string(b)
	}
	content = shimBlockRe.ReplaceAllString(content, "")
	if block != "" {
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		content += block + "\n"
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	return os.WriteFile(file, []byte(content), 0o644)
}

// shimTargets is the shell configuration to inject into, per platform. Only
// files that already exist on POSIX: creating a .zshrc on a machine that has no
// zsh would be this installer inventing a shell configuration.
func shimTargets() []string {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("powershell", "-NoProfile", "-Command", "$PROFILE.CurrentUserAllHosts").Output()
		if err != nil {
			return nil
		}
		prof := strings.TrimSpace(string(out))
		if prof == "" {
			return nil
		}
		return []string{prof}
	}
	home := GlobalPaths().Home
	var targets []string
	for _, name := range []string{".bashrc", ".zshrc", ".profile"} {
		f := filepath.Join(home, name)
		if Exists(f) {
			targets = append(targets, f)
		}
	}
	return targets
}

// resolveRealClaude finds the binary the shim will wrap, or "" when Claude Code
// is not installed.
func resolveRealClaude() string {
	finder := "which"
	if runtime.GOOS == "windows" {
		finder = "where"
	}
	out, err := exec.Command(finder, "claude").Output()
	if err != nil {
		return ""
	}
	var lines []string
	for _, l := range strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	if runtime.GOOS != "windows" {
		return lines[0]
	}
	// The shield spawns the real claude through cmd.exe, which can only run a
	// .cmd or .exe — NOT the npm-generated claude.ps1 or the extension-less bash
	// shim. `where` lists all of them, so the runnable one has to be picked out.
	for _, ext := range []string{".cmd", ".exe", ".bat"} {
		for _, l := range lines {
			if strings.HasSuffix(strings.ToLower(l), ext) {
				return l
			}
		}
	}
	return lines[0]
}
