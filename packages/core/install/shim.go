// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const (
	shimBegin = "# >>> SolonGate shield (auto secret redaction) >>>"
	shimEnd   = "# <<< SolonGate shield <<<"
)

var shimBlockRe = regexp.MustCompile(`(?s)` + regexp.QuoteMeta(shimBegin) + `.*?` + regexp.QuoteMeta(shimEnd) + `\r?\n?`)

func InstallClaudeShim(p Paths) bool {
	real := resolveRealClaude()
	if real == "" {
		return false
	}
	gobin := filepath.ToSlash(p.GuardBinaryPath())

	sg := filepath.ToSlash(filepath.Join(BinDir(), "solongate"))
	block := `claude() {
  if [ -x "` + sg + `" ] && [ -x "` + gobin + `" ]; then
    "` + sg + `" run -- "` + gobin + `" shield -- "` + real + `" "$@"
  elif [ -x "` + gobin + `" ]; then
    "` + gobin + `" shield -- "` + real + `" "$@"
  else
    "` + real + `" "$@"
  fi
}`
	if runtime.GOOS == "windows" {

		block = `function claude {
  if ((Test-Path "` + sg + `.exe") -and (Test-Path "` + gobin + `.exe")) { & "` + sg + `.exe" run -- "` + gobin + `" shield -- "` + real + `" @args }
  elseif (Test-Path "` + gobin + `.exe") { & "` + gobin + `" shield -- "` + real + `" @args }
  else { & "` + real + `" @args }
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

func RemoveClaudeShim() {
	for _, file := range shimTargets() {
		_ = writeShimBlock(file, "")
	}
}

func writeShimBlock(file, block string) error {
	var content string
	if b, err := os.ReadFile(file); err == nil {
		content = string(b)
	} else if os.IsNotExist(err) && block == "" {
		return nil
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

func shimTargets() []string {
	if runtime.GOOS == "windows" {
		out, err := exec.Command(windowsPowerShell(), "-NoProfile", "-Command", "$PROFILE.CurrentUserAllHosts").Output()
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

// windowsPowerShell resolves the fixed, unwriteable System32 location of
// powershell.exe instead of trusting a PATH lookup, falling back to the bare
// name only if that location doesn't exist on this machine.
func windowsPowerShell() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	p := root + `\System32\WindowsPowerShell\v1.0\powershell.exe`
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return "powershell"
}

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

	for _, ext := range []string{".cmd", ".exe", ".bat"} {
		for _, l := range lines {
			if strings.HasSuffix(strings.ToLower(l), ext) {
				return l
			}
		}
	}
	return lines[0]
}