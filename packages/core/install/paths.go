// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"os"
	"path/filepath"

	"github.com/solongate/agent-security/packages/core/config"
)

const (
	GuardHookName = "guard.mjs"
	auditHookName = "audit.mjs"
	stopHookName  = "stop.mjs"

	tokensHookName = "tokens.mjs"

	shieldHookName = "shield.mjs"

	dlpModuleName = "dlp.mjs"

	bundledGuardName = "guard.bundled.mjs"

	opencodePluginName = "opencode-plugin.mjs"
)

type Paths struct {
	Home     string
	SGDir    string
	HooksDir string

	ClaudeDir    string
	SettingsPath string

	BackupPath string

	AntigravityDir        string
	AntigravityHooksPath  string
	AntigravityBackupPath string

	CodexDir        string
	CodexHooksPath  string
	CodexBackupPath string
	CodexConfigPath string

	OpencodeDir        string
	OpencodePluginDir  string
	OpencodePluginPath string

	UpdateCheckPath string
}

func GlobalPaths() Paths {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	claudeDir := filepath.Join(home, ".claude")
	antigravityDir := filepath.Join(home, ".gemini", "config")
	codexDir := absOr(os.Getenv("CODEX_HOME"), filepath.Join(home, ".codex"))
	opencodeDir := filepath.Join(absOr(os.Getenv("XDG_CONFIG_HOME"), filepath.Join(home, ".config")), "opencode")

	return Paths{
		Home:     home,
		SGDir:    config.Dir(),
		HooksDir: config.HooksDir(),

		ClaudeDir:    claudeDir,
		SettingsPath: filepath.Join(claudeDir, "settings.json"),
		BackupPath:   filepath.Join(claudeDir, "settings.solongate.bak"),

		AntigravityDir:        antigravityDir,
		AntigravityHooksPath:  filepath.Join(antigravityDir, "hooks.json"),
		AntigravityBackupPath: filepath.Join(antigravityDir, "hooks.solongate.bak"),

		CodexDir:        codexDir,
		CodexHooksPath:  filepath.Join(codexDir, "hooks.json"),
		CodexBackupPath: filepath.Join(codexDir, "hooks.solongate.bak"),
		CodexConfigPath: filepath.Join(codexDir, "config.toml"),

		OpencodeDir:        opencodeDir,
		OpencodePluginDir:  filepath.Join(opencodeDir, "plugins"),
		OpencodePluginPath: filepath.Join(opencodeDir, "plugins", "solongate.js"),

		UpdateCheckPath: filepath.Join(config.Dir(), ".hook-update-check"),
	}
}

func absOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return fallback
	}
	return abs
}

func Exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func (p Paths) GuardPath() string { return filepath.Join(p.HooksDir, GuardHookName) }

func (p Paths) protectedTargets() []string {
	return []string{
		filepath.Join(p.HooksDir, GuardHookName),
		filepath.Join(p.HooksDir, auditHookName),
		filepath.Join(p.HooksDir, stopHookName),
		filepath.Join(p.HooksDir, shieldHookName),

		p.SettingsPath,
		filepath.Join(p.HooksDir, tokensHookName),

		filepath.Join(p.HooksDir, dlpModuleName),

		filepath.Join(p.HooksDir, LauncherName),
		p.AntigravityHooksPath,
		p.CodexHooksPath,
		p.OpencodePluginPath,

		filepath.Join(BinDir(), guardBinaryName()),
	}
}

func guardBinaryName() string { return goBinaryNames()[0] }

func LockProtected() {
	for _, f := range GlobalPaths().protectedTargets() {
		config.LockFile(f)
	}
}

func UnlockProtected() {
	for _, f := range GlobalPaths().protectedTargets() {
		config.UnlockFile(f)
	}
}

func locksDisabled() bool { return os.Getenv("SOLONGATE_NO_OS_LOCK") == "1" }