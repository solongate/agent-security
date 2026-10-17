// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/solongate/agent-security/packages/core/config"
)

type Result struct {
	OK      bool
	Message string

	Notes []string
}

var ErrNoLogin = errors.New("no login on this device")

func Install() Result {
	p := GlobalPaths()

	node, err := resolveNode(p)
	if err != nil {
		return Result{Message: err.Error()}
	}

	st, err := stageHooks(p, node)
	if err != nil {
		return Result{Message: err.Error()}
	}

	claude, err := planClaude(p, node)
	if err != nil {
		return Result{Message: err.Error()}
	}
	antigravity, agErr := planAntigravity(p, node)
	codex, cxErr := planCodex(p, node)

	if err := os.MkdirAll(p.HooksDir, 0o755); err != nil {
		return Result{Message: err.Error()}
	}
	if err := os.MkdirAll(p.ClaudeDir, 0o755); err != nil {
		return Result{Message: err.Error()}
	}

	UnlockProtected()

	fail := func(msg string) Result {
		if !locksDisabled() {
			LockProtected()
		}
		return Result{Message: msg}
	}

	for _, name := range []string{GuardHookName, auditHookName, stopHookName, tokensHookName, shieldHookName, dlpModuleName} {
		body, ok := st.hooks[name]
		if !ok {
			continue
		}
		if err := writeFileAtomic(filepath.Join(p.HooksDir, name), body); err != nil {
			return fail(err.Error())
		}
	}

	if runtime.GOOS != "windows" {
		if err := writeFileAtomic(filepath.Join(p.HooksDir, LauncherName), []byte(launcherScript(node))); err != nil {
			return fail(err.Error())
		}

		_ = os.Chmod(filepath.Join(p.HooksDir, LauncherName), 0o755)
		_ = os.MkdirAll(filepath.Join(p.SGDir, BeatDirName), config.DirMode)
	}

	goBins := InstallGoBinaries()

	RecordInstallSource()

	if err := claude.commit(); err != nil {
		return fail(err.Error())
	}

	if agErr == nil {
		_ = antigravity.commit()
	}
	if cxErr == nil {
		_ = codex.commit()
	}
	if st.plugin != nil {
		_ = installOpencodePlugin(p, st.plugin)
	}

	shimmed := InstallClaudeShim(filepath.Join(p.HooksDir, shieldHookName))

	if !locksDisabled() {
		LockProtected()
	}

	res := Result{OK: true, Message: "guard installed (open a new session)"}
	if !shimmed {

		res.Notes = append(res.Notes,
			"Secrets in tool calls are masked, but NOT in the prompt: the `claude` shell shim could not be installed (Claude Code is not on PATH, or no shell profile was found). Tool-call enforcement is unaffected.")
	}
	if st.sourceMissing {

		res.Notes = append(res.Notes,
			"The hook programs already on this device were re-registered but NOT rewritten: this build could not find the hook files to copy. Run ./scripts/shell/install.sh from a checkout to replace them.")
	}

	if len(goBins) == 0 {
		res.Notes = append(res.Notes,
			"No native binary for this platform, so the guard runs its Node implementation: same policy, a few tens of milliseconds slower per tool call.")
	}
	return res
}

func Uninstall() Result {
	p := GlobalPaths()
	UnlockProtected()
	RemoveClaudeShim()

	_ = removeAntigravityRegistration(p)
	_ = removeCodexRegistration(p)
	_ = removeOpencodePlugin(p)

	if err := removeClaudeRegistration(p); err != nil {
		return Result{Message: err.Error()}
	}
	return Result{OK: true, Message: "guard removed (open a new session)"}
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".solongate-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}

	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func ClearUpdateCheckStamp() bool {
	err := os.Remove(GlobalPaths().UpdateCheckPath)
	return err == nil || os.IsNotExist(err)
}