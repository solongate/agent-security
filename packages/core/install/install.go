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
	guardBin := p.GuardBinaryPath()

	st, err := stageOpencodePlugin(p, guardBin)
	if err != nil {
		return Result{Message: err.Error()}
	}

	claude, err := planClaude(p)
	if err != nil {
		return Result{Message: err.Error()}
	}
	antigravity, agErr := planAntigravity(p)
	codex, cxErr := planCodex(p)

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

	if runtime.GOOS != "windows" {
		if err := writeFileAtomic(filepath.Join(p.HooksDir, LauncherName), []byte(launcherScript(guardBin))); err != nil {
			return fail(err.Error())
		}

		_ = os.Chmod(filepath.Join(p.HooksDir, LauncherName), 0o700)
		_ = os.MkdirAll(filepath.Join(p.SGDir, BeatDirName), config.DirMode)
	}

	InstallGoBinaries()
	if !Exists(guardBin) {
		return fail("no guard binary for this platform; run ./scripts/install.sh from a checkout to build one")
	}

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

	shimmed := InstallClaudeShim(p)

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
			"The OpenCode plugin already on this device was re-registered but NOT rewritten: this build could not find it to copy. Run ./scripts/install.sh from a checkout to replace it.")
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

	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func ClearUpdateCheckStamp() bool {
	err := os.Remove(GlobalPaths().UpdateCheckPath)
	return err == nil || os.IsNotExist(err)
}