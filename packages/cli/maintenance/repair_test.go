// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build !windows

package maintenance

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/core/install"
)

// isolatedRepairHome sets up the same env a fresh, empty home needs for
// install.Repair() to run entirely against a fake filesystem, matching the
// pattern already used by packages/core/install's own Repair tests.
func isolatedRepairHome(t *testing.T) string {
	t.Helper()
	home := newHome(t)
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("SOLONGATE_NO_OS_LOCK", "1")
	return home
}

func TestRefuseUnderSudoNotRefusedWhenInternal(t *testing.T) {
	t.Setenv("SOLONGATE_INTERNAL", "1")
	code, refused := refuseUnderSudo()
	if refused {
		t.Error("refuseUnderSudo() refused even with SOLONGATE_INTERNAL=1 set, want allowed")
	}
	if code != 0 {
		t.Errorf("refuseUnderSudo() code = %d, want 0 when allowed", code)
	}
}

func TestRefuseUnderSudoNotRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root, this case is covered by TestRefuseUnderSudoAsRoot instead")
	}
	code, refused := refuseUnderSudo()
	if refused {
		t.Error("refuseUnderSudo() refused while not running as root, want allowed")
	}
	if code != 0 {
		t.Errorf("refuseUnderSudo() code = %d, want 0 when allowed", code)
	}
}

func TestRefuseUnderSudoAsRoot(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() != 0 {
		t.Skip("not running as root on a non-windows system, cannot exercise the refusal branch")
	}
	var code int
	var refused bool
	out := captureStderrFD(t, func() {
		code, refused = refuseUnderSudo()
	})
	if !refused {
		t.Error("refuseUnderSudo() did not refuse while running as root, want refused")
	}
	if code != 1 {
		t.Errorf("refuseUnderSudo() code = %d, want 1 when refused", code)
	}
	if !strings.Contains(out, "Do not run") {
		t.Errorf("refuseUnderSudo() refusal message missing, got: %s", out)
	}
}

func TestRunRepairOnAFreshEmptyHome(t *testing.T) {
	isolatedRepairHome(t)
	t.Setenv("SOLONGATE_INTERNAL", "1")

	rep := install.Repair()
	wantCode := 0
	if !rep.OK {
		wantCode = 1
	}

	var code int
	out := captureStderrFD(t, func() {
		code = RunRepair(nil)
	})

	if code != wantCode {
		t.Errorf("RunRepair(nil) = %d, want %d (install.Repair().OK = %v)", code, wantCode, rep.OK)
	}
	if out == "" {
		t.Error("RunRepair(nil) printed nothing, want at least the repair outcome")
	}
}