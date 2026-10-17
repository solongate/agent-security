// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package shared

import (
	"os"
	"path/filepath"
	"strings"
)

const SandboxEnv = "SOLONGATE_SANDBOX"

const (
	SandboxModeRun = "run"
	SandboxModeBox = "box"
)

func SandboxMarker(mode, version string) string { return mode + ":" + version }

func InSandbox() bool { return os.Getenv(SandboxEnv) != "" }

func SandboxMode() string {
	v := os.Getenv(SandboxEnv)
	if v == "" {
		return ""
	}
	if i := strings.IndexByte(v, ':'); i >= 0 {
		return v[:i]
	}

	return SandboxModeRun
}

func VerifiedInSandbox(protectedPaths []string) (confined, conclusive bool) {
	switch SandboxMode() {
	case "":

		return false, true

	case SandboxModeBox:
		b, err := os.ReadFile("/proc/1/comm")
		if err != nil {

			return false, false
		}
		init := strings.TrimSpace(string(b))
		switch init {
		case "systemd", "init", "launchd":

			return false, true
		case "":
			return false, false
		default:
			return true, true
		}

	default:
		for _, p := range protectedPaths {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			f, err := os.Open(filepath.Clean(p))
			if err == nil {

				_ = f.Close()
				return false, true
			}
			if os.IsNotExist(err) {
				continue
			}

			return true, true
		}
		return false, false
	}
}