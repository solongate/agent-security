// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package sandbox

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
)

type Plan struct {
	Deny []string

	Workspace string

	RuntimeRead []string

	RuntimeWrite []string

	Immutable []string
}

func (p Plan) Confined() bool { return p.Workspace != "" || len(p.Deny) > 0 }

func (p Plan) Allowlist() bool { return p.Workspace != "" }

type Report struct {
	Mechanism string

	Enforced bool

	Notes []string

	ABI int

	Err error
}

var ErrUnsupported = errors.New("no OS-level confinement is implemented for this platform")

func DefaultRuntimeRead() []string {
	return []string{

		"/usr", "/bin", "/lib", "/lib64", "/sbin", "/opt",

		"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf",
		"/etc/localtime", "/etc/ssl", "/etc/pki", "/etc/ca-certificates",
		"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d",

		"/proc/self", "/sys/devices/system/cpu",
	}
}

func DefaultRuntimeWrite(home string) []string { return nil }

func DefaultRuntimeDevices() []string {
	return []string{
		"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom",
		"/dev/tty", "/dev/pts", "/dev/ptmx",
	}
}

func LaunchTargetPaths(name string) []string {
	if name == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || p == "/" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}

	resolved, err := exec.LookPath(name)
	if err != nil {

		return nil
	}
	add(filepath.Dir(resolved))

	real, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		return out
	}
	add(packageRoot(filepath.Dir(real)))
	return out
}

func packageRoot(dir string) string {
	for i := 0; i < 4; i++ {
		base := filepath.Base(dir)
		parent := filepath.Dir(dir)
		if base == "bin" || base == "lib" || base == "dist" || base == "build" {
			dir = parent
			continue
		}

		if filepath.Base(parent) == "node_modules" || strings.HasPrefix(filepath.Base(parent), "@") {
			return dir
		}
		return dir
	}
	return dir
}