// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build !windows

package confine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/sandbox"
)

func TestSandboxUsage(t *testing.T) {
	u := sandboxUsage()
	if !strings.Contains(u, "solongate sandbox") {
		t.Errorf("sandboxUsage() should mention solongate sandbox, got: %s", u)
	}
	if !strings.Contains(u, "--explain") {
		t.Errorf("sandboxUsage() should mention --explain, got: %s", u)
	}
}

func TestSandboxAgentEmptyArgvShowsUsage(t *testing.T) {
	var code int
	out := captureStderr(t, func() {
		code = SandboxAgent(nil)
	})
	if code != 1 {
		t.Errorf("SandboxAgent(nil) = %d, want 1", code)
	}
	if !strings.Contains(out, "solongate sandbox") {
		t.Errorf("SandboxAgent(nil) output=%q, want usage mentioning solongate sandbox", out)
	}
}

func TestSandboxAgentExplainDelegatesToExplainBox(t *testing.T) {
	boxErr := sandbox.BoxAvailable()

	for _, arg := range []string{"--explain", "explain"} {
		t.Run(arg, func(t *testing.T) {
			newHome(t)
			var code int
			out := captureStderr(t, func() {
				code = SandboxAgent([]string{arg})
			})
			if boxErr != nil {
				if code != 1 {
					t.Errorf("SandboxAgent([%q]) = %d, want 1 (no closed box here)", arg, code)
				}
				if !strings.Contains(out, "No closed box on this machine") {
					t.Errorf("SandboxAgent([%q]) output=%q, want it to say no closed box", arg, out)
				}
				return
			}
			if code != 0 {
				t.Errorf("SandboxAgent([%q]) = %d, want 0, output=%q", arg, code, out)
			}
			if !strings.Contains(out, "The closed box") {
				t.Errorf("SandboxAgent([%q]) output=%q, want it to describe the closed box", arg, out)
			}
		})
	}
}

func TestSandboxAgentListDelegatesToListBoxes(t *testing.T) {
	for _, arg := range []string{"list", "ls"} {
		t.Run(arg, func(t *testing.T) {
			newHome(t)
			var code int
			out := captureStderr(t, func() {
				code = SandboxAgent([]string{arg})
			})
			if code != 0 {
				t.Errorf("SandboxAgent([%q]) = %d, want 0, output=%q", arg, code, out)
			}
			if !strings.Contains(out, "No sandboxes") {
				t.Errorf("SandboxAgent([%q]) output=%q, want it to say no sandboxes", arg, out)
			}
		})
	}
}

func TestListBoxesEmpty(t *testing.T) {
	newHome(t)

	var code int
	out := captureStderr(t, func() {
		code = listBoxes()
	})
	if code != 0 {
		t.Errorf("listBoxes() = %d, want 0", code)
	}
	if !strings.Contains(out, "No sandboxes") {
		t.Errorf("listBoxes() output=%q, want it to say no sandboxes", out)
	}
}

func TestListBoxesNonEmpty(t *testing.T) {
	newHome(t)
	dir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	box, err := client.New().Settings.SandboxCreate(ctx, dir, "my-label", true)
	if err != nil {
		t.Fatalf("SandboxCreate() error: %v", err)
	}

	var code int
	out := captureStderr(t, func() {
		code = listBoxes()
	})
	if code != 0 {
		t.Errorf("listBoxes() = %d, want 0, output=%q", code, out)
	}
	if !strings.Contains(out, box.ID) {
		t.Errorf("listBoxes() output=%q, want it to list box id %q", out, box.ID)
	}
	if !strings.Contains(out, dir) {
		t.Errorf("listBoxes() output=%q, want it to list dir %q", out, dir)
	}
	if !strings.Contains(out, "my-label") {
		t.Errorf("listBoxes() output=%q, want it to list the label", out)
	}
	if !strings.Contains(out, "network on") {
		t.Errorf("listBoxes() output=%q, want it to say network on", out)
	}
}

func TestExplainBoxNoArgv(t *testing.T) {
	newHome(t)

	boxErr := sandbox.BoxAvailable()
	var code int
	out := captureStderr(t, func() {
		code = explainBox(nil)
	})

	if boxErr != nil {
		if code != 1 {
			t.Errorf("explainBox(nil) = %d, want 1 (no closed box here)", code)
		}
		if !strings.Contains(out, "No closed box on this machine") {
			t.Errorf("explainBox(nil) output=%q, want it to say no closed box", out)
		}
		return
	}

	if code != 0 {
		t.Errorf("explainBox(nil) = %d, want 0, output=%q", code, out)
	}
	if !strings.Contains(out, "No id given") {
		t.Errorf("explainBox(nil) output=%q, want it to say no id given", out)
	}
	if !strings.Contains(out, "mount namespace (bubblewrap)") {
		t.Errorf("explainBox(nil) output=%q, want it to describe the mechanism", out)
	}
}

func TestExplainBoxWithUnknownID(t *testing.T) {
	newHome(t)

	boxErr := sandbox.BoxAvailable()
	var code int
	out := captureStderr(t, func() {
		code = explainBox([]string{"999"})
	})

	if boxErr != nil {
		if code != 1 {
			t.Errorf("explainBox([999]) = %d, want 1 (no closed box here)", code)
		}
		if !strings.Contains(out, "No closed box on this machine") {
			t.Errorf("explainBox([999]) output=%q, want it to say no closed box", out)
		}
		return
	}

	if code != 1 {
		t.Errorf("explainBox([999]) = %d, want 1 (unknown sandbox against empty store)", code)
	}
	if !strings.Contains(out, "there is no sandbox") {
		t.Errorf("explainBox([999]) output=%q, want it to say there is no sandbox", out)
	}
}