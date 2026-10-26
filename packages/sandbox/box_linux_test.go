// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build linux

package sandbox

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultBoxRuntimeIsNonEmpty(t *testing.T) {
	if len(DefaultBoxRuntime()) == 0 {
		t.Error("DefaultBoxRuntime() should list at least the base system paths")
	}
}

func TestBoxAvailableMatchesBwrapPresence(t *testing.T) {
	_, lookErr := exec.LookPath("bwrap")
	err := BoxAvailable()
	if lookErr != nil {
		if err == nil || !strings.Contains(err.Error(), "bwrap") {
			t.Errorf("bwrap is missing, expected BoxAvailable to say so, got %v", err)
		}
	}
}

func TestBoxLaunchRequiresAgentExec(t *testing.T) {
	if err := BoxAvailable(); err != nil {
		t.Skip("bwrap is not usable on this machine: " + err.Error())
	}
	_, err := BoxLaunch(BoxPlan{Workspace: t.TempDir()}, nil)
	if err == nil {
		t.Fatal("expected an error when AgentExec is empty")
	}
}

func TestBoxLaunchRequiresAbsoluteWorkspace(t *testing.T) {
	if err := BoxAvailable(); err != nil {
		t.Skip("bwrap is not usable on this machine: " + err.Error())
	}
	_, err := BoxLaunch(BoxPlan{Workspace: "relative/path", AgentExec: []string{"true"}}, nil)
	if err == nil {
		t.Fatal("expected an error for a relative workspace")
	}
}

func TestBoxLaunchRequiresReadableWorkspace(t *testing.T) {
	if err := BoxAvailable(); err != nil {
		t.Skip("bwrap is not usable on this machine: " + err.Error())
	}
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	_, err := BoxLaunch(BoxPlan{Workspace: missing, AgentExec: []string{"true"}}, nil)
	if err == nil {
		t.Fatal("expected an error for a workspace that does not exist")
	}
}

func TestBoxAgentUnknownBinary(t *testing.T) {
	_, _, err := BoxAgent("sg-definitely-not-a-real-binary", nil)
	if err == nil {
		t.Fatal("expected an error for a binary that is not on PATH")
	}
}

func TestBoxAgentResolvesKnownBinary(t *testing.T) {
	tree, exec_, err := BoxAgent("ls", []string{"-la"})
	if err != nil {
		t.Fatal(err)
	}
	if tree == "" {
		t.Error("expected a non-empty package root")
	}
	if len(exec_) < 2 || exec_[len(exec_)-1] != "-la" {
		t.Errorf("expected the original args to be preserved, got %v", exec_)
	}
}
