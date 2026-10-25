// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package client

import (
	"context"
	"os"
	"testing"
)

func TestGetSecurityLayersReturnsPatternsAndCurrentLayers(t *testing.T) {
	newHome(t)
	s := Settings{&Client{}}
	out, err := s.GetSecurityLayers(context.Background())
	if err != nil {
		t.Fatalf("GetSecurityLayers: %v", err)
	}
	if out.Layers.DLP.Mode != LayerOff {
		t.Errorf("a fresh machine should have DLP off, got %q", out.Layers.DLP.Mode)
	}
	if len(out.AvailablePatterns) != len(dlpPatternNames) {
		t.Errorf("got %d available patterns, want %d", len(out.AvailablePatterns), len(dlpPatternNames))
	}
}

func TestSetSecurityLayersPersistsAndRecordsHistory(t *testing.T) {
	newHome(t)
	s := Settings{&Client{}}

	layers := SecurityLayers{}
	layers.RateLimit.Mode = LayerBlock
	layers.RateLimit.PerMinute = 3

	got, err := s.SetSecurityLayers(context.Background(), layers)
	if err != nil {
		t.Fatalf("SetSecurityLayers: %v", err)
	}
	if got.RateLimit.PerMinute != 3 {
		t.Errorf("PerMinute = %d, want 3", got.RateLimit.PerMinute)
	}

	again, err := s.GetSecurityLayers(context.Background())
	if err != nil {
		t.Fatalf("GetSecurityLayers: %v", err)
	}
	if again.Layers.RateLimit.PerMinute != 3 {
		t.Errorf("the layers did not persist across a re-read: %+v", again.Layers)
	}

	history, err := s.GetRateLimitHistory(context.Background())
	if err != nil {
		t.Fatalf("GetRateLimitHistory: %v", err)
	}
	if len(history) != 1 || history[0].Minute != 3 {
		t.Errorf("history = %+v, want one entry with Minute 3", history)
	}
}

func TestClearRateLimitHistory(t *testing.T) {
	newHome(t)
	s := Settings{&Client{}}
	layers := SecurityLayers{}
	layers.RateLimit.PerMinute = 1
	if _, err := s.SetSecurityLayers(context.Background(), layers); err != nil {
		t.Fatalf("SetSecurityLayers: %v", err)
	}
	if err := s.ClearRateLimitHistory(context.Background()); err != nil {
		t.Fatalf("ClearRateLimitHistory: %v", err)
	}
	history, err := s.GetRateLimitHistory(context.Background())
	if err != nil {
		t.Fatalf("GetRateLimitHistory: %v", err)
	}
	if len(history) != 0 {
		t.Errorf("got %d entries after clearing, want 0", len(history))
	}
}

func TestGetGuardStatus(t *testing.T) {
	newHome(t)
	original := GuardVersions
	t.Cleanup(func() { GuardVersions = original })
	s := Settings{&Client{}}

	installedLow := 3
	installedCurrent := 5
	cases := []struct {
		name         string
		latest       int
		installed    *int
		wantUpToDate bool
		wantOutdated int
	}{
		{"never installed", 5, nil, false, 0},
		{"behind", 5, &installedLow, false, 1},
		{"current", 5, &installedCurrent, true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			GuardVersions = func() (int, *int) { return c.latest, c.installed }
			out, err := s.GetGuardStatus(context.Background())
			if err != nil {
				t.Fatalf("GetGuardStatus: %v", err)
			}
			if out.Latest != c.latest {
				t.Errorf("Latest = %d, want %d", out.Latest, c.latest)
			}
			if out.UpToDate != c.wantUpToDate {
				t.Errorf("UpToDate = %v, want %v", out.UpToDate, c.wantUpToDate)
			}
			if out.OutdatedCount != c.wantOutdated {
				t.Errorf("OutdatedCount = %d, want %d", out.OutdatedCount, c.wantOutdated)
			}
			if out.DeviceCount != 1 {
				t.Errorf("DeviceCount = %d, want 1", out.DeviceCount)
			}
		})
	}
}

func TestSelfProtectionDefaultsToEnabled(t *testing.T) {
	newHome(t)
	s := Settings{&Client{}}
	enabled, err := s.GetSelfProtection(context.Background())
	if err != nil {
		t.Fatalf("GetSelfProtection: %v", err)
	}
	if !enabled {
		t.Error("self protection should default to enabled")
	}
}

func TestSetSelfProtectionPersists(t *testing.T) {
	newHome(t)
	s := Settings{&Client{}}
	if _, err := s.SetSelfProtection(context.Background(), false); err != nil {
		t.Fatalf("SetSelfProtection: %v", err)
	}
	got, err := s.GetSelfProtection(context.Background())
	if err != nil {
		t.Fatalf("GetSelfProtection: %v", err)
	}
	if got {
		t.Error("self protection should be false after being explicitly disabled")
	}
}

func TestProtectedPathsRoundTrip(t *testing.T) {
	newHome(t)
	s := Settings{&Client{}}
	paths, err := s.ProtectedPaths(context.Background())
	if err != nil {
		t.Fatalf("ProtectedPaths: %v", err)
	}
	if paths != nil {
		t.Errorf("fresh machine should have no protected paths, got %v", paths)
	}

	want := []string{"/etc", "/home/x/.ssh"}
	if err := s.SetProtectedPaths(context.Background(), want); err != nil {
		t.Fatalf("SetProtectedPaths: %v", err)
	}
	got, err := s.ProtectedPaths(context.Background())
	if err != nil {
		t.Fatalf("ProtectedPaths: %v", err)
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSandboxLifecycle(t *testing.T) {
	newHome(t)
	s := Settings{&Client{}}
	dirA := t.TempDir()
	dirB := t.TempDir()

	boxes, err := s.Sandboxes(context.Background())
	if err != nil {
		t.Fatalf("Sandboxes: %v", err)
	}
	if boxes != nil {
		t.Errorf("a fresh machine should have no sandboxes, got %v", boxes)
	}

	created, err := s.SandboxCreate(context.Background(), dirA, "first", true)
	if err != nil {
		t.Fatalf("SandboxCreate: %v", err)
	}
	if created.ID != "001" || created.Dir != dirA || !created.Network || created.Label != "first" {
		t.Errorf("created sandbox = %+v", created)
	}

	if _, err := s.SandboxCreate(context.Background(), dirA, "dup", false); err == nil {
		t.Error("creating a sandbox on a directory already confined should fail")
	}

	second, err := s.SandboxCreate(context.Background(), dirB, "second", false)
	if err != nil {
		t.Fatalf("SandboxCreate: %v", err)
	}
	if second.ID != "002" {
		t.Errorf("second sandbox id = %q, want 002", second.ID)
	}

	got, err := s.Sandbox(context.Background(), "1")
	if err != nil {
		t.Fatalf("Sandbox: %v", err)
	}
	if got.ID != "001" {
		t.Errorf("Sandbox(\"1\") did not normalize to 001: got %+v", got)
	}

	if _, err := s.Sandbox(context.Background(), "999"); err == nil {
		t.Error("looking up a nonexistent sandbox should fail")
	}

	if err := s.SandboxUpdate(context.Background(), "1", dirB, "renamed", true); err == nil {
		t.Error("updating sandbox 001 to a directory already used by 002 should fail")
	}

	dirC := t.TempDir()
	if err := s.SandboxUpdate(context.Background(), "1", dirC, "renamed", true); err != nil {
		t.Fatalf("SandboxUpdate: %v", err)
	}
	updated, err := s.Sandbox(context.Background(), "1")
	if err != nil {
		t.Fatalf("Sandbox: %v", err)
	}
	if updated.Dir != dirC || updated.Label != "renamed" || !updated.Network {
		t.Errorf("sandbox was not updated: %+v", updated)
	}

	if err := s.SandboxUpdate(context.Background(), "999", dirC, "x", false); err == nil {
		t.Error("updating a nonexistent sandbox should fail")
	}

	if err := s.SandboxDelete(context.Background(), "1"); err != nil {
		t.Fatalf("SandboxDelete: %v", err)
	}
	if _, err := s.Sandbox(context.Background(), "1"); err == nil {
		t.Error("sandbox 001 should be gone after deletion")
	}
	if err := s.SandboxDelete(context.Background(), "1"); err == nil {
		t.Error("deleting an already-deleted sandbox should fail")
	}
}

func TestSandboxOperationsWithoutAnySandboxesYetError(t *testing.T) {
	newHome(t)
	s := Settings{&Client{}}
	if err := s.SandboxUpdate(context.Background(), "1", t.TempDir(), "x", false); err == nil {
		t.Error("updating a sandbox before any exist should fail")
	}
	if err := s.SandboxDelete(context.Background(), "1"); err == nil {
		t.Error("deleting a sandbox before any exist should fail")
	}
}

func TestRequireSandbox(t *testing.T) {
	newHome(t)
	s := Settings{&Client{}}
	on, err := s.RequireSandbox(context.Background())
	if err != nil {
		t.Fatalf("RequireSandbox: %v", err)
	}
	if on {
		t.Error("RequireSandbox should default to false")
	}

	if err := s.SetRequireSandbox(context.Background(), true); err != nil {
		t.Fatalf("SetRequireSandbox: %v", err)
	}
	on, err = s.RequireSandbox(context.Background())
	if err != nil {
		t.Fatalf("RequireSandbox: %v", err)
	}
	if !on {
		t.Error("RequireSandbox should be true after being set")
	}
}

func TestGetLocalLogsDefaultsWhenUnset(t *testing.T) {
	newHome(t)
	s := Settings{&Client{}}
	cfg, err := s.GetLocalLogs(context.Background())
	if err != nil {
		t.Fatalf("GetLocalLogs: %v", err)
	}
	if !cfg.Enabled || cfg.Path != DefaultLogDir() {
		t.Errorf("default local logs = %+v, want enabled at %q", cfg, DefaultLogDir())
	}
}

func TestSetLocalLogsRoundTripAndClear(t *testing.T) {
	newHome(t)
	s := Settings{&Client{}}
	custom := t.TempDir()

	got, err := s.SetLocalLogs(context.Background(), LocalLogsConfig{Enabled: false, Path: custom})
	if err != nil {
		t.Fatalf("SetLocalLogs: %v", err)
	}
	if got.Path != custom || got.Enabled {
		t.Errorf("got %+v, want disabled at %q", got, custom)
	}

	again, err := s.GetLocalLogs(context.Background())
	if err != nil {
		t.Fatalf("GetLocalLogs: %v", err)
	}
	if again.Path != custom || again.Enabled {
		t.Errorf("custom local logs did not persist: %+v", again)
	}

	cleared, err := s.SetLocalLogs(context.Background(), LocalLogsConfig{Path: ""})
	if err != nil {
		t.Fatalf("SetLocalLogs: %v", err)
	}
	if cleared.Path != DefaultLogDir() || !cleared.Enabled {
		t.Errorf("clearing the path should fall back to the default: %+v", cleared)
	}
}

func TestSettingsStoreLazilyCreatesSecurityBlock(t *testing.T) {
	newHome(t)
	s := Settings{&Client{}}
	if err := s.SetProtectedPaths(context.Background(), []string{"/etc"}); err != nil {
		t.Fatalf("SetProtectedPaths: %v", err)
	}
	if _, err := os.Stat(PolicyPath()); err != nil {
		t.Fatalf("expected a store file to be created: %v", err)
	}
}