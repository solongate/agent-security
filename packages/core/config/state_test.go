// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package config

import (
	"encoding/json"
	"os"
	"testing"
)

func TestUpdateRangeOf(t *testing.T) {
	cases := []struct {
		name string
		cfg  TUIConfig
		want string
	}{
		{"short", TUIConfig{UpdateRange: UpdateRangeShort}, UpdateRangeShort},
		{"long", TUIConfig{UpdateRange: UpdateRangeLong}, UpdateRangeLong},
		{"unset defaults to long", TUIConfig{}, UpdateRangeLong},
		{"garbage defaults to long", TUIConfig{UpdateRange: "whatever"}, UpdateRangeLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := UpdateRangeOf(tc.cfg); got != tc.want {
				t.Errorf("UpdateRangeOf(%+v) = %q, want %q", tc.cfg, got, tc.want)
			}
		})
	}
}

func TestSetUpdateRangeRejectsInvalidValues(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := SetUpdateRange("sideways"); err == nil {
		t.Error("expected an error for an invalid update range")
	}
}

func TestSetUpdateRangeWritesThenLoadsBack(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := SetUpdateRange(UpdateRangeShort); err != nil {
		t.Fatal(err)
	}
	cfg := LoadTUIConfig()
	if cfg.UpdateRange != UpdateRangeShort {
		t.Errorf("UpdateRange = %q, want %q", cfg.UpdateRange, UpdateRangeShort)
	}
}

func TestSetUpdateRangePreservesOtherFields(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{"accent": "blue", "notifications": false}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(TUIConfigPath(), b, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := SetUpdateRange(UpdateRangeLong); err != nil {
		t.Fatal(err)
	}

	cfg := LoadTUIConfig()
	if cfg.Accent != "blue" {
		t.Errorf("Accent = %q, want %q", cfg.Accent, "blue")
	}
	if cfg.Notifications {
		t.Error("Notifications = true, want the previously stored false to survive")
	}
	if cfg.UpdateRange != UpdateRangeLong {
		t.Errorf("UpdateRange = %q, want %q", cfg.UpdateRange, UpdateRangeLong)
	}
}

func TestLoadTUIConfigMissingFileReturnsDefault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfg := LoadTUIConfig()
	if !cfg.Notifications {
		t.Error("Notifications = false, want true by default")
	}
	if cfg.Accent != "" || cfg.PollMs != 0 || cfg.SetupDoneAt != "" || cfg.UpdateRange != "" {
		t.Errorf("LoadTUIConfig() = %+v, want all zero values besides Notifications", cfg)
	}
}

func TestLoadTUIConfigInvalidJSONReturnsDefault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(TUIConfigPath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := LoadTUIConfig()
	if !cfg.Notifications {
		t.Error("Notifications = false, want the default true on parse failure")
	}
}

func TestLoadTUIConfigHonorsExplicitFalseNotifications(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(TUIConfigPath(), []byte(`{"notifications":false,"pollMs":50}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := LoadTUIConfig()
	if cfg.Notifications {
		t.Error("Notifications = true, want the explicit false to be honored")
	}
	if cfg.PollMs != 50 {
		t.Errorf("PollMs = %d, want 50", cfg.PollMs)
	}
}

func TestMarkSetupDoneWritesTimestamp(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	MarkSetupDone()
	cfg := LoadTUIConfig()
	if cfg.SetupDoneAt == "" {
		t.Error("SetupDoneAt is empty after MarkSetupDone()")
	}
}

func TestMarkSetupDonePreservesOtherFields(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := SetUpdateRange(UpdateRangeShort); err != nil {
		t.Fatal(err)
	}
	MarkSetupDone()
	cfg := LoadTUIConfig()
	if cfg.UpdateRange != UpdateRangeShort {
		t.Errorf("UpdateRange = %q, want %q to survive MarkSetupDone()", cfg.UpdateRange, UpdateRangeShort)
	}
	if cfg.SetupDoneAt == "" {
		t.Error("SetupDoneAt is empty after MarkSetupDone()")
	}
}