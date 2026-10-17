// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package config

import (
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/solongate/agent-security/packages/shared"
)

type DLPCustom = shared.DLPCustom

type DLPConfig = shared.DLPConfig

type RateLimit = shared.RateLimit

type LocalLogs = shared.LocalLogs

type Security = shared.Security

type Policy = shared.Policy

type PolicyCache = shared.PolicyCache

type TUIConfig struct {
	Notifications bool   `json:"notifications"`
	Accent        string `json:"accent,omitempty"`
	PollMs        int    `json:"pollMs,omitempty"`

	SetupDoneAt string `json:"setupDoneAt,omitempty"`

	UpdateRange string `json:"updateRange,omitempty"`
}

const (
	UpdateRangeShort = "short"
	UpdateRangeLong  = "long"
)

func UpdateRangeOf(cfg TUIConfig) string {
	if cfg.UpdateRange == UpdateRangeShort {
		return UpdateRangeShort
	}
	return UpdateRangeLong
}

func SetUpdateRange(which string) error {
	if which != UpdateRangeShort && which != UpdateRangeLong {
		return errors.New(`update range must be "short" or "long"`)
	}
	if err := EnsureDir(); err != nil {
		return err
	}
	doc := map[string]any{}
	if b, err := os.ReadFile(TUIConfigPath()); err == nil {
		_ = json.Unmarshal(b, &doc)
	}
	doc["updateRange"] = which
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(TUIConfigPath(), append(out, '\n'), FileMode)
}

func LoadTUIConfig() TUIConfig {
	cfg := TUIConfig{Notifications: true}
	b, err := os.ReadFile(TUIConfigPath())
	if err != nil {
		return cfg
	}
	var raw struct {
		Notifications *bool  `json:"notifications"`
		Accent        string `json:"accent"`
		PollMs        *int   `json:"pollMs"`
		SetupDoneAt   string `json:"setupDoneAt"`
		UpdateRange   string `json:"updateRange"`
	}
	if json.Unmarshal(b, &raw) != nil {
		return cfg
	}
	if raw.Notifications != nil {
		cfg.Notifications = *raw.Notifications
	}
	cfg.Accent = raw.Accent
	if raw.PollMs != nil {
		cfg.PollMs = *raw.PollMs
	}
	cfg.SetupDoneAt = raw.SetupDoneAt
	cfg.UpdateRange = raw.UpdateRange
	return cfg
}

func MarkSetupDone() {
	if EnsureDir() != nil {
		return
	}
	doc := map[string]any{}
	if b, err := os.ReadFile(TUIConfigPath()); err == nil {
		_ = json.Unmarshal(b, &doc)
	}
	doc["setupDoneAt"] = time.Now().UTC().Format(time.RFC3339)
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(TUIConfigPath(), append(out, '\n'), FileMode)
}