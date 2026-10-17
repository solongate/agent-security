// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package client

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/solongate/agent-security/packages/shared"
)

type Settings struct{ c *Client }

type SecurityLayersResponse struct {
	Layers            SecurityLayers `json:"layers"`
	AvailablePatterns []string       `json:"availablePatterns"`
}

func (s Settings) GetSecurityLayers(ctx context.Context) (SecurityLayersResponse, error) {
	st, err := readStore()
	if err != nil {
		return SecurityLayersResponse{}, err
	}
	return SecurityLayersResponse{Layers: toLayers(st.Security), AvailablePatterns: AvailablePatterns()}, nil
}

func (s Settings) SetSecurityLayers(ctx context.Context, layers SecurityLayers) (SecurityLayers, error) {
	st, err := readStore()
	if err != nil {
		return SecurityLayers{}, err
	}
	next := fromLayers(layers, st.Security)
	st.Security = next
	st.absent = false
	if err := writeStore(st); err != nil {
		return SecurityLayers{}, err
	}

	recordRateLimitChange(layers)
	return toLayers(next), nil
}

func (s Settings) GetRateLimitHistory(ctx context.Context) ([]RateLimitChange, error) {
	return readRateLimitHistory(), nil
}

func (s Settings) ClearRateLimitHistory(ctx context.Context) error {
	if err := os.WriteFile(historyPath(), []byte("[]"), 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

type GuardStatus struct {
	Latest        int  `json:"latest"`
	Installed     *int `json:"installed"`
	UpToDate      bool `json:"up_to_date"`
	DeviceCount   int  `json:"device_count"`
	OutdatedCount int  `json:"outdated_count"`
}

var GuardVersions = func() (latest int, installed *int) { return 0, nil }

func (s Settings) GetGuardStatus(ctx context.Context) (GuardStatus, error) {
	latest, installed := GuardVersions()
	out := GuardStatus{Latest: latest, Installed: installed, DeviceCount: 1}
	if installed != nil && *installed >= latest {
		out.UpToDate = true
	}
	if installed != nil && *installed < latest {
		out.OutdatedCount = 1
	}
	return out, nil
}

func (s Settings) GetSelfProtection(ctx context.Context) (bool, error) {
	st, err := readStore()
	if err != nil {
		return true, err
	}

	return st.SelfProtect == nil || *st.SelfProtect, nil
}

func (s Settings) SetSelfProtection(ctx context.Context, enabled bool) (bool, error) {
	st, err := readStore()
	if err != nil {
		return false, err
	}
	st.SelfProtect = &enabled
	st.absent = false
	if err := writeStore(st); err != nil {
		return false, err
	}
	return enabled, nil
}

func (s Settings) ProtectedPaths(ctx context.Context) ([]string, error) {
	st, err := readStore()
	if err != nil {
		return nil, err
	}
	if st.Security == nil {
		return nil, nil
	}
	return st.Security.ProtectedPaths, nil
}

func (s Settings) SetProtectedPaths(ctx context.Context, paths []string) error {
	st, err := readStore()
	if err != nil {
		return err
	}
	if st.Security == nil {
		st.Security = &guardSecurity{}
	}
	st.Security.ProtectedPaths = paths
	st.absent = false
	return writeStore(st)
}

func (s Settings) Sandboxes(ctx context.Context) ([]shared.Sandbox, error) {
	st, err := readStore()
	if err != nil {
		return nil, err
	}
	if st.Security == nil {
		return nil, nil
	}
	out := append([]shared.Sandbox(nil), st.Security.Sandboxes...)
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, nil
}

func (s Settings) Sandbox(ctx context.Context, id string) (shared.Sandbox, error) {
	boxes, err := s.Sandboxes(ctx)
	if err != nil {
		return shared.Sandbox{}, err
	}
	id = NormalizeSandboxID(id)
	for _, b := range boxes {
		if b.ID == id {
			return b, nil
		}
	}
	return shared.Sandbox{}, errors.New("there is no sandbox " + id +
		", `solongate sandbox list` shows the ones there are")
}

func NormalizeSandboxID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	n := 0
	for _, r := range id {
		if r < '0' || r > '9' {
			return id
		}
		n = n*10 + int(r-'0')
	}
	return fmt.Sprintf("%03d", n)
}

func nextSandboxID(existing []shared.Sandbox) string {
	taken := make(map[string]bool, len(existing))
	for _, b := range existing {
		taken[b.ID] = true
	}
	for n := 1; ; n++ {
		id := fmt.Sprintf("%03d", n)
		if !taken[id] {
			return id
		}
	}
}

func validateSandboxDir(dir string) (string, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return "", errors.New("a sandbox needs a directory")
	}
	if strings.HasPrefix(dir, "~") {
		return "", errors.New(`"~" is a shell convention, not a path the kernel can confine to, write it out in full`)
	}
	if !filepath.IsAbs(dir) {
		return "", errors.New("the directory must be an absolute path, like /home/you/projects/thing")
	}
	dir = filepath.Clean(dir)
	if dir == string(filepath.Separator) {
		return "", errors.New(`"/" as a sandbox confines nothing`)
	}
	if home, err := os.UserHomeDir(); err == nil && filepath.Clean(home) == dir {
		return "", errors.New("the home directory cannot be a sandbox: it holds ~/.ssh and every " +
			"other project, which is what a sandbox exists to keep the agent out of")
	}
	st, err := os.Stat(dir)
	if err != nil {
		return "", errors.New(dir + " cannot be read: " + err.Error())
	}
	if !st.IsDir() {
		return "", errors.New(dir + " is not a directory")
	}
	return dir, nil
}

func (s Settings) SandboxCreate(ctx context.Context, dir, label string, network bool) (shared.Sandbox, error) {
	clean, err := validateSandboxDir(dir)
	if err != nil {
		return shared.Sandbox{}, err
	}
	st, err := readStore()
	if err != nil {
		return shared.Sandbox{}, err
	}
	if st.Security == nil {
		st.Security = &guardSecurity{}
	}

	for _, b := range st.Security.Sandboxes {
		if b.Dir == clean {
			return shared.Sandbox{}, errors.New("sandbox " + b.ID + " is already " + clean)
		}
	}
	box := shared.Sandbox{
		ID:      nextSandboxID(st.Security.Sandboxes),
		Dir:     clean,
		Network: network,
		Label:   strings.TrimSpace(label),
	}
	st.Security.Sandboxes = append(st.Security.Sandboxes, box)
	st.absent = false
	if err := writeStore(st); err != nil {
		return shared.Sandbox{}, err
	}
	return box, nil
}

func (s Settings) SandboxUpdate(ctx context.Context, id, dir, label string, network bool) error {
	clean, err := validateSandboxDir(dir)
	if err != nil {
		return err
	}
	st, err := readStore()
	if err != nil {
		return err
	}
	if st.Security == nil {
		return errors.New("there are no sandboxes to update")
	}
	id = NormalizeSandboxID(id)
	for i := range st.Security.Sandboxes {
		if st.Security.Sandboxes[i].ID != id {
			continue
		}
		for j, other := range st.Security.Sandboxes {
			if j != i && other.Dir == clean {
				return errors.New("sandbox " + other.ID + " is already " + clean)
			}
		}
		st.Security.Sandboxes[i].Dir = clean
		st.Security.Sandboxes[i].Label = strings.TrimSpace(label)
		st.Security.Sandboxes[i].Network = network
		st.absent = false
		return writeStore(st)
	}
	return errors.New("there is no sandbox " + id)
}

func (s Settings) SandboxDelete(ctx context.Context, id string) error {
	st, err := readStore()
	if err != nil {
		return err
	}
	if st.Security == nil {
		return errors.New("there are no sandboxes to delete")
	}
	id = NormalizeSandboxID(id)
	out := make([]shared.Sandbox, 0, len(st.Security.Sandboxes))
	found := false
	for _, b := range st.Security.Sandboxes {
		if b.ID == id {
			found = true
			continue
		}
		out = append(out, b)
	}
	if !found {
		return errors.New("there is no sandbox " + id)
	}
	st.Security.Sandboxes = out
	st.absent = false
	return writeStore(st)
}

func (s Settings) RequireSandbox(ctx context.Context) (bool, error) {
	st, err := readStore()
	if err != nil {
		return false, err
	}
	if st.Security == nil {
		return false, nil
	}
	return st.Security.RequireSandbox, nil
}

func (s Settings) SetRequireSandbox(ctx context.Context, on bool) error {
	st, err := readStore()
	if err != nil {
		return err
	}
	if st.Security == nil {
		st.Security = &guardSecurity{}
	}
	st.Security.RequireSandbox = on
	st.absent = false
	return writeStore(st)
}

type LocalLogsConfig struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

func (s Settings) GetLocalLogs(ctx context.Context) (LocalLogsConfig, error) {
	st, err := readStore()
	if err != nil {
		return LocalLogsConfig{}, err
	}
	if st.Security != nil && st.Security.LocalLogs != nil && strings.TrimSpace(st.Security.LocalLogs.Path) != "" {
		return LocalLogsConfig{Enabled: st.Security.LocalLogs.Enabled, Path: st.Security.LocalLogs.Path}, nil
	}
	return LocalLogsConfig{Enabled: true, Path: DefaultLogDir()}, nil
}

func (s Settings) SetLocalLogs(ctx context.Context, cfg LocalLogsConfig) (LocalLogsConfig, error) {
	st, err := readStore()
	if err != nil {
		return LocalLogsConfig{}, err
	}
	path := strings.TrimSpace(cfg.Path)
	if st.Security == nil {
		st.Security = &guardSecurity{}
	}
	if path == "" {
		st.Security.LocalLogs = nil
	} else {
		st.Security.LocalLogs = &localLogsBlock{Enabled: cfg.Enabled, Path: path}
	}
	st.absent = false
	if err := writeStore(st); err != nil {
		return LocalLogsConfig{}, err
	}
	if path == "" {
		return LocalLogsConfig{Enabled: true, Path: DefaultLogDir()}, nil
	}
	return LocalLogsConfig{Enabled: cfg.Enabled, Path: path}, nil
}