// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package client

// Split from resources.go: the /settings namespace. See resources_policy.go for
// the file-level rationale.

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

// ── /settings ──────────────────────────────────────────────────────────────

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
	// The change is worth seeing beside a burst later: "the limit was 30 then".
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

// GuardStatus is this machine's guard against the one this binary ships.
//
// `latest` used to mean "the newest version the service serves". It means the
// version in this build now, which is the only newer one a machine can get: the
// installer writes the shipped hook, so an out-of-date install is fixed by
// reinstalling rather than by waiting for a download.
type GuardStatus struct {
	Latest        int  `json:"latest"`
	Installed     *int `json:"installed"`
	UpToDate      bool `json:"up_to_date"`
	DeviceCount   int  `json:"device_count"`
	OutdatedCount int  `json:"outdated_count"`
}

// GuardVersions is filled in by the install layer, which owns both numbers. It
// is a function variable rather than an import because core/install imports
// this package, and a cycle is not worth one integer.
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
	// Defaults ON: a file that says nothing leaves protection on, because the
	// failure mode of guessing wrong the other way is a guard that can be edited
	// out of the way.
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

// ProtectedPaths is the list `solongate protect` maintains.
//
// THE LIST IS THE RECORD, NOT THE ENFORCEMENT. What is actually in force on
// each path is a question for the filesystem, and config.CheckLock asks it.
// Reading this and reporting "protected" would be reporting an intention.
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

// SetProtectedPaths replaces the list.
//
// It creates the security block when there is none, which is the common case:
// most people reach `protect` before they reach DLP or a rate limit.
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

// Sandboxes are the closed boxes this machine has defined, lowest id first.
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

// Sandbox returns one box by id.
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

// NormalizeSandboxID turns what somebody typed into the stored form.
//
// `solongate sandbox 1 claude` and `solongate sandbox 001 claude` are the same
// box: the padding is how the list lines up in a column, not part of the name,
// and requiring it would mean a command that fails for a reason nobody can see.
func NormalizeSandboxID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	n := 0
	for _, r := range id {
		if r < '0' || r > '9' {
			return id // not a number; returned as-is so the lookup fails by name
		}
		n = n*10 + int(r-'0')
	}
	return fmt.Sprintf("%03d", n)
}

// nextSandboxID is the LOWEST FREE number, not one past the highest.
//
// Deleting a box frees its id, and the next box takes it. The alternative, a
// counter that only goes up, means a machine where boxes get made and removed
// ends up typing "047" for its only sandbox, and the id is a thing somebody
// types every time they start an agent. The number names a slot.
//
// Three digits because 999 boxes is more than anybody has and a fixed width is
// what makes the list a column rather than a ragged edge. Past 999 it keeps
// counting and the column gets wider, which is better than refusing.
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

// validateSandboxDir refuses the paths that would look like confinement and not
// be it.
//
// CHECKED WHEREVER A BOX IS WRITTEN, because the person setting it is at a
// terminal and can be told, while the launch happens in front of an agent that
// is about to start.
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

// SandboxCreate adds a box and returns it, with the id it was given.
//
// Network defaults to true, and the default is deliberate: a box with no
// network cannot reach the model that drives the agent, so it is airtight and
// unused. The surfaces that offer this say what the choice costs rather than
// choosing quietly.
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
	// One box per directory. Two boxes about the same directory differing only
	// in whether the network is on is a way to run the confined agent
	// unconfined-enough by typing the other number, and nothing about the list
	// would show that had happened.
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

// SandboxUpdate replaces a box's directory, label and network answer, keeping
// its id, the id is what somebody types, so changing a box must not change it.
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

// SandboxDelete removes a box and frees its id for the next one.
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

// RequireSandbox is the fail-closed switch: refuse every call from an agent
// that was not started by `solongate run`.
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

// LocalLogsConfig is where the hooks write the record. On a machine with no
// service this is the only destination there is, so it reads as ON with the
// default folder unless somebody named another, the FOLDER is the part worth
// choosing.
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