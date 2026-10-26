// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package confine

import (
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/shared"
)

func TestBuildSandboxEnvOverridesHostVariables(t *testing.T) {
	t.Setenv("HOME", "/host/user/home")
	t.Setenv("PWD", "/host/project")
	t.Setenv("TMPDIR", "/host/tmp")
	t.Setenv("XDG_CACHE_HOME", "/host/user/.cache")
	t.Setenv("XDG_CONFIG_HOME", "/host/user/.config")
	t.Setenv("SSH_AUTH_SOCK", "/run/user/1000/ssh.sock")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
	t.Setenv("SOLONGATE_SANDBOX", "run:0.0.0-outer")
	t.Setenv("CUSTOM_AGENT_KEY", "secret-agent-key-123")

	env := buildSandboxEnv("/workspace/.sandbox-home")

	var (
		homeCount int
		pwdCount  int
		gotHome   string
		gotPwd    string
		gotTmp    string
		gotCache  string
		gotConfig string
		gotMarker string
		hasSSH    bool
		hasDBUS   bool
		gotCustom string
	)

	for _, kv := range env {
		idx := strings.IndexByte(kv, '=')
		if idx <= 0 {
			continue
		}
		k, v := kv[:idx], kv[idx+1:]
		switch k {
		case "HOME":
			homeCount++
			gotHome = v
		case "PWD":
			pwdCount++
			gotPwd = v
		case "TMPDIR":
			gotTmp = v
		case "XDG_CACHE_HOME":
			gotCache = v
		case "XDG_CONFIG_HOME":
			gotConfig = v
		case shared.SandboxEnv:
			gotMarker = v
		case "SSH_AUTH_SOCK":
			hasSSH = true
		case "DBUS_SESSION_BUS_ADDRESS":
			hasDBUS = true
		case "CUSTOM_AGENT_KEY":
			gotCustom = v
		}
	}

	if homeCount != 1 || gotHome != "/workspace/.sandbox-home" {
		t.Errorf("HOME count=%d value=%q, want exactly 1 count with /workspace/.sandbox-home", homeCount, gotHome)
	}
	if pwdCount != 1 || gotPwd != "/workspace" {
		t.Errorf("PWD count=%d value=%q, want exactly 1 count with /workspace", pwdCount, gotPwd)
	}
	if gotTmp != "/tmp" {
		t.Errorf("TMPDIR=%q, want /tmp", gotTmp)
	}
	if gotCache != "/workspace/.sandbox-home/.cache" {
		t.Errorf("XDG_CACHE_HOME=%q, want /workspace/.sandbox-home/.cache", gotCache)
	}
	if gotConfig != "/workspace/.sandbox-home/.config" {
		t.Errorf("XDG_CONFIG_HOME=%q, want /workspace/.sandbox-home/.config", gotConfig)
	}
	if !strings.HasPrefix(gotMarker, "box:") {
		t.Errorf("SOLONGATE_SANDBOX=%q, want box:...", gotMarker)
	}
	if hasSSH {
		t.Errorf("SSH_AUTH_SOCK was not stripped from sandbox environment")
	}
	if hasDBUS {
		t.Errorf("DBUS_SESSION_BUS_ADDRESS was not stripped from sandbox environment")
	}
	if gotCustom != "secret-agent-key-123" {
		t.Errorf("CUSTOM_AGENT_KEY=%q, want secret-agent-key-123", gotCustom)
	}
}

func TestParseSandboxArgs(t *testing.T) {
	cases := []struct {
		name     string
		argv     []string
		wantID   string
		wantRest []string
		wantOK   bool
	}{
		{
			name:     "standard invocation",
			argv:     []string{"001", "claude"},
			wantID:   "001",
			wantRest: []string{"claude"},
			wantOK:   true,
		},
		{
			name:     "delimiter before id",
			argv:     []string{"--", "001", "claude"},
			wantID:   "001",
			wantRest: []string{"claude"},
			wantOK:   true,
		},
		{
			name:     "delimiter after id",
			argv:     []string{"001", "--", "claude"},
			wantID:   "001",
			wantRest: []string{"claude"},
			wantOK:   true,
		},
		{
			name:     "delimiters before and after id",
			argv:     []string{"--", "001", "--", "claude"},
			wantID:   "001",
			wantRest: []string{"claude"},
			wantOK:   true,
		},
		{
			name:     "preserves double dash in agent arguments",
			argv:     []string{"001", "python", "-m", "pytest", "--", "-k", "test_foo"},
			wantID:   "001",
			wantRest: []string{"python", "-m", "pytest", "--", "-k", "test_foo"},
			wantOK:   true,
		},
		{
			name:     "preserves trailing double dash",
			argv:     []string{"001", "echo", "foo", "--"},
			wantID:   "001",
			wantRest: []string{"echo", "foo", "--"},
			wantOK:   true,
		},
		{
			name:   "missing agent",
			argv:   []string{"001"},
			wantOK: false,
		},
		{
			name:   "delimiter with no agent",
			argv:   []string{"001", "--"},
			wantOK: false,
		},
		{
			name:   "empty argv",
			argv:   nil,
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotID, gotRest, gotOK := parseSandboxArgs(tc.argv)
			if gotOK != tc.wantOK {
				t.Fatalf("parseSandboxArgs(%v) ok=%v, want %v", tc.argv, gotOK, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if gotID != tc.wantID {
				t.Errorf("gotID=%q, want %q", gotID, tc.wantID)
			}
			if len(gotRest) != len(tc.wantRest) {
				t.Fatalf("gotRest=%v, want %v", gotRest, tc.wantRest)
			}
			for i := range gotRest {
				if gotRest[i] != tc.wantRest[i] {
					t.Errorf("gotRest[%d]=%q, want %q", i, gotRest[i], tc.wantRest[i])
				}
			}
		})
	}
}