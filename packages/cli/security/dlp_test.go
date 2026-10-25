// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build !windows

package security

import (
	"context"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
)

// newHome isolates the local-file client store behind a throwaway $HOME so
// tests never touch the real machine's SolonGate state.
func newHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

// captureOutput redirects the process's real stdout and stderr file
// descriptors for the duration of fn and returns everything written to
// either. cliutil.Out/Errln/Table/PrintJSON write through unexported
// io.Writer values that were bound to os.Stdout/os.Stderr at package init,
// so merely reassigning those variables would not intercept the writes; the
// underlying fds must be swapped instead.
func captureOutput(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	outFd := int(os.Stdout.Fd())
	errFd := int(os.Stderr.Fd())
	origOut, err := syscall.Dup(outFd)
	if err != nil {
		t.Fatal(err)
	}
	origErr, err := syscall.Dup(errFd)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Dup2(int(w.Fd()), outFd); err != nil {
		t.Fatal(err)
	}
	if err := unix.Dup2(int(w.Fd()), errFd); err != nil {
		t.Fatal(err)
	}

	fn()

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Dup2(origOut, outFd); err != nil {
		t.Fatal(err)
	}
	if err := unix.Dup2(origErr, errFd); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Close(origOut); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Close(origErr); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestDLPUsage(t *testing.T) {
	u := dlpUsage()
	for _, want := range []string{"solongate dlp", "dlp show", "dlp mode", "dlp enable", "dlp disable", "add-custom", "remove-custom"} {
		if !strings.Contains(u, want) {
			t.Errorf("dlpUsage() missing %q:\n%s", want, u)
		}
	}
}

func TestRunDLPHelp(t *testing.T) {
	newHome(t)
	c := client.New()
	ctx := context.Background()

	var code int
	var err error
	out := captureOutput(t, func() { code, err = RunDLP(ctx, c, cliutil.Parse([]string{"help"})) })
	if code != 0 || err != nil {
		t.Errorf("RunDLP(help) = (%d, %v), want (0, nil)", code, err)
	}
	if !strings.Contains(out, "solongate dlp") {
		t.Errorf("help did not print usage:\n%s", out)
	}
}

func TestRunDLPUnknownSub(t *testing.T) {
	newHome(t)
	c := client.New()
	ctx := context.Background()

	var code int
	var err error
	out := captureOutput(t, func() { code, err = RunDLP(ctx, c, cliutil.Parse([]string{"bogus-sub"})) })
	if code != 1 || err != nil {
		t.Errorf("RunDLP(bogus-sub) = (%d, %v), want (1, nil)", code, err)
	}
	if !strings.Contains(out, "Unknown dlp subcommand") || !strings.Contains(out, "bogus-sub") {
		t.Errorf("unexpected unknown-sub output:\n%s", out)
	}
}

func TestRunDLPShow(t *testing.T) {
	newHome(t)
	c := client.New()
	ctx := context.Background()

	run := func(args ...string) (int, error, string) {
		var code int
		var err error
		out := captureOutput(t, func() { code, err = RunDLP(ctx, c, cliutil.Parse(args)) })
		return code, err, out
	}

	t.Run("empty sub defaults to show", func(t *testing.T) {
		code, err, out := run()
		if code != 0 || err != nil {
			t.Fatalf("RunDLP() = (%d, %v), want (0, nil): %s", code, err, out)
		}
		if !strings.Contains(out, "DLP") || !strings.Contains(out, "PATTERN") {
			t.Errorf("show output=%q, want it to render the pattern table", out)
		}
	})

	t.Run("show json lists availablePatterns", func(t *testing.T) {
		code, err, out := run("show", "--json")
		if code != 0 || err != nil {
			t.Fatalf("RunDLP(show --json) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		if !strings.Contains(out, `"availablePatterns"`) || !strings.Contains(out, "AWS access key") {
			t.Errorf("show --json output=%q, want availablePatterns to list known patterns", out)
		}
		if !strings.Contains(out, `"dlp"`) {
			t.Errorf("show --json output=%q, want a top-level dlp key", out)
		}
	})

	t.Run("enabled pattern renders as an active dot, others dimmed", func(t *testing.T) {
		code, err, _ := run("enable", "JWT")
		if code != 0 || err != nil {
			t.Fatalf("RunDLP(enable JWT) = (%d, %v), want (0, nil)", code, err)
		}
		layers, lerr := c.Settings.GetSecurityLayers(ctx)
		if lerr != nil {
			t.Fatalf("GetSecurityLayers: %v", lerr)
		}
		found := false
		for _, name := range layers.Layers.DLP.Patterns {
			if name == "JWT" {
				found = true
			}
		}
		if !found {
			t.Fatalf("DLP.Patterns = %v, want JWT present after enable", layers.Layers.DLP.Patterns)
		}
		_, _, out := run("show")
		if !strings.Contains(out, cliutil.Green("●")+"  JWT") {
			t.Errorf("show output=%q, want JWT rendered with the active (green) dot", out)
		}
	})

	t.Run("custom patterns appear under a Custom section", func(t *testing.T) {
		code, err, _ := run("add-custom", "--name", "ticket-id", "--re", `TCK-\d+`)
		if code != 0 || err != nil {
			t.Fatalf("RunDLP(add-custom) = (%d, %v), want (0, nil)", code, err)
		}
		_, _, out := run("show")
		if !strings.Contains(out, "Custom:") || !strings.Contains(out, "ticket-id") || !strings.Contains(out, `TCK-\d+`) {
			t.Errorf("show output=%q, want it to render the custom pattern", out)
		}
	})
}

func TestRunDLPMode(t *testing.T) {
	newHome(t)
	c := client.New()
	ctx := context.Background()

	run := func(args ...string) (int, error, string) {
		var code int
		var err error
		out := captureOutput(t, func() { code, err = RunDLP(ctx, c, cliutil.Parse(args)) })
		return code, err, out
	}

	t.Run("bad mode is a usage error", func(t *testing.T) {
		code, err, out := run("mode", "bogus")
		if code != 1 || err != nil {
			t.Errorf("RunDLP(mode bogus) = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, "Usage: dlp mode") {
			t.Errorf("mode bogus output=%q, want usage text", out)
		}
	})

	t.Run("missing mode is a usage error", func(t *testing.T) {
		code, err, _ := run("mode")
		if code != 1 || err != nil {
			t.Errorf("RunDLP(mode) = (%d, %v), want (1, nil)", code, err)
		}
	})

	for _, mode := range []string{"off", "detect", "redact", "block"} {
		t.Run("mode "+mode+" round trips through show", func(t *testing.T) {
			code, err, out := run("mode", mode)
			if code != 0 || err != nil {
				t.Fatalf("RunDLP(mode %s) = (%d, %v), want (0, nil): %s", mode, code, err, out)
			}
			if !strings.Contains(out, "DLP mode") || !strings.Contains(out, mode) {
				t.Errorf("mode %s output=%q, want confirmation naming the new mode", mode, out)
			}
			_, _, show := run("show", "--json")
			if !strings.Contains(show, `"mode": "`+mode+`"`) {
				t.Errorf("show --json after mode %s = %q, want mode %s reflected", mode, show, mode)
			}
		})
	}

	t.Run("mode --json prints the saved layer", func(t *testing.T) {
		code, err, out := run("mode", "block", "--json")
		if code != 0 || err != nil {
			t.Fatalf("RunDLP(mode block --json) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		if !strings.Contains(out, `"mode": "block"`) {
			t.Errorf("mode block --json output=%q, want it to echo the saved mode", out)
		}
	})
}

func TestRunDLPEnableDisable(t *testing.T) {
	newHome(t)
	c := client.New()
	ctx := context.Background()

	run := func(args ...string) (int, error, string) {
		var code int
		var err error
		out := captureOutput(t, func() { code, err = RunDLP(ctx, c, cliutil.Parse(args)) })
		return code, err, out
	}

	t.Run("enable with no pattern is a usage error", func(t *testing.T) {
		code, err, out := run("enable")
		if code != 1 || err != nil {
			t.Errorf("RunDLP(enable) = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, "Usage: dlp enable") {
			t.Errorf("enable output=%q, want usage text", out)
		}
	})

	t.Run("disable with no pattern is a usage error", func(t *testing.T) {
		code, err, out := run("disable")
		if code != 1 || err != nil {
			t.Errorf("RunDLP(disable) = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, "Usage: dlp disable") {
			t.Errorf("disable output=%q, want usage text", out)
		}
	})

	t.Run("enabling an unknown pattern lists the available ones and fails", func(t *testing.T) {
		code, err, out := run("enable", "not-a-real-pattern")
		if code != 1 || err != nil {
			t.Errorf("RunDLP(enable not-a-real-pattern) = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, "Unknown pattern") || !strings.Contains(out, "not-a-real-pattern") {
			t.Errorf("enable unknown output=%q, want it to name the bad pattern", out)
		}
		if !strings.Contains(out, "AWS access key") {
			t.Errorf("enable unknown output=%q, want it to list the available patterns", out)
		}
	})

	t.Run("enable a real pattern, then disable it", func(t *testing.T) {
		code, err, out := run("enable", "JWT")
		if code != 0 || err != nil {
			t.Fatalf("RunDLP(enable JWT) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		if !strings.Contains(out, "enabled") || !strings.Contains(out, "JWT") {
			t.Errorf("enable JWT output=%q, want confirmation", out)
		}

		layers, lerr := c.Settings.GetSecurityLayers(ctx)
		if lerr != nil {
			t.Fatalf("GetSecurityLayers: %v", lerr)
		}
		if !containsStr(layers.Layers.DLP.Patterns, "JWT") {
			t.Fatalf("DLP.Patterns = %v, want JWT present after enable", layers.Layers.DLP.Patterns)
		}

		code, err, out = run("disable", "JWT")
		if code != 0 || err != nil {
			t.Fatalf("RunDLP(disable JWT) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		if !strings.Contains(out, "disabled") {
			t.Errorf("disable JWT output=%q, want confirmation", out)
		}

		layers, lerr = c.Settings.GetSecurityLayers(ctx)
		if lerr != nil {
			t.Fatalf("GetSecurityLayers: %v", lerr)
		}
		if containsStr(layers.Layers.DLP.Patterns, "JWT") {
			t.Errorf("DLP.Patterns = %v, want JWT gone after disable", layers.Layers.DLP.Patterns)
		}
	})

	t.Run("enabling a multi-word pattern name works via Rest", func(t *testing.T) {
		code, err, out := run("enable", "Bearer", "token")
		if code != 0 || err != nil {
			t.Fatalf("RunDLP(enable Bearer token) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		if !strings.Contains(out, "Bearer token") {
			t.Errorf("enable Bearer token output=%q, want it to name the pattern", out)
		}
		layers, lerr := c.Settings.GetSecurityLayers(ctx)
		if lerr != nil {
			t.Fatalf("GetSecurityLayers: %v", lerr)
		}
		if !containsStr(layers.Layers.DLP.Patterns, "Bearer token") {
			t.Fatalf("DLP.Patterns = %v, want \"Bearer token\" present", layers.Layers.DLP.Patterns)
		}
	})

	t.Run("enable --json prints the saved layer", func(t *testing.T) {
		code, err, out := run("enable", "JWT", "--json")
		if code != 0 || err != nil {
			t.Fatalf("RunDLP(enable JWT --json) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		if !strings.Contains(out, "JWT") {
			t.Errorf("enable --json output=%q, want JWT in the patterns array", out)
		}
	})
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestRunDLPAddCustom(t *testing.T) {
	newHome(t)
	c := client.New()
	ctx := context.Background()

	run := func(args ...string) (int, error, string) {
		var code int
		var err error
		out := captureOutput(t, func() { code, err = RunDLP(ctx, c, cliutil.Parse(args)) })
		return code, err, out
	}

	t.Run("missing --name is a usage error", func(t *testing.T) {
		code, err, out := run("add-custom", "--re", "foo.*")
		if code != 1 || err != nil {
			t.Errorf("RunDLP(add-custom, no name) = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, "Usage: dlp add-custom") {
			t.Errorf("add-custom output=%q, want usage text", out)
		}
	})

	t.Run("missing --re is a usage error", func(t *testing.T) {
		code, err, out := run("add-custom", "--name", "foo")
		if code != 1 || err != nil {
			t.Errorf("RunDLP(add-custom, no re) = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, "Usage: dlp add-custom") {
			t.Errorf("add-custom output=%q, want usage text", out)
		}
	})

	t.Run("adding then re-adding the same name replaces, not duplicates", func(t *testing.T) {
		code, err, out := run("add-custom", "--name", "ticket-id", "--re", `TCK-\d+`)
		if code != 0 || err != nil {
			t.Fatalf("RunDLP(add-custom) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		code, err, out = run("add-custom", "--name", "ticket-id", "--re", `TICK-\d{4}`)
		if code != 0 || err != nil {
			t.Fatalf("RunDLP(add-custom replace) = (%d, %v), want (0, nil): %s", code, err, out)
		}

		layers, err := c.Settings.GetSecurityLayers(ctx)
		if err != nil {
			t.Fatalf("GetSecurityLayers: %v", err)
		}
		count := 0
		for _, cp := range layers.Layers.DLP.Custom {
			if cp.Name == "ticket-id" {
				count++
				if cp.Re != `TICK-\d{4}` {
					t.Errorf("custom pattern ticket-id re = %q, want the replaced regex", cp.Re)
				}
			}
		}
		if count != 1 {
			t.Errorf("found %d custom patterns named ticket-id, want exactly 1 (replace, not append)", count)
		}
	})

	t.Run("add-custom --json prints the saved layer", func(t *testing.T) {
		code, err, out := run("add-custom", "--name", "another", "--re", "x+", "--json")
		if code != 0 || err != nil {
			t.Fatalf("RunDLP(add-custom --json) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		if !strings.Contains(out, "another") {
			t.Errorf("add-custom --json output=%q, want it to include the new pattern", out)
		}
	})
}

func TestRunDLPRemoveCustom(t *testing.T) {
	newHome(t)
	c := client.New()
	ctx := context.Background()

	run := func(args ...string) (int, error, string) {
		var code int
		var err error
		out := captureOutput(t, func() { code, err = RunDLP(ctx, c, cliutil.Parse(args)) })
		return code, err, out
	}

	t.Run("missing name is a usage error", func(t *testing.T) {
		code, err, out := run("remove-custom")
		if code != 1 || err != nil {
			t.Errorf("RunDLP(remove-custom) = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, "Usage: dlp remove-custom") {
			t.Errorf("remove-custom output=%q, want usage text", out)
		}
	})

	t.Run("removing a nonexistent pattern is a no-op success, not an error", func(t *testing.T) {
		// withoutCustom silently drops nothing when the name is absent, and
		// RunDLP never distinguishes that from a real removal, so the
		// documented behaviour here is success, not a reported error.
		code, err, out := run("remove-custom", "never-added")
		if code != 0 || err != nil {
			t.Errorf("RunDLP(remove-custom never-added) = (%d, %v), want (0, nil)", code, err)
		}
		if !strings.Contains(out, "Removed custom pattern") {
			t.Errorf("remove-custom output=%q, want a removal confirmation", out)
		}
	})

	t.Run("add then remove round trip", func(t *testing.T) {
		code, err, out := run("add-custom", "--name", "temp", "--re", "a+")
		if code != 0 || err != nil {
			t.Fatalf("RunDLP(add-custom) = (%d, %v), want (0, nil): %s", code, err, out)
		}

		mid, err := c.Settings.GetSecurityLayers(ctx)
		if err != nil {
			t.Fatalf("GetSecurityLayers: %v", err)
		}
		midFound := false
		for _, cp := range mid.Layers.DLP.Custom {
			if cp.Name == "temp" {
				midFound = true
			}
		}
		if !midFound {
			t.Fatalf("DLP.Custom = %v, want temp present right after add-custom", mid.Layers.DLP.Custom)
		}

		code, err, out = run("remove-custom", "temp")
		if code != 0 || err != nil {
			t.Fatalf("RunDLP(remove-custom temp) = (%d, %v), want (0, nil): %s", code, err, out)
		}

		layers, err := c.Settings.GetSecurityLayers(ctx)
		if err != nil {
			t.Fatalf("GetSecurityLayers: %v", err)
		}
		for _, cp := range layers.Layers.DLP.Custom {
			if cp.Name == "temp" {
				t.Errorf("custom pattern %q still present after remove-custom", cp.Name)
			}
		}
	})
}

// TestDLPPatternsPersistWhileModeIsOff guards against a regression in
// packages/core/client/localstore.go's fromLayers/toLayers round trip, where
// DLP.Patterns/DLP.Custom set while the mode is still "off" were silently
// dropped because the on-disk switch over the mode had no case for
// LayerOff. "dlp enable X" / "dlp add-custom" must persist regardless of the
// current mode.
func TestDLPPatternsPersistWhileModeIsOff(t *testing.T) {
	newHome(t)
	c := client.New()
	ctx := context.Background()

	run := func(args ...string) (int, error, string) {
		var code int
		var err error
		out := captureOutput(t, func() { code, err = RunDLP(ctx, c, cliutil.Parse(args)) })
		return code, err, out
	}

	code, err, out := run("enable", "JWT")
	if code != 0 || err != nil {
		t.Fatalf("RunDLP(enable JWT) = (%d, %v), want (0, nil): %s", code, err, out)
	}
	if !strings.Contains(out, "enabled") {
		t.Errorf("enable JWT output=%q, want it to report success", out)
	}

	layers, err := c.Settings.GetSecurityLayers(ctx)
	if err != nil {
		t.Fatalf("GetSecurityLayers: %v", err)
	}
	if layers.Layers.DLP.Mode != "off" {
		t.Fatalf("DLP.Mode = %q, want it to remain off", layers.Layers.DLP.Mode)
	}
	if !containsStr(layers.Layers.DLP.Patterns, "JWT") {
		t.Fatalf("DLP.Patterns = %v, want JWT present even though mode is off", layers.Layers.DLP.Patterns)
	}

	code, err, out = run("add-custom", "--name", "ticket-id", "--re", `TCK-\d+`)
	if code != 0 || err != nil {
		t.Fatalf("RunDLP(add-custom) = (%d, %v), want (0, nil): %s", code, err, out)
	}
	layers, err = c.Settings.GetSecurityLayers(ctx)
	if err != nil {
		t.Fatalf("GetSecurityLayers: %v", err)
	}
	found := false
	for _, cp := range layers.Layers.DLP.Custom {
		if cp.Name == "ticket-id" {
			found = true
		}
	}
	if !found {
		t.Fatalf("DLP.Custom = %v, want ticket-id present even though mode is off", layers.Layers.DLP.Custom)
	}
}

func TestTogglePattern(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		pattern  string
		on       bool
		want     []string
	}{
		{"turning on an absent pattern appends it", []string{"A"}, "B", true, []string{"A", "B"}},
		{"turning on an already-present pattern does not duplicate it", []string{"A", "B"}, "B", true, []string{"A", "B"}},
		{"turning off a present pattern removes it", []string{"A", "B"}, "B", false, []string{"A"}},
		{"turning off an absent pattern is a no-op", []string{"A"}, "B", false, []string{"A"}},
		{"turning on into an empty list", nil, "A", true, []string{"A"}},
		{"turning off the only entry empties the list", []string{"A"}, "A", false, []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := togglePattern(tc.patterns, tc.pattern, tc.on)
			if len(got) != len(tc.want) {
				t.Fatalf("togglePattern(%v, %q, %v) = %v, want %v", tc.patterns, tc.pattern, tc.on, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("togglePattern(%v, %q, %v)[%d] = %q, want %q", tc.patterns, tc.pattern, tc.on, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestWithoutCustom(t *testing.T) {
	seed := []client.CustomPattern{
		{Name: "a", Re: "1"},
		{Name: "b", Re: "2"},
		{Name: "c", Re: "3"},
	}

	t.Run("removes the matching entry, keeps the rest in order", func(t *testing.T) {
		got := withoutCustom(seed, "b")
		if len(got) != 2 || got[0].Name != "a" || got[1].Name != "c" {
			t.Errorf("withoutCustom(seed, b) = %v, want [a c]", got)
		}
	})

	t.Run("no-op when the name is absent", func(t *testing.T) {
		got := withoutCustom(seed, "nonexistent")
		if len(got) != len(seed) {
			t.Fatalf("withoutCustom(seed, nonexistent) = %v, want all %d entries kept", got, len(seed))
		}
		for i := range got {
			if got[i] != seed[i] {
				t.Errorf("withoutCustom(seed, nonexistent)[%d] = %v, want %v", i, got[i], seed[i])
			}
		}
	})

	t.Run("empty input stays empty", func(t *testing.T) {
		got := withoutCustom(nil, "anything")
		if len(got) != 0 {
			t.Errorf("withoutCustom(nil, anything) = %v, want empty", got)
		}
	})
}