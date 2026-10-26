// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build !windows

package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
)

func TestRunProtectDispatch(t *testing.T) {
	newHome(t)
	c := client.New()
	ctx := context.Background()

	t.Run("empty sub lists", func(t *testing.T) {
		out := captureOutput(t, func() {
			code, err := runProtect(ctx, c, cliutil.Parse(nil))
			if code != 0 || err != nil {
				t.Errorf("runProtect() = (%d, %v), want (0, nil)", code, err)
			}
		})
		if !strings.Contains(out, "No protected paths") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run(`"list" lists`, func(t *testing.T) {
		out := captureOutput(t, func() {
			code, err := runProtect(ctx, c, cliutil.Parse([]string{"list"}))
			if code != 0 || err != nil {
				t.Errorf("runProtect(list) = (%d, %v), want (0, nil)", code, err)
			}
		})
		if !strings.Contains(out, "No protected paths") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run(`"help" prints usage`, func(t *testing.T) {
		out := captureOutput(t, func() {
			code, err := runProtect(ctx, c, cliutil.Parse([]string{"help"}))
			if code != 0 || err != nil {
				t.Errorf("runProtect(help) = (%d, %v), want (0, nil)", code, err)
			}
		})
		if !strings.Contains(out, "solongate policy protect") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run(`"remove" delegates to protectRemove`, func(t *testing.T) {
		out := captureOutput(t, func() {
			code, err := runProtect(ctx, c, cliutil.Parse([]string{"remove", "/nowhere"}))
			if code != 1 || err != nil {
				t.Errorf("runProtect(remove) = (%d, %v), want (1, nil)", code, err)
			}
		})
		if !strings.Contains(out, "is not protected") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run(`"rm" is an alias for remove`, func(t *testing.T) {
		out := captureOutput(t, func() {
			code, err := runProtect(ctx, c, cliutil.Parse([]string{"rm", "/nowhere"}))
			if code != 1 || err != nil {
				t.Errorf("runProtect(rm) = (%d, %v), want (1, nil)", code, err)
			}
		})
		if !strings.Contains(out, "is not protected") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run(`"require-sandbox" delegates to protectRequireSandbox`, func(t *testing.T) {
		out := captureOutput(t, func() {
			code, err := runProtect(ctx, c, cliutil.Parse([]string{"require-sandbox"}))
			if code != 0 || err != nil {
				t.Errorf("runProtect(require-sandbox) = (%d, %v), want (0, nil)", code, err)
			}
		})
		if !strings.Contains(out, "calls from any agent are judged normally") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("anything else delegates to protectAdd", func(t *testing.T) {
		out := captureOutput(t, func() {
			code, err := runProtect(ctx, c, cliutil.Parse([]string{"/definitely/does/not/exist"}))
			if code != 1 || err != nil {
				t.Errorf("runProtect(path) = (%d, %v), want (1, nil)", code, err)
			}
		})
		if !strings.Contains(out, "There is nothing at") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})
}

func TestAskForRootDeclines(t *testing.T) {
	// Only the "no" path is exercised: saying "yes" would run real sudo via
	// cliutil.RunInteractive("sudo", "-v"), which must never happen in a test.
	withStdin(t, "n\n")
	out := captureOutput(t, func() {
		ok, err := askForRoot("/some/protected/file")
		if err != nil {
			t.Errorf("askForRoot() error = %v, want nil", err)
		}
		if ok {
			t.Errorf("askForRoot() = true, want false when the user declines")
		}
	})
	if !strings.Contains(out, "Not elevated") {
		t.Errorf("unexpected output:\n%s", out)
	}
}

// withDecline pipes a single "n\n" into stdin, enough for one askYes
// prompt. protectAdd always asks before locking in this sandbox, since the
// test process has neither root nor CAP_LINUX_IMMUTABLE.
func withDecline(t *testing.T) { withStdin(t, "n\n") }

// writeProtectableFile creates a plain file in a fresh temp dir, restoring
// its permissions after the test so os.RemoveAll can clean it up even if a
// lock command changed its mode bits.
func writeProtectableFile(t *testing.T) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), "secret.env")
	if err := os.WriteFile(target, []byte("X=1"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(target, 0o644) })
	return target
}

// newProtectedTarget writes a protectable file and protects it via
// protectAdd (declining the elevation prompt), for tests that need an
// already-protected path to exercise remove/list/sandbox-state behavior.
func newProtectedTarget(t *testing.T, ctx context.Context, c *client.Client) string {
	t.Helper()
	target := writeProtectableFile(t)
	withDecline(t)
	captureOutput(t, func() {
		if code, err := protectAdd(ctx, c, target); code != 0 || err != nil {
			t.Fatalf("protectAdd() = (%d, %v), want (0, nil)", code, err)
		}
	})
	return target
}

func TestProtectAdd(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		newHome(t)
		c := client.New()
		out := captureOutput(t, func() {
			code, err := protectAdd(context.Background(), c, "   ")
			if code != 1 || err != nil {
				t.Errorf("protectAdd(blank) = (%d, %v), want (1, nil)", code, err)
			}
		})
		if !strings.Contains(out, "solongate policy protect") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("path does not exist", func(t *testing.T) {
		newHome(t)
		c := client.New()
		missing := filepath.Join(t.TempDir(), "nope.txt")
		out := captureOutput(t, func() {
			code, err := protectAdd(context.Background(), c, missing)
			if code != 1 || err != nil {
				t.Errorf("protectAdd(missing) = (%d, %v), want (1, nil)", code, err)
			}
		})
		if !strings.Contains(out, "There is nothing at") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("protects a real file, then is idempotent", func(t *testing.T) {
		newHome(t)
		c := client.New()
		ctx := context.Background()
		target := writeProtectableFile(t)

		withDecline(t)
		out := captureOutput(t, func() {
			code, err := protectAdd(ctx, c, target)
			if code != 0 || err != nil {
				t.Fatalf("protectAdd() = (%d, %v), want (0, nil)", code, err)
			}
		})
		if !strings.Contains(out, target) {
			t.Errorf("unexpected output:\n%s", out)
		}

		paths, err := c.Settings.ProtectedPaths(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(paths) != 1 || paths[0] != target {
			t.Errorf("ProtectedPaths() = %v, want [%s]", paths, target)
		}

		// Calling it again still asks (NeedsRootOnLinux is checked before the
		// already-protected check), then reports the already-protected case.
		withDecline(t)
		out = captureOutput(t, func() {
			code, err := protectAdd(ctx, c, target)
			if code != 0 || err != nil {
				t.Fatalf("protectAdd() second call = (%d, %v), want (0, nil)", code, err)
			}
		})
		if !strings.Contains(out, "Already protected") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})
}

func TestProtectRemove(t *testing.T) {
	invalid := []struct {
		name       string
		path       string
		wantSubstr string
	}{
		{"empty path", "  ", "solongate policy protect"},
		{"not currently protected", "/never/added", "is not protected"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			newHome(t)
			c := client.New()
			out := captureOutput(t, func() {
				code, err := protectRemove(context.Background(), c, tc.path)
				if code != 1 || err != nil {
					t.Errorf("protectRemove(%q) = (%d, %v), want (1, nil)", tc.path, code, err)
				}
			})
			if !strings.Contains(out, tc.wantSubstr) {
				t.Errorf("unexpected output:\n%s", out)
			}
		})
	}

	t.Run("protect then remove round trip", func(t *testing.T) {
		newHome(t)
		c := client.New()
		ctx := context.Background()
		target := newProtectedTarget(t, ctx, c)

		// The chmod-only fallback lock (no root/CAP_LINUX_IMMUTABLE here)
		// isn't Immutable, so protectRemove's root-elevation branch is
		// skipped entirely and no stdin is needed for this call.
		out := captureOutput(t, func() {
			code, err := protectRemove(ctx, c, target)
			if code != 0 || err != nil {
				t.Fatalf("protectRemove() = (%d, %v), want (0, nil)", code, err)
			}
		})
		if !strings.Contains(out, "no longer protected") {
			t.Errorf("unexpected output:\n%s", out)
		}

		paths, err := c.Settings.ProtectedPaths(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(paths) != 0 {
			t.Errorf("ProtectedPaths() = %v, want empty", paths)
		}

		still := config.CheckLock(target)
		if still.Held() {
			t.Errorf("expected the lock to be fully lifted, got %+v", still)
		}
	})
}

func TestProtectList(t *testing.T) {
	t.Run("zero paths", func(t *testing.T) {
		newHome(t)
		c := client.New()
		out := captureOutput(t, func() {
			code, err := protectList(context.Background(), c)
			if code != 0 || err != nil {
				t.Errorf("protectList() = (%d, %v), want (0, nil)", code, err)
			}
		})
		if !strings.Contains(out, "No protected paths") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("a protected path, sandbox not required", func(t *testing.T) {
		newHome(t)
		c := client.New()
		ctx := context.Background()
		target := newProtectedTarget(t, ctx, c)

		out := captureOutput(t, func() {
			code, err := protectList(ctx, c)
			if code != 0 || err != nil {
				t.Errorf("protectList() = (%d, %v), want (0, nil)", code, err)
			}
		})
		if !strings.Contains(out, target) {
			t.Errorf("unexpected output:\n%s", out)
		}
		if !strings.Contains(out, "applied when started with `solongate run`, not required") {
			t.Errorf("unexpected output:\n%s", out)
		}
		if !strings.Contains(out, "An agent started outside `solongate run` is held only by the two") {
			t.Errorf("expected the require-sandbox hint when it is off:\n%s", out)
		}
	})

	t.Run("a protected path, sandbox required", func(t *testing.T) {
		newHome(t)
		c := client.New()
		ctx := context.Background()
		_ = newProtectedTarget(t, ctx, c)
		if err := c.Settings.SetRequireSandbox(ctx, true); err != nil {
			t.Fatal(err)
		}

		out := captureOutput(t, func() {
			code, err := protectList(ctx, c)
			if code != 0 || err != nil {
				t.Errorf("protectList() = (%d, %v), want (0, nil)", code, err)
			}
		})
		if !strings.Contains(out, "required · a call from outside it is refused") {
			t.Errorf("unexpected output:\n%s", out)
		}
		if strings.Contains(out, "An agent started outside `solongate run` is held only by the two") {
			t.Errorf("the require-sandbox hint should not print once it is on:\n%s", out)
		}
	})
}

func TestProtectRequireSandbox(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(t *testing.T, ctx context.Context, c *client.Client)
		arg        string
		wantCode   int
		wantSubstr string
		checkOn    bool
		wantOn     bool
	}{
		{
			name:       "on declined leaves it off",
			setup:      func(t *testing.T, ctx context.Context, c *client.Client) { withStdin(t, "n\n") },
			arg:        "on",
			wantSubstr: "Left off",
			checkOn:    true,
			wantOn:     false,
		},
		{
			name:       "on confirmed turns it on",
			setup:      func(t *testing.T, ctx context.Context, c *client.Client) { withStdin(t, "y\n") },
			arg:        "true",
			wantSubstr: "✓ on",
			checkOn:    true,
			wantOn:     true,
		},
		{
			name: "off never prompts",
			setup: func(t *testing.T, ctx context.Context, c *client.Client) {
				if err := c.Settings.SetRequireSandbox(ctx, true); err != nil {
					t.Fatal(err)
				}
			},
			arg:        "no",
			wantSubstr: "✓ off",
			checkOn:    true,
			wantOn:     false,
		},
		{
			name:       "empty arg reports current state (off)",
			arg:        "",
			wantSubstr: "calls from any agent are judged normally",
		},
		{
			name: "empty arg reports current state (on)",
			setup: func(t *testing.T, ctx context.Context, c *client.Client) {
				if err := c.Settings.SetRequireSandbox(ctx, true); err != nil {
					t.Fatal(err)
				}
			},
			arg:        "",
			wantSubstr: "a call from outside `solongate run` is refused",
		},
		{
			name:       "unrecognized arg",
			arg:        "bogus",
			wantCode:   1,
			wantSubstr: "solongate policy protect",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			newHome(t)
			c := client.New()
			ctx := context.Background()
			if tc.setup != nil {
				tc.setup(t, ctx, c)
			}
			out := captureOutput(t, func() {
				code, err := protectRequireSandbox(ctx, c, tc.arg)
				if code != tc.wantCode || err != nil {
					t.Errorf("protectRequireSandbox(%q) = (%d, %v), want (%d, nil)", tc.arg, code, err, tc.wantCode)
				}
			})
			if !strings.Contains(out, tc.wantSubstr) {
				t.Errorf("unexpected output:\n%s", out)
			}
			if tc.checkOn {
				on, err := c.Settings.RequireSandbox(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if on != tc.wantOn {
					t.Errorf("RequireSandbox() = %v, want %v", on, tc.wantOn)
				}
			}
		})
	}
}