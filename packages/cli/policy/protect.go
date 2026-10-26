// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package policy

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
)

func protectUsage() string {
	return cliutil.Usage("solongate policy protect", "paths the agent may not touch", []cliutil.UsageRow{
		cliutil.Row("<path>", "add a path, and lock it with the OS"),
		cliutil.Row("list", "every protected path, and what is holding it"),
		cliutil.Row("remove <path>", "drop a path and lift its lock"),
		cliutil.Line(""),
		cliutil.Row("require-sandbox on|off", "refuse calls from agents not started by `solongate run`"),
	})
}

func runProtect(ctx context.Context, c *client.Client, p cliutil.ParsedArgs) (int, error) {
	sub := p.Positional(0)
	switch sub {
	case "", "list":
		return protectList(ctx, c)
	case "help":
		cliutil.Errln(protectUsage())
		return 0, nil
	case "remove", "rm":
		return protectRemove(ctx, c, p.Positional(1))
	case "require-sandbox":
		return protectRequireSandbox(ctx, c, p.Positional(1))
	default:
		return protectAdd(ctx, c, sub)
	}
}

func protectList(ctx context.Context, c *client.Client) (int, error) {
	paths, err := c.Settings.ProtectedPaths(ctx)
	if err != nil {
		return 1, err
	}
	needSandbox, _ := c.Settings.RequireSandbox(ctx)

	cliutil.Errln("")
	if len(paths) == 0 {
		cliutil.Errln("  " + cliutil.Dim("No protected paths. `solongate policy protect <path>` adds one."))
		cliutil.Errln("")
		return 0, nil
	}

	cliutil.Errln("  " + cliutil.Bold("Protected paths"))
	cliutil.Errln("")
	for _, path := range paths {
		lock := config.CheckLock(path)
		mark := cliutil.Red("✗")
		switch {
		case lock.Immutable:
			mark = cliutil.Green("✓")
		case lock.Held():
			mark = cliutil.Yellow("!")
		}
		cliutil.Errln("  " + mark + " " + path)
		cliutil.Errln("      " + cliutil.Dim("os lock    ") + lockColour(lock))
		cliutil.Errln("      " + cliutil.Dim("guard      ") + cliutil.Green("refuses a tool call that names it"))
		cliutil.Errln("      " + cliutil.Dim("sandbox    ") + sandboxLine(needSandbox))
	}
	cliutil.Errln("")
	if !needSandbox {
		cliutil.Errln("  " + cliutil.Dim("An agent started outside `solongate run` is held only by the two"))
		cliutil.Errln("  " + cliutil.Dim("above. `solongate policy protect require-sandbox on` refuses those calls."))
		cliutil.Errln("")
	}
	return 0, nil
}

func lockColour(l config.Lock) string {
	switch {
	case l.Immutable:
		return cliutil.Green(l.Summary())
	case l.Held():
		return cliutil.Yellow(l.Summary())
	default:
		return cliutil.Red(l.Summary())
	}
}

func sandboxLine(required bool) string {
	if required {
		return cliutil.Green("required · a call from outside it is refused")
	}
	return cliutil.Yellow("applied when started with `solongate run`, not required")
}

func protectAdd(ctx context.Context, c *client.Client, path string) (int, error) {
	if strings.TrimSpace(path) == "" {
		cliutil.Errln(protectUsage())
		return 1, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return 1, err
	}
	abs = filepath.Clean(abs)
	if _, err := os.Stat(abs); err != nil {
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Red("There is nothing at ") + abs)
		cliutil.Errln("  " + cliutil.Dim("Protect something that exists; the lock is put on the file itself."))
		cliutil.Errln("")
		return 1, nil
	}

	withSudo := false
	if config.NeedsRootOnLinux() {
		ok, err := askForRoot(abs)
		if err != nil {
			return 1, err
		}
		withSudo = ok
	}

	lock := config.LockPath(abs, withSudo)

	paths, err := c.Settings.ProtectedPaths(ctx)
	if err != nil {
		return 1, err
	}
	for _, p := range paths {
		if p == abs {
			cliutil.Errln("")
			cliutil.Errln("  " + cliutil.Dim("Already protected.") + "  " + lockColour(lock))
			cliutil.Errln("")
			return 0, nil
		}
	}
	if err := c.Settings.SetProtectedPaths(ctx, append(paths, abs)); err != nil {
		return 1, err
	}

	cliutil.Errln("")
	cliutil.Errln("  " + cliutil.Green("✓ ") + abs)
	cliutil.Errln("")
	cliutil.Errln("  " + cliutil.Dim("os lock    ") + lockColour(lock))
	cliutil.Errln("  " + cliutil.Dim("guard      ") + cliutil.Green("refuses a tool call that names it"))
	cliutil.Errln("  " + cliutil.Dim("sandbox    ") + sandboxLine(false))
	cliutil.Errln("")

	if !lock.Immutable {
		cliutil.Errln("  " + cliutil.Yellow("The file cannot be overwritten. It can still be deleted."))
		cliutil.Errln("  " + cliutil.Dim("Start your agent with `solongate run -- <agent>` and the sandbox"))
		cliutil.Errln("  " + cliutil.Dim("closes that too, for anything it starts."))
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Dim("One more cost, inside `solongate run`: this file's directory is"))
		cliutil.Errln("  " + cliutil.Dim("granted listing and creating but not writing, because a write"))
		cliutil.Errln("  " + cliutil.Dim("grant on a directory reaches everything under it, this file"))
		cliutil.Errln("  " + cliutil.Dim("included. A file your agent creates there cannot then be written"))
		cliutil.Errln("  " + cliutil.Dim("until it restarts."))
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Dim("Both costs come from the same missing capability, and both go"))
		cliutil.Errln("  " + cliutil.Dim("away together:"))
		cliutil.Errln("")
		cliutil.Errln("      " + cliutil.Cyan("sudo chattr +i "+abs))
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Dim("Then the flag holds the file in the inode, below the layer"))
		cliutil.Errln("  " + cliutil.Dim("`run` works in, and the directory is granted whole."))
		cliutil.Errln("")
	}
	return 0, nil
}

func askForRoot(path string) (bool, error) {
	cliutil.Errln("")
	cliutil.Errln("  " + cliutil.Bold("This needs one command as root, and here is exactly why."))
	cliutil.Errln("")
	cliutil.Errln("  " + cliutil.Dim("The lock means nothing on this machine can delete or overwrite the"))
	cliutil.Errln("  " + cliutil.Dim("file, including a program running as you. On macOS and Windows"))
	cliutil.Errln("  " + cliutil.Dim("SolonGate does that with no special permission at all."))
	cliutil.Errln("")
	cliutil.Errln("  " + cliutil.Dim("Linux has no unprivileged equivalent. The immutable flag is set by"))
	cliutil.Errln("  " + cliutil.Dim("the kernel and setting it needs CAP_LINUX_IMMUTABLE. One command"))
	cliutil.Errln("  " + cliutil.Dim("runs as root and it is this one:"))
	cliutil.Errln("")
	cliutil.Errln("      " + cliutil.Cyan("sudo chattr +i "+path))
	cliutil.Errln("")
	cliutil.Errln("  " + cliutil.Dim("Nothing else is elevated. No service is installed, no privileged"))
	cliutil.Errln("  " + cliutil.Dim("helper is kept, and you are not asked again until you protect"))
	cliutil.Errln("  " + cliutil.Dim("another path. `solongate policy protect remove` runs `sudo chattr -i` on"))
	cliutil.Errln("  " + cliutil.Dim("the same file."))
	cliutil.Errln("")
	cliutil.Errln("  " + cliutil.Dim("If you say no: the file is set to 0444, which stops it being"))
	cliutil.Errln("  " + cliutil.Dim("overwritten and ") + cliutil.Yellow("does not stop it being deleted") + cliutil.Dim("."))
	cliutil.Errln("")

	cliutil.Errln("  " + cliutil.Dim("And inside `solongate run`: the flag is what lets this file's"))
	cliutil.Errln("  " + cliutil.Dim("directory stay fully writable. Without it the directory is"))
	cliutil.Errln("  " + cliutil.Dim("granted listing and creating only, so a file your agent makes"))
	cliutil.Errln("  " + cliutil.Dim("there cannot then be written until it restarts."))
	cliutil.Errln("")

	if !askYes("  Run that one command as root? [y/N] ") {
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Dim("Not elevated. Continuing with the weaker lock."))
		return false, nil
	}

	if err := cliutil.RunInteractive("sudo", "-v"); err != nil {
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Yellow("sudo did not authenticate. Continuing with the weaker lock."))
		return false, nil
	}
	return true, nil
}

func askYes(prompt string) bool {
	cliutil.ErrPrint(prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

func protectRemove(ctx context.Context, c *client.Client, path string) (int, error) {
	if strings.TrimSpace(path) == "" {
		cliutil.Errln(protectUsage())
		return 1, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return 1, err
	}
	abs = filepath.Clean(abs)

	paths, err := c.Settings.ProtectedPaths(ctx)
	if err != nil {
		return 1, err
	}
	kept := make([]string, 0, len(paths))
	found := false
	for _, p := range paths {
		if p == abs {
			found = true
			continue
		}
		kept = append(kept, p)
	}
	if !found {
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Dim(abs+" is not protected."))
		cliutil.Errln("")
		return 1, nil
	}

	withSudo := false
	if runtime.GOOS == "linux" && config.CheckLock(abs).Immutable && config.NeedsRootOnLinux() {
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Dim("Lifting the immutable flag needs root, the same way setting it did:"))
		cliutil.Errln("")
		cliutil.Errln("      " + cliutil.Cyan("sudo chattr -i "+abs))
		cliutil.Errln("")
		if askYes("  Run it? [y/N] ") {
			withSudo = cliutil.RunInteractive("sudo", "-v") == nil
		}
	}

	lock := config.UnlockPath(abs, withSudo)
	if err := c.Settings.SetProtectedPaths(ctx, kept); err != nil {
		return 1, err
	}

	cliutil.Errln("")
	cliutil.Errln("  " + cliutil.Green("✓ no longer protected: ") + abs)
	still := config.CheckLock(abs)
	if still.Held() {
		cliutil.Errln("  " + cliutil.Yellow("The OS lock is still on it: ") + still.Summary())
		if lock.Err != "" {
			cliutil.Errln("  " + cliutil.Dim(lock.Err))
		}
	}
	cliutil.Errln("")
	return 0, nil
}

func protectRequireSandbox(ctx context.Context, c *client.Client, arg string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(arg)) {
	case "on", "true", "yes":
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Bold("This fails closed, which is the point and also the cost."))
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Dim("Every tool call from an agent that was not started with"))
		cliutil.Errln("  " + cliutil.Cyan("  solongate run -- <agent>") + cliutil.Dim("  is refused. Not the calls that touch a"))
		cliutil.Errln("  " + cliutil.Dim("protected path: all of them. An agent you start the usual way"))
		cliutil.Errln("  " + cliutil.Dim("stops working until you start it through SolonGate."))
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Dim("Turn it off again with `solongate policy protect require-sandbox off`,"))
		cliutil.Errln("  " + cliutil.Dim("which is a command only a person at a terminal can run."))
		cliutil.Errln("")
		if !askYes("  Turn it on? [y/N] ") {
			cliutil.Errln("")
			cliutil.Errln("  " + cliutil.Dim("Left off."))
			cliutil.Errln("")
			return 0, nil
		}
		if err := c.Settings.SetRequireSandbox(ctx, true); err != nil {
			return 1, err
		}
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Green("✓ on") + cliutil.Dim(" · agents outside the sandbox are refused"))
		cliutil.Errln("")
		return 0, nil

	case "off", "false", "no":
		if err := c.Settings.SetRequireSandbox(ctx, false); err != nil {
			return 1, err
		}
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Green("✓ off") + cliutil.Dim(" · the OS lock and the guard still apply"))
		cliutil.Errln("")
		return 0, nil

	case "":
		on, err := c.Settings.RequireSandbox(ctx)
		if err != nil {
			return 1, err
		}
		cliutil.Errln("")
		if on {
			cliutil.Errln("  " + cliutil.Green("on") + cliutil.Dim(" · a call from outside `solongate run` is refused"))
		} else {
			cliutil.Errln("  " + cliutil.Yellow("off") + cliutil.Dim(" · calls from any agent are judged normally"))
		}
		cliutil.Errln("")
		return 0, nil
	}
	cliutil.Errln(protectUsage())
	return 1, nil
}
