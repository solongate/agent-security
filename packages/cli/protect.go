// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
)

func protectUsage() string {
	return usage("solongate protect", "paths the agent may not touch", []usageRow{
		row("protect <path>", "add a path, and lock it with the OS"),
		row("protect list", "every protected path, and what is holding it"),
		row("protect remove <path>", "drop a path and lift its lock"),
		line(""),
		row("protect require-sandbox on|off", "refuse calls from agents not started by `solongate run`"),
	})
}

func runProtect(ctx context.Context, c *client.Client, p parsedArgs) (int, error) {
	sub := p.positional(0)
	switch sub {
	case "", "list":
		return protectList(ctx, c)
	case "help":
		errln(protectUsage())
		return 0, nil
	case "remove", "rm":
		return protectRemove(ctx, c, p.positional(1))
	case "require-sandbox":
		return protectRequireSandbox(ctx, c, p.positional(1))
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

	errln("")
	if len(paths) == 0 {
		errln("  " + dim("No protected paths. `solongate protect <path>` adds one."))
		errln("")
		return 0, nil
	}

	errln("  " + bold("Protected paths"))
	errln("")
	for _, path := range paths {
		lock := config.CheckLock(path)
		mark := red("✗")
		switch {
		case lock.Immutable:
			mark = green("✓")
		case lock.Held():
			mark = yellow("!")
		}
		errln("  " + mark + " " + path)
		errln("      " + dim("os lock    ") + lockColour(lock))
		errln("      " + dim("guard      ") + green("refuses a tool call that names it"))
		errln("      " + dim("sandbox    ") + sandboxLine(needSandbox))
	}
	errln("")
	if !needSandbox {
		errln("  " + dim("An agent started outside `solongate run` is held only by the two"))
		errln("  " + dim("above. `solongate protect require-sandbox on` refuses those calls."))
		errln("")
	}
	return 0, nil
}

func lockColour(l config.Lock) string {
	switch {
	case l.Immutable:
		return green(l.Summary())
	case l.Held():
		return yellow(l.Summary())
	default:
		return red(l.Summary())
	}
}

func sandboxLine(required bool) string {
	if required {
		return green("required · a call from outside it is refused")
	}
	return yellow("applied when started with `solongate run`, not required")
}

func protectAdd(ctx context.Context, c *client.Client, path string) (int, error) {
	if strings.TrimSpace(path) == "" {
		errln(protectUsage())
		return 1, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return 1, err
	}
	abs = filepath.Clean(abs)
	if _, err := os.Stat(abs); err != nil {
		errln("")
		errln("  " + red("There is nothing at ") + abs)
		errln("  " + dim("Protect something that exists; the lock is put on the file itself."))
		errln("")
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
			errln("")
			errln("  " + dim("Already protected.") + "  " + lockColour(lock))
			errln("")
			return 0, nil
		}
	}
	if err := c.Settings.SetProtectedPaths(ctx, append(paths, abs)); err != nil {
		return 1, err
	}

	errln("")
	errln("  " + green("✓ ") + abs)
	errln("")
	errln("  " + dim("os lock    ") + lockColour(lock))
	errln("  " + dim("guard      ") + green("refuses a tool call that names it"))
	errln("  " + dim("sandbox    ") + sandboxLine(false))
	errln("")

	if !lock.Immutable {
		errln("  " + yellow("The file cannot be overwritten. It can still be deleted."))
		errln("  " + dim("Start your agent with `solongate run -- <agent>` and the sandbox"))
		errln("  " + dim("closes that too, for anything it starts."))
		errln("")
		errln("  " + dim("One more cost, inside `solongate run`: this file's directory is"))
		errln("  " + dim("granted listing and creating but not writing, because a write"))
		errln("  " + dim("grant on a directory reaches everything under it, this file"))
		errln("  " + dim("included. A file your agent creates there cannot then be written"))
		errln("  " + dim("until it restarts."))
		errln("")
		errln("  " + dim("Both costs come from the same missing capability, and both go"))
		errln("  " + dim("away together:"))
		errln("")
		errln("      " + cyan("sudo chattr +i "+abs))
		errln("")
		errln("  " + dim("Then the flag holds the file in the inode, below the layer"))
		errln("  " + dim("`run` works in, and the directory is granted whole."))
		errln("")
	}
	return 0, nil
}

func askForRoot(path string) (bool, error) {
	errln("")
	errln("  " + bold("This needs one command as root, and here is exactly why."))
	errln("")
	errln("  " + dim("The lock means nothing on this machine can delete or overwrite the"))
	errln("  " + dim("file, including a program running as you. On macOS and Windows"))
	errln("  " + dim("SolonGate does that with no special permission at all."))
	errln("")
	errln("  " + dim("Linux has no unprivileged equivalent. The immutable flag is set by"))
	errln("  " + dim("the kernel and setting it needs CAP_LINUX_IMMUTABLE. One command"))
	errln("  " + dim("runs as root and it is this one:"))
	errln("")
	errln("      " + cyan("sudo chattr +i "+path))
	errln("")
	errln("  " + dim("Nothing else is elevated. No service is installed, no privileged"))
	errln("  " + dim("helper is kept, and you are not asked again until you protect"))
	errln("  " + dim("another path. `solongate protect remove` runs `sudo chattr -i` on"))
	errln("  " + dim("the same file."))
	errln("")
	errln("  " + dim("If you say no: the file is set to 0444, which stops it being"))
	errln("  " + dim("overwritten and ") + yellow("does not stop it being deleted") + dim("."))
	errln("")

	errln("  " + dim("And inside `solongate run`: the flag is what lets this file's"))
	errln("  " + dim("directory stay fully writable. Without it the directory is"))
	errln("  " + dim("granted listing and creating only, so a file your agent makes"))
	errln("  " + dim("there cannot then be written until it restarts."))
	errln("")

	if !askYes("  Run that one command as root? [y/N] ") {
		errln("")
		errln("  " + dim("Not elevated. Continuing with the weaker lock."))
		return false, nil
	}

	if err := runInteractive("sudo", "-v"); err != nil {
		errln("")
		errln("  " + yellow("sudo did not authenticate. Continuing with the weaker lock."))
		return false, nil
	}
	return true, nil
}

func askYes(prompt string) bool {
	errPrint(prompt)
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
		errln(protectUsage())
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
		errln("")
		errln("  " + dim(abs+" is not protected."))
		errln("")
		return 1, nil
	}

	withSudo := false
	if runtime.GOOS == "linux" && config.CheckLock(abs).Immutable && config.NeedsRootOnLinux() {
		errln("")
		errln("  " + dim("Lifting the immutable flag needs root, the same way setting it did:"))
		errln("")
		errln("      " + cyan("sudo chattr -i "+abs))
		errln("")
		if askYes("  Run it? [y/N] ") {
			withSudo = runInteractive("sudo", "-v") == nil
		}
	}

	lock := config.UnlockPath(abs, withSudo)
	if err := c.Settings.SetProtectedPaths(ctx, kept); err != nil {
		return 1, err
	}

	errln("")
	errln("  " + green("✓ no longer protected: ") + abs)
	still := config.CheckLock(abs)
	if still.Held() {
		errln("  " + yellow("The OS lock is still on it: ") + still.Summary())
		if lock.Err != "" {
			errln("  " + dim(lock.Err))
		}
	}
	errln("")
	return 0, nil
}

func protectRequireSandbox(ctx context.Context, c *client.Client, arg string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(arg)) {
	case "on", "true", "yes":
		errln("")
		errln("  " + bold("This fails closed, which is the point and also the cost."))
		errln("")
		errln("  " + dim("Every tool call from an agent that was not started with"))
		errln("  " + cyan("  solongate run -- <agent>") + dim("  is refused. Not the calls that touch a"))
		errln("  " + dim("protected path: all of them. An agent you start the usual way"))
		errln("  " + dim("stops working until you start it through SolonGate."))
		errln("")
		errln("  " + dim("Turn it off again with `solongate protect require-sandbox off`,"))
		errln("  " + dim("which is a command only a person at a terminal can run."))
		errln("")
		if !askYes("  Turn it on? [y/N] ") {
			errln("")
			errln("  " + dim("Left off."))
			errln("")
			return 0, nil
		}
		if err := c.Settings.SetRequireSandbox(ctx, true); err != nil {
			return 1, err
		}
		errln("")
		errln("  " + green("✓ on") + dim(" · agents outside the sandbox are refused"))
		errln("")
		return 0, nil

	case "off", "false", "no":
		if err := c.Settings.SetRequireSandbox(ctx, false); err != nil {
			return 1, err
		}
		errln("")
		errln("  " + green("✓ off") + dim(" · the OS lock and the guard still apply"))
		errln("")
		return 0, nil

	case "":
		on, err := c.Settings.RequireSandbox(ctx)
		if err != nil {
			return 1, err
		}
		errln("")
		if on {
			errln("  " + green("on") + dim(" · a call from outside `solongate run` is refused"))
		} else {
			errln("  " + yellow("off") + dim(" · calls from any agent are judged normally"))
		}
		errln("")
		return 0, nil
	}
	errln(protectUsage())
	return 1, nil
}