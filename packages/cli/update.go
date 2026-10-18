// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/core/install"
	"github.com/solongate/agent-security/packages/core/term"
)

func RunUpdate(args []string) int {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "update takes no arguments")
		return 2
	}

	root, ok := install.InstalledFrom()
	if !ok {
		return noSourceToUpdateFrom()
	}

	before := install.InstalledGuardVersion()

	fmt.Fprint(os.Stderr, "         "+term.Bold+"SolonGate"+term.Reset+"  ")
	typeOut("updating from " + root)

	if code := restoreInstallArtifacts(root); code != 0 {
		return code
	}

	head, _ := gitOutput(root, "rev-parse", "HEAD")

	rng := config.UpdateRangeOf(config.LoadTUIConfig())
	typeOut("         range " + rng + ": " + rangeOneLiner(rng))

	var code int
	if rng == config.UpdateRangeShort {
		code = moveToBranchTip(root)
	} else {
		code = moveToNewestRelease(root)
	}
	if code != 0 {
		return code
	}

	after, _ := gitOutput(root, "rev-parse", "HEAD")
	if head != "" && head == after {
		markOK("Already on the newest version.")
	}

	script := filepath.Join(root, "scripts", "shell", "install.sh")
	if !install.Exists(script) {
		fmt.Fprintln(os.Stderr, "         "+script+" is missing, so there is nothing to run.")
		return 1
	}
	if code := step(root, "Rebuilding and reinstalling", shInterpreter(), script, "--yes"); code != 0 {
		return code
	}

	now := install.InstalledGuardVersion()
	switch {
	case before == nil && now != nil:
		markOK("SolonGate installed, guard v" + strconv.Itoa(*now) + ".")
	case before != nil && now != nil && *before != *now:
		markOK("Updated: guard v" + strconv.Itoa(*before) + " to v" + strconv.Itoa(*now) + ".")
	case now != nil:
		markOK("Up to date: guard v" + strconv.Itoa(*now) + ".")
	default:
		markOK("Done.")
	}
	return 0
}

func quietStep(dir, label, name string, args ...string) int {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out

	stop := spin(label)
	err := cmd.Run()
	stop()

	if err != nil {
		markNo(label)
		if text := strings.TrimSpace(out.String()); text != "" {
			for _, line := range strings.Split(text, "\n") {
				fmt.Fprintln(os.Stderr, "         "+line)
			}
		}
		var exit *exec.ExitError
		if ok := asExitError(err, &exit); ok {
			return exit.ExitCode()
		}
		return 1
	}
	markOK(label)
	return 0
}

func markOK(text string) {
	fmt.Fprintf(os.Stderr, "%s[  OK  ]%s ", term.Green, term.Reset)
	typeOut(text)
}

func markNo(text string) {
	fmt.Fprintf(os.Stderr, "%s[FAILED]%s ", term.Red, term.Reset)
	typeOut(text)
}

func typeOut(text string) {
	if !isTerminal(os.Stderr) {
		fmt.Fprintln(os.Stderr, text)
		return
	}
	for _, r := range text {
		fmt.Fprintf(os.Stderr, "%c", r)
		time.Sleep(typeDelay)
	}
	fmt.Fprintln(os.Stderr)
}

const typeDelay = 3 * time.Millisecond

func spin(label string) func() {
	if !isTerminal(os.Stderr) {
		fmt.Fprintln(os.Stderr, "         "+label+"...")
		return func() {}
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for i := 0; ; i++ {
			select {
			case <-done:
				fmt.Fprint(os.Stderr, "\r\x1b[2K")
				return
			default:
			}
			fmt.Fprintf(os.Stderr, "\r\x1b[2K         %s%s", label, strings.Repeat(".", i%3+1))
			time.Sleep(350 * time.Millisecond)
		}
	}()
	return func() { close(done); <-finished }
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// shInterpreter resolves /bin/sh, the POSIX-guaranteed location for the
// system shell, instead of trusting a PATH lookup; it falls back to the bare
// name only if that path doesn't exist on this machine.
func shInterpreter() string {
	if info, err := os.Stat("/bin/sh"); err == nil && !info.IsDir() {
		return "/bin/sh"
	}
	return "sh"
}

func step(dir, label, name string, args ...string) int {
	fmt.Fprintln(os.Stderr, "         "+label+"...")
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if ok := asExitError(err, &exit); ok {
			return exit.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "         "+label+" failed: "+err.Error())
		return 1
	}
	return 0
}

func asExitError(err error, out **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*out = e
	}
	return ok
}

func gitOutput(dir string, args ...string) (string, bool) {
	git, err := exec.LookPath("git")
	if err != nil {
		return "", false
	}
	cmd := exec.Command(git, args...)
	cmd.Dir = dir
	b, err := cmd.Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

func noSourceToUpdateFrom() int {
	w := bufio.NewWriter(os.Stderr)
	defer w.Flush()
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  This install did not come from a checkout, so there is nothing to pull.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  SolonGate is distributed over git and builds from source. Clone it and run")
	fmt.Fprintln(w, "  the install script once; `update` will remember where it is:")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "      git clone https://github.com/solongate/agent-security")
	fmt.Fprintln(w, "      cd agent-security && ./scripts/shell/install.sh")
	fmt.Fprintln(w)
	return 1
}

var installArtifacts = []string{
	"pnpm-lock.yaml",
	"packages/hooks/package.json",
	"packages/hooks/guard.bundled.mjs",
}

func rangeOneLiner(rng string) string {
	if rng == config.UpdateRangeShort {
		return "every commit on the branch, including ones no release has covered"
	}
	return "tagged releases only"
}

func moveToBranchTip(root string) int {
	if detached(root) {
		branch := defaultBranch(root)
		if c := quietStep(root, "Returning to "+branch, "git", "checkout", branch); c != 0 {
			return c
		}
	}
	if c := quietStep(root, "Fetching the newest commit", "git", "pull", "--ff-only"); c != 0 {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "         The pull failed. Most often that is a local change in the checkout:")
		fmt.Fprintln(os.Stderr, "            cd "+root+" && git status")
		fmt.Fprintln(os.Stderr)
		return 1
	}
	return 0
}

func moveToNewestRelease(root string) int {
	if c := quietStep(root, "Fetching releases", "git", "fetch", "--tags", "--force", "origin"); c != 0 {
		return c
	}
	tag, _ := gitOutput(root, "tag", "-l", "v*", "--sort=-v:refname")
	tag = strings.TrimSpace(strings.SplitN(tag, "\n", 2)[0])
	if tag == "" {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "         There are no release tags in this checkout, so the long range has")
		fmt.Fprintln(os.Stderr, "         nothing to move to. `solongate range short` follows the branch instead.")
		fmt.Fprintln(os.Stderr)
		return 1
	}
	if c := quietStep(root, "Checking out "+tag, "git", "checkout", "--detach", tag); c != 0 {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "         The checkout failed. Most often that is a local change:")
		fmt.Fprintln(os.Stderr, "            cd "+root+" && git status")
		fmt.Fprintln(os.Stderr)
		return 1
	}
	return 0
}

func detached(root string) bool {
	out, ok := gitOutput(root, "symbolic-ref", "-q", "HEAD")
	return !ok || strings.TrimSpace(out) == ""
}

func defaultBranch(root string) string {
	out, ok := gitOutput(root, "symbolic-ref", "refs/remotes/origin/HEAD")
	if ok {
		if i := strings.LastIndex(strings.TrimSpace(out), "/"); i >= 0 {
			if name := strings.TrimSpace(out)[i+1:]; name != "" {
				return name
			}
		}
	}
	return "main"
}

func restoreInstallArtifacts(root string) int {
	out, ok := gitOutput(root, "status", "--porcelain")
	if !ok || strings.TrimSpace(out) == "" {
		return 0
	}

	var generated, foreign []string
	for _, line := range strings.Split(out, "\n") {
		if len(line) < 4 {
			continue
		}

		if strings.HasPrefix(line, "??") {
			continue
		}
		path := strings.TrimSpace(line[2:])

		if i := strings.Index(path, " -> "); i >= 0 {
			path = path[i+4:]
		}
		path = strings.Trim(path, `"`)
		if containsPath(installArtifacts, path) {
			generated = append(generated, path)
		} else {
			foreign = append(foreign, path)
		}
	}

	if len(foreign) > 0 {
		fmt.Fprintln(os.Stderr)

		markNo("Update stopped: the checkout has local changes.")
		fmt.Fprintln(os.Stderr, "         Not the install's own, so they are yours to keep:")
		for _, f := range foreign {
			fmt.Fprintln(os.Stderr, "            "+f)
		}
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "         Those are yours, so nothing here will throw them away. Commit or")
		fmt.Fprintln(os.Stderr, "         stash them and run update again:")
		fmt.Fprintln(os.Stderr, "            cd "+root+" && git status")
		fmt.Fprintln(os.Stderr)
		return 1
	}

	if len(generated) == 0 {
		return 0
	}

	args := append([]string{"checkout", "--"}, generated...)
	if _, ok := gitOutput(root, args...); !ok {
		fmt.Fprintln(os.Stderr)
		markNo("Update stopped: could not restore what the last install rewrote.")
		fmt.Fprintln(os.Stderr, "         These are the files it writes every time:")
		for _, g := range generated {
			fmt.Fprintln(os.Stderr, "            "+g)
		}
		fmt.Fprintln(os.Stderr)
		return 1
	}
	fmt.Println("  Reset " + strconv.Itoa(len(generated)) + " file(s) the last install rewrote (" +
		strings.Join(generated, ", ") + ").")
	return 0
}

func containsPath(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}