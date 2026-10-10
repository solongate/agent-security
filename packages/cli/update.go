// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/core/install"
)

// `solongate update` — fetch the newest source and reinstall from it.
//
// WHY THIS COMMAND EXISTS AT ALL. `solongate doctor` has told people to run it for as
// long as there has been a doctor, and until now there was no such command: the one
// instruction the health check gives was a command that answered "Unknown command".
//
// And the thing it replaces is three steps somebody had to know by heart — change to a
// directory they may not remember, pull, run the install script — none of which is the
// user's problem. An update is one word.
//
// IT UPDATES FROM WHERE IT WAS INSTALLED FROM. The install writes that path down (see
// install.RecordInstallSource), because once the binaries are in the store nothing about
// their location says where they were built. No record means this was not a checkout
// install, and the honest answer there is to say so rather than guess.

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

	fmt.Println()
	fmt.Println("  Updating SolonGate from " + root)
	fmt.Println()

	// FETCH FIRST, AND SAY WHETHER ANYTHING CAME. A pull that changes nothing still costs
	// a full rebuild, and somebody watching it has no way to tell a no-op from a real
	// update unless it is said out loud.
	// THE INSTALL DIRTIES THE CHECKOUT IT WILL LATER PULL INTO.
	//
	// install.sh runs `pnpm install`, and pnpm rewrites pnpm-lock.yaml whenever the
	// manifest and the lock disagree about anything — including an optional package
	// it decides to drop. The build script rewrites packages/hooks/package.json for
	// the same class of reason. Both files are tracked, so one update later the
	// checkout has modifications nobody made, and the NEXT update dies on
	// `git pull --ff-only` before it reaches any of the work.
	//
	// The user never typed anything to cause that and has nothing to decide about
	// it, so the only honest behaviour is to put those files back and carry on. The
	// test is narrow on purpose: ONLY the files an install is known to write are
	// restored, and anything else stops the update exactly as it did before —
	// a real local edit is the user's and discarding it silently would be theft.
	if code := restoreInstallArtifacts(root); code != 0 {
		return code
	}

	head, _ := gitOutput(root, "rev-parse", "HEAD")

	rng := config.UpdateRangeOf(config.LoadTUIConfig())
	fmt.Println("  Update range: " + rng + " · " + rangeOneLiner(rng))
	fmt.Println()

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
		fmt.Println("  Already on the newest version.")
	}

	// REBUILD AND REINSTALL THROUGH install.sh, rather than repeating its steps here.
	// That script is what a person runs by hand and what the README documents; a second
	// implementation of the same four steps is a second thing to keep correct, and the
	// one that drifts is always the one nobody runs.
	//
	// --yes because this is already the answer to "do you want to update".
	script := filepath.Join(root, "install.sh")
	if !install.Exists(script) {
		fmt.Fprintln(os.Stderr, "  "+script+" is missing, so there is nothing to run.")
		return 1
	}
	if code := step(root, "Rebuilding and reinstalling", "sh", script, "--yes"); code != 0 {
		return code
	}

	now := install.InstalledGuardVersion()
	fmt.Println()
	switch {
	case before == nil && now != nil:
		fmt.Println("  ✓ SolonGate installed, guard v" + strconv.Itoa(*now) + ".")
	case before != nil && now != nil && *before != *now:
		fmt.Println("  ✓ Updated: guard v" + strconv.Itoa(*before) + " → v" + strconv.Itoa(*now) + ".")
	case now != nil:
		fmt.Println("  ✓ Up to date: guard v" + strconv.Itoa(*now) + ".")
	default:
		fmt.Println("  ✓ Done.")
	}
	fmt.Println("    Open a new terminal — hooks load when a session starts.")
	fmt.Println()
	return 0
}

// step runs one command with its output streamed through, so a build that takes a minute
// looks like a build taking a minute rather than a hang.
func step(dir, label, name string, args ...string) int {
	fmt.Println("  " + label + "…")
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
		fmt.Fprintln(os.Stderr, "  "+label+" failed: "+err.Error())
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
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	b, err := cmd.Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// noSourceToUpdateFrom explains the one case this command cannot handle, and names the
// two ways out rather than stopping at "not found".
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
	fmt.Fprintln(w, "      cd agent-security && ./install.sh")
	fmt.Fprintln(w)
	return 1
}

// installArtifacts are the TRACKED files an install rewrites inside the checkout.
//
// Each one is generated, not authored: pnpm owns the lockfile, and
// build-go-binaries.mjs owns the six optionalDependencies pins in the proxy
// manifest (it forces them to equal the package version, which is correct for a
// publish and is why the file moves during an ordinary build). guard.bundled.mjs
// is written by bundle-hooks on every build from the source beside it.
//
// A file is on this list because an INSTALL writes it, not because it looks
// unimportant. Nothing else may be added without that being true.
var installArtifacts = []string{
	"pnpm-lock.yaml",
	"packages/hooks/package.json",
	"packages/hooks/guard.bundled.mjs",
}

// rangeOneLiner is the sentence printed on every update, so the choice is
// visible at the moment it is acting rather than only in a settings panel.
func rangeOneLiner(rng string) string {
	if rng == config.UpdateRangeShort {
		return "every commit on the branch, including ones no release has covered"
	}
	return "tagged releases only"
}

// moveToBranchTip is the short range: whatever is on the branch now.
//
// It also comes BACK from a detached head, which is the state the long range
// leaves the checkout in. Without that, switching short and then updating
// would pull nothing and report success, because a detached head has no
// upstream to pull from.
func moveToBranchTip(root string) int {
	if detached(root) {
		branch := defaultBranch(root)
		if c := step(root, "Returning to "+branch, "git", "checkout", branch); c != 0 {
			return c
		}
	}
	if c := step(root, "Fetching the newest commit", "git", "pull", "--ff-only"); c != 0 {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "  The pull failed. Most often that is a local change in the checkout:")
		fmt.Fprintln(os.Stderr, "    cd "+root+" && git status")
		fmt.Fprintln(os.Stderr)
		return 1
	}
	return 0
}

// moveToNewestRelease is the long range: the highest v-tag there is.
//
// --force on the fetch because a tag can be moved. That is rare and it is also
// exactly the case where not following it leaves a machine pinned to bytes
// nobody is serving any more.
//
// The checkout is DETACHED on purpose. Putting a branch on a tag would make
// the next `git pull` quietly a different operation, and this command is not
// the only thing that runs git in this directory.
func moveToNewestRelease(root string) int {
	if c := step(root, "Fetching releases", "git", "fetch", "--tags", "--force", "origin"); c != 0 {
		return c
	}
	tag, _ := gitOutput(root, "tag", "-l", "v*", "--sort=-v:refname")
	tag = strings.TrimSpace(strings.SplitN(tag, "\n", 2)[0])
	if tag == "" {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "  There are no release tags in this checkout, so the long range has")
		fmt.Fprintln(os.Stderr, "  nothing to move to. `solongate range short` follows the branch instead.")
		fmt.Fprintln(os.Stderr)
		return 1
	}
	if c := step(root, "Checking out "+tag, "git", "checkout", "--detach", tag); c != 0 {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "  The checkout failed. Most often that is a local change:")
		fmt.Fprintln(os.Stderr, "    cd "+root+" && git status")
		fmt.Fprintln(os.Stderr)
		return 1
	}
	return 0
}

func detached(root string) bool {
	out, ok := gitOutput(root, "symbolic-ref", "-q", "HEAD")
	return !ok || strings.TrimSpace(out) == ""
}

// defaultBranch asks the remote rather than assuming "main". A fork or a
// mirror is free to call it something else, and guessing wrong here strands
// somebody on a detached head with an error about a branch they never had.
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

// restoreInstallArtifacts puts the generated files back so the pull can run.
//
// Returns 0 when the checkout is pullable — either it was already clean, or the
// only modifications were files the install itself wrote. A modification
// anywhere else is reported and the update stops: that is somebody's work, and
// this command has no business choosing to lose it.
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
		// Untracked files do not block a fast-forward, so they are not this
		// command's problem and must not be deleted on the way past.
		if strings.HasPrefix(line, "??") {
			continue
		}
		path := strings.TrimSpace(line[2:])
		// A rename reads as "old -> new"; the new name is the one on disk.
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
		fmt.Fprintln(os.Stderr, "  The checkout has local changes that are not the install's:")
		for _, f := range foreign {
			fmt.Fprintln(os.Stderr, "      "+f)
		}
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "  Those are yours, so nothing here will throw them away. Commit or")
		fmt.Fprintln(os.Stderr, "  stash them and run update again:")
		fmt.Fprintln(os.Stderr, "      cd "+root+" && git status")
		fmt.Fprintln(os.Stderr)
		return 1
	}

	if len(generated) == 0 {
		return 0
	}

	args := append([]string{"checkout", "--"}, generated...)
	if _, ok := gitOutput(root, args...); !ok {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "  Could not restore the files the last install rewrote:")
		for _, g := range generated {
			fmt.Fprintln(os.Stderr, "      "+g)
		}
		fmt.Fprintln(os.Stderr)
		return 1
	}
	fmt.Println("  Reset " + strconv.Itoa(len(generated)) + " file(s) the last install rewrote (" +
		strings.Join(generated, ", ") + ").")
	return 0
}

// containsPath is a plain lookup. The list is three entries and a map would read
// worse than the thing it replaced.
func containsPath(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
