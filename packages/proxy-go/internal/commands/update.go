package commands

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/codeyevsky/solongate/proxy/internal/install"
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
	head, _ := gitOutput(root, "rev-parse", "HEAD")
	if code := step(root, "Fetching the newest version", "git", "pull", "--ff-only"); code != 0 {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "  The pull failed. Most often that is a local change in the checkout:")
		fmt.Fprintln(os.Stderr, "    cd "+root+" && git status")
		fmt.Fprintln(os.Stderr)
		return 1
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
	fmt.Fprintln(w, "  If you installed with npm:")
	fmt.Fprintln(w, "      npm install -g @solongate/proxy")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  If you have a checkout, run its install script once and `update` will")
	fmt.Fprintln(w, "  remember where it is:")
	fmt.Fprintln(w, "      ./install.sh")
	fmt.Fprintln(w)
	return 1
}
