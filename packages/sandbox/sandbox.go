// SPDX-License-Identifier: Apache-2.0

// Confinement the agent cannot talk its way out of.
//
// WHY THIS EXISTS AT ALL. Everything else in SolonGate decides by reading the
// strings in a tool call. That catches `rm game.c` and does not catch
// `find . -name 'game*' -delete`, a base64 pipeline, a script written a moment
// earlier and then run, or a program the agent compiles that calls unlink
// itself. Measured against this build, four of six attempts went straight
// through. The set of ways to name a file without typing its name has no end,
// so no amount of pattern-adding closes it.
//
// What closes it is the kernel, and reaching the kernel means being the
// agent's PARENT. SolonGate has never been that: the guard is a hook the agent
// spawns, judged and then obeyed by the agent's own process. `solongate run`
// inverts it. The confinement is installed before the agent's first
// instruction, every descendant inherits it, and nothing the agent runs can
// take it off.
//
// THE THREE PLATFORMS DO NOT WORK THE SAME WAY and this package does not
// pretend they do. Each file says what it actually gets and what it does not;
// Describe reports it back so the CLI can print the true version rather than
// the flattering one.
package sandbox

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
)

// Plan is what the confinement has to achieve, in one of two shapes.
//
// TWO SHAPES BECAUSE THEY ANSWER DIFFERENT QUESTIONS, and only one of them is
// a sandbox in the sense people mean the word.
//
// Deny is a denylist: everything is reachable, and the paths named here are
// not. It protects what you remembered to name. Name nothing and it protects
// nothing, the confinement is still entered, but every file on the machine is
// still open to the agent.
//
// Workspace is an allowlist: ONE directory is writable and nothing else
// outside a fixed runtime set is reachable at all. It protects everything you
// did not name, which is the set that actually matters, nobody thinks to add
// ~/.ssh or a sibling customer's repository to a denylist, and those are
// exactly what an agent reaching too far would find.
//
// A plan carrying a Workspace ignores Deny. The two cannot be combined in a
// meaningful way: inside an allowlist a deny rule is a narrower grant, and
// Landlock has no way to express one (see linux.go).
type Plan struct {
	// Deny are absolute, cleaned paths the child must not be able to read,
	// write or delete. A directory covers everything inside it.
	Deny []string

	// Workspace is the one directory the agent may write in, as an ABSOLUTE
	// path. Everything outside it and outside the runtime set below is
	// unreachable, not merely unwritable.
	//
	// Must be absolute and already resolved: "~/projects/x" is not a path, it
	// is a shell convention, and a sandbox keyed on a string the kernel will
	// not expand is a sandbox around nothing.
	Workspace string

	// RuntimeRead are the paths the agent may READ but never write, and they
	// are the honest cost of the allowlist. A process confined to its project
	// alone does not start: it cannot load its own interpreter, its shared
	// libraries, or /dev/urandom. Every real sandbox has this set; the only
	// question is whether it is written down. See DefaultRuntimeRead.
	RuntimeRead []string

	// RuntimeWrite are the few paths outside the workspace that must stay
	// writable for the agent to function at all, its own configuration and
	// session state, and a scratch directory. Kept separate from RuntimeRead so
	// a reader can see exactly how far the writable surface extends past the
	// project, which is the number that matters.
	RuntimeWrite []string
}

// Confined reports whether this plan asks for anything at all.
func (p Plan) Confined() bool { return p.Workspace != "" || len(p.Deny) > 0 }

// Allowlist reports which of the two shapes this plan is.
func (p Plan) Allowlist() bool { return p.Workspace != "" }

// Report is what a platform actually managed, in enough detail to print.
type Report struct {
	// Mechanism names the kernel feature, so somebody can go and read about it:
	// "Landlock", "Seatbelt", "restricted token", or "" when there is none.
	Mechanism string

	// Enforced is whether the Deny list is actually being enforced by the OS.
	// False means the process ran unconfined and the caller must say so.
	Enforced bool

	// Notes are the true costs and limits of what was applied, one per line.
	// They are printed, not logged: a limit nobody is told about is a limit
	// that gets discovered as a bug.
	Notes []string

	// ABI is the Landlock version the kernel negotiated, 0 where the concept
	// does not apply. Printed, because the number decides what is actually
	// restricted: below 3 a file the agent can read it can also truncate.
	ABI int

	// Err is why nothing was applied.
	Err error
}

// ErrUnsupported is returned by platforms with no implementation.
var ErrUnsupported = errors.New("no OS-level confinement is implemented for this platform")

// DefaultRuntimeRead is the minimum a modern agent needs to exist, and it is
// deliberately a literal list rather than a heuristic.
//
// WHY THERE HAS TO BE ONE. "The agent touches nothing outside the project" is
// the right requirement and it cannot be implemented as written. A process
// confined to one directory cannot open its own interpreter, cannot map libc,
// cannot read /dev/urandom, and never reaches main(). Docker, Flatpak, bubblewrap
// and Seatbelt all carry the same set; the difference between them and a
// hand-rolled sandbox is that theirs is written down.
//
// WHAT IS NOT ON IT, which is the half that matters: no $HOME, no /etc/shadow,
// no /root, no /var, no /mnt or /media, no sibling project directory, and no
// ~/.ssh, ~/.aws, ~/.gnupg, ~/.kube or ~/.docker. The agent cannot read a key it
// cannot open, so these need no pattern and no rule, they are simply not
// granted, and in an allowlist not granted means not there.
//
// READ-ONLY, all of it. A readable toolchain is a toolchain the agent can use;
// a writable one is a toolchain the agent can replace with something that runs
// next time outside the sandbox.
func DefaultRuntimeRead() []string {
	return []string{
		// The interpreter, the libraries and the tools. /usr covers nearly all
		// of a modern distribution; /bin, /lib, /sbin are usually symlinks into
		// it and are listed for systems where they are not.
		"/usr", "/bin", "/lib", "/lib64", "/sbin", "/opt",
		// Name resolution, certificates, timezone and locale. NAMED FILES
		// rather than /etc as a whole. The whole directory was granted here
		// once, on the argument that every runtime reads a different subset of
		// it. That is true and it is also how /etc/passwd, every service's
		// configuration and whatever somebody dropped in /etc/secrets became
		// readable to the agent. These are the ones a process needs to resolve
		// a name and verify a certificate, and nothing else in /etc is.
		"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf",
		"/etc/localtime", "/etc/ssl", "/etc/pki", "/etc/ca-certificates",
		"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
		// Self-inspection, and ONLY self: /proc/self rather than /proc. The
		// whole of /proc is every other process on the machine, their command
		// lines, their environment, their open files, which is a reading of
		// "the agent touches nothing outside the project" that nobody means.
		// Go and Node read /proc/self at startup; /sys/devices/system/cpu is
		// how they count cores.
		"/proc/self", "/sys/devices/system/cpu",
	}
}

// DefaultRuntimeWrite is EMPTY, and that is the whole posture.
//
// NOTHING OUTSIDE THE WORKSPACE IS WRITABLE. Not /tmp, not ~/.cache, not the
// agent's own configuration directory, not a module cache. The agent cannot
// create, modify, truncate, rename or delete a single byte anywhere except the
// one directory it was pointed at.
//
// This list used to hold /tmp, /var/tmp, ~/.claude, ~/.codex, ~/.gemini,
// ~/.config/opencode, ~/.solongate, ~/.cache, ~/.npm, ~/.local/share/pnpm and
// go/pkg/mod, the set a toolchain is comfortable with. Each entry was a place
// the agent could leave something behind, and two of them were worse than
// that: /tmp is where an agent writes a script before running it, and
// ~/.solongate is the guard's own state. Granting the second meant the
// confinement handed the agent write access to the thing confining it.
//
// WHAT IT COSTS, stated rather than discovered. A build that insists on a
// writable cache outside the project will fail, and the failure is an EACCES
// the agent reports rather than a silent wrong answer. The fix is to point the
// toolchain inside the workspace (TMPDIR, GOMODCACHE, npm_config_cache all
// take a path), not to widen this list. `solongate run` sets those three to
// directories under the workspace for exactly that reason.
//
// The parameter is kept so the signature does not change under callers, and so
// the next person to reach for "just add ~/.cache" finds this comment first.
func DefaultRuntimeWrite(home string) []string { return nil }

// DefaultRuntimeDevices are the character devices, and they are WRITABLE for a
// reason that is not obvious and that cost a working sandbox to find.
//
// These were in the read-only set, which looked right, nobody needs to write
// to /dev/urandom. It broke every subprocess the agent starts. Go's os/exec
// opens /dev/null for WRITING to wire up any stream the caller left unset, so a
// read-only /dev/null made `exec.Command(...).Run()` fail with EACCES before
// the child existed: measured as "run a real binary: DENIED, open /dev/null:
// permission denied". An agent that cannot spawn a process cannot run a tool,
// which is all an agent does.
//
// /dev/tty and /dev/pts are the same shape for a different reason: writing to
// the terminal IS the agent's output. Read-only there is an agent that draws
// nothing.
//
// Writing to these gives nothing away. They discard (/dev/null, /dev/zero),
// generate (/dev/random), or lead back to the terminal the user is already
// looking at. None of them is a path to a file somebody wanted kept.
//
// NOT /dev/stdin, /dev/stdout, /dev/stderr OR /dev/fd, and leaving them out is
// a fix rather than an omission. Each is a symlink into /proc/self/fd, so the
// path resolves to whatever that descriptor currently is, and when stdout is a
// pipe, Landlock refuses to add a rule for it and the library returns
// "BUG(go-landlock): file descriptor in bad state". Measured: `solongate run`
// died before the agent started, with that message, any time its output was
// piped rather than attached to a terminal.
//
// They are not needed. Landlock governs OPENING a path, not writing to a
// descriptor that is already open, and stdout and stderr are inherited from the
// parent, the agent writes to them without ever naming them.
func DefaultRuntimeDevices() []string {
	return []string{
		"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom",
		"/dev/tty", "/dev/pts", "/dev/ptmx",
	}
}

// LaunchTargetPaths are the read-only paths a command needs in order to BE
// executed, and they exist because the tight read set broke the obvious case.
//
// An agent installed through npm does not live in /usr. `claude` on this
// machine is ~/.local/bin/claude, a symlink into
// ~/.local/lib/node_modules/@anthropic-ai/claude-code/, and with $HOME
// unreachable the exec failed with EACCES before the sandbox had done anything
// useful. Granting $HOME to fix that would have undone the entire mode.
//
// So the command is resolved and exactly what it resolves to is granted: the
// name on PATH, the file the symlink points at, and the package directory that
// file sits in, because a Node CLI is one entry file plus the tree beside it,
// and granting only the entry file gets MODULE_NOT_FOUND instead.
//
// READ AND EXECUTE, never write. The agent can run its own code and cannot
// replace it, which also means it cannot leave something behind in its own
// install that would run next time outside the sandbox.
//
// It walks UP to the package root rather than taking the whole of
// node_modules: for the path above that is .../@anthropic-ai/claude-code, not
// .../node_modules, so one agent's confinement does not quietly include every
// other package on the machine.
func LaunchTargetPaths(name string) []string {
	if name == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || p == "/" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}

	resolved, err := exec.LookPath(name)
	if err != nil {
		// Not on PATH: Launch will fail with its own error, and a plan with no
		// grant for it is the honest shape of that.
		return nil
	}
	add(filepath.Dir(resolved))

	real, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		return out
	}
	add(packageRoot(filepath.Dir(real)))
	return out
}

// packageRoot climbs out of bin/ and lib/ to the directory holding the
// package's own files, stopping at the first node_modules it would otherwise
// step into. For .../node_modules/@scope/pkg/bin it returns
// .../node_modules/@scope/pkg.
func packageRoot(dir string) string {
	for i := 0; i < 4; i++ {
		base := filepath.Base(dir)
		parent := filepath.Dir(dir)
		if base == "bin" || base == "lib" || base == "dist" || base == "build" {
			dir = parent
			continue
		}
		// One level above a scope directory or node_modules itself is too far:
		// that is every package on the machine.
		if filepath.Base(parent) == "node_modules" || strings.HasPrefix(filepath.Base(parent), "@") {
			return dir
		}
		return dir
	}
	return dir
}
