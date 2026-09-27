package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// pkgName is what npm installs. The Go binary has no separate npm identity: it
// rides in this package's platform dependency, and go-binary.mjs will only use a
// binary whose version equals this package's, so they have to be updated as one
// thing.
const pkgName = "@solongate/proxy"

// platformPackage is the optional dependency this machine's binaries ship in,
// named the way it was published: the npm platform words (win32, x64), not Go's
// (windows, amd64). Empty for a platform with no published package, which every
// caller treats as "nothing to install here" rather than as a fault.
func platformPackage() string {
	os_ := runtime.GOOS
	if os_ == "windows" {
		os_ = "win32"
	}
	cpu := runtime.GOARCH
	if cpu == "amd64" {
		cpu = "x64"
	}
	switch os_ {
	case "linux", "darwin", "win32":
	default:
		return ""
	}
	switch cpu {
	case "x64", "arm64":
	default:
		return ""
	}
	return "@solongate/guard-" + os_ + "-" + cpu
}

// npm's own words when the global prefix is not writable by this user. Matching
// them is what separates "retry later, it was a blip" from "no amount of
// retrying will help — this machine needs sudo", and the difference decides
// whether the updater retries every six hours forever or tells the user the two
// commands that actually work.
var needsAdminRe = regexp.MustCompile(`(?i)\bEACCES\b|\bEPERM\b|permission denied|operation not permitted`)

// registryBase is a variable only so a test can point the lookup at a stub. The
// rule it exists to pin — a version is not "available" until the same document
// lists it under versions — is one that already regressed once in production,
// and it cannot be tested against the real registry.
var registryBase = "https://registry.npmjs.org/"

// LatestVersion is the newest version published to npm, and false when the
// registry could not be reached or answered with something unusable.
//
// This talks to registry.npmjs.org rather than going through internal/api: that
// client speaks to the SolonGate API, sends the device credential and builds
// /api/v1 paths. Sending a SolonGate API key to a public registry would be a
// credential leak with no purpose, so the registry gets a bare, anonymous
// request instead.
func LatestVersion(ctx context.Context) (string, bool) {
	// The ABBREVIATED packument, which is exactly what `npm install` resolves
	// against, so dist-tags and versions are consistent. Deliberately NOT the
	// small /latest document: right after a publish its `latest` pointer can
	// reach a CDN edge BEFORE that version's metadata does, so we would announce
	// a version `npm install` still rejects with ETARGET — and burn the six-hour
	// retry slot for nothing. Requiring versions[latest] in the same document
	// ties "seen" to "installable".
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, registryBase+pkgName, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Accept", "application/vnd.npm.install-v1+json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", false
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", false
	}
	// The abbreviated packument of a package with a long history is still a few
	// hundred kilobytes; cap the read so a wrong URL or a hijacked proxy cannot
	// stream into this process indefinitely.
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return "", false
	}

	var doc struct {
		DistTags struct {
			Latest string `json:"latest"`
		} `json:"dist-tags"`
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return "", false
	}
	latest := doc.DistTags.Latest
	if latest == "" {
		return "", false
	}
	if _, installable := doc.Versions[latest]; !installable {
		return "", false // published but not resolvable yet — stay quiet
	}
	return latest, true
}

// RunningAsRoot answers "did someone run this under sudo".
//
// It matters because `sudo solongate update` half-works, which is worse than
// failing: npm installs fine as root, and then the guard-hook refresh writes
// into ROOT's home instead of the user's, so their agents quietly stop being
// guarded.
func RunningAsRoot() bool { return runtime.GOOS != "windows" && os.Geteuid() == 0 }

// AdminInstallCommand is the exact command that fixes a root-owned global
// prefix.
func AdminInstallCommand() string {
	if runtime.GOOS == "windows" {
		return "npm i -g " + pkgName + "@latest  (in an Administrator terminal)"
	}
	return "sudo npm i -g " + pkgName + "@latest"
}

// AdminUpdateSteps are the two commands that update SolonGate on a machine whose
// global npm folder belongs to root. `repair` is deliberately NOT under sudo: it
// writes the guard hooks into the invoking user's home, so as root it would arm
// root's home and leave the actual user unguarded.
func AdminUpdateSteps() []string {
	repair := "solongate repair"
	if runtime.GOOS != "windows" {
		repair += "   (this one WITHOUT sudo)"
	}
	return []string{AdminInstallCommand(), repair}
}

var (
	prefixOnce     sync.Once
	prefixWritable *bool
	prefixDir      string
)

// GlobalInstallCheck answers, before anything is installed, whether THIS user
// can replace the installed copy — i.e. whether `npm install -g` can work
// without sudo.
//
// Asking first is the whole point: on a stock macOS Node the answer is no, and
// running the install anyway only buys a wall of npm EACCES noise a minute
// later instead of an answer the user can act on.
//
// A nil result means "could not tell" — running from a source build, an unusual
// layout, a directory that is simply absent. Never block on a guess: try the
// install and report what npm says.
//
// Cached because the dataroom reads it from a render path.
func GlobalInstallCheck() (writable *bool, dir string) {
	prefixOnce.Do(func() {
		prefixDir = ownNodeModules()
		if prefixDir == "" {
			return
		}
		prefixWritable = dirWritable(prefixDir)
	})
	return prefixWritable, prefixDir
}

// ownNodeModules is the node_modules directory this CLI was installed into, or
// "" when it is not running from one.
//
// Deliberately NOT `npm prefix -g`: that spawns npm, and npm pipes its output
// through a secret-redactor that will happily rewrite parts of a path it finds
// suspicious (a UUID in the path is enough), handing back a directory that does
// not exist. Our own location needs no subprocess and cannot be misreported.
//
// The symlink is resolved first because npm puts a link in its bin directory and
// the real file lives under the package: without resolving it the walk starts in
// .../bin and finds no node_modules at all, which reads as "cannot tell" on
// every normal global install.
func ownNodeModules() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return nodeModulesAbove(exe)
}

func nodeModulesAbove(exe string) string {
	dir := filepath.Dir(exe)
	for i := 0; i < 12; i++ {
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		if filepath.Base(dir) == "node_modules" {
			return dir
		}
		dir = parent
	}
	return ""
}

// ownPackageDir is the directory of the @solongate/proxy PACKAGE this CLI was
// installed as — which is not the directory the running binary sits in.
//
// The executable is a Go binary inside a PLATFORM package, nested under the
// proxy's own node_modules:
//
//	<prefix>/node_modules/@solongate/proxy/node_modules/@solongate/guard-linux-x64/bin/solongate
//
// so walking up to the first node_modules finds the proxy's PRIVATE dependency
// folder, and looking for @solongate/proxy inside that finds nothing. That is
// not hypothetical: it is what made a successful 0.83.71 install report "update
// failed" — npm had done the work, and the check was looking somewhere the
// package could never be.
//
// So the walk asks each directory what package it IS, and stops at the one
// whose manifest carries this package's name. A layout with no answer returns
// "", and every caller treats that as "cannot tell" rather than as a fault.
//
// It must be called BEFORE an install. npm renames the package directory aside
// (@solongate/.proxy-XXXXXX) while it extracts, and on Linux /proc/self/exe
// follows the running file into that temporary name — so a path derived after
// npm has started describes a directory that is about to stop existing.
func ownPackageDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return packageDirAbove(exe, pkgName)
}

// packageDirAbove walks up from a path looking for the package with this name.
func packageDirAbove(start, name string) string {
	dir := filepath.Dir(start)
	for i := 0; i < 12; i++ {
		if manifestName(dir) == name {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// manifestName is what a directory calls itself, or "" if it is not a package.
func manifestName(dir string) string {
	body, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return ""
	}
	var manifest struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &manifest) != nil {
		return ""
	}
	return manifest.Name
}

// dirWritable tests the permission npm actually needs — creating a file in the
// directory that holds the package — rather than reading mode bits. On Windows
// the mode bits are fiction and the ACL decides; on a read-only mount the bits
// look fine and every write fails. The probe file is removed immediately.
func dirWritable(dir string) *bool {
	f, err := os.CreateTemp(dir, ".solongate-write-probe-")
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			no := false
			return &no
		}
		return nil // something else is wrong; do not turn that into a verdict
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	yes := true
	return &yes
}

// installResult is the outcome of a foreground install. needsAdmin means npm
// refused for permissions, which is not a blip to retry.
type installResult struct {
	ok         bool
	needsAdmin bool
	// busy means another install holds the lease. It is not a failure to
	// report as one: nothing is wrong, something else is already doing it.
	busy bool
	// ran means npm exited 0. It is separate from ok because the two answer
	// different questions: npm's exit code is evidence about npm's process, and
	// ok is evidence about what is on disk afterwards. Where they disagree, the
	// files npm wrote are still there — so the hooks are still worth
	// refreshing, and saying "update failed" without doing that leaves a
	// machine both updated and unregistered.
	ran bool
	// why is the verification's own words, for a person who now has to decide
	// what to do about it.
	why string
}

// npmPath resolves npm once. On Windows npm is npm.cmd and Go's LookPath finds
// it through PATHEXT, so no shell is needed — which is the point: passing an
// install command through a shell is how a version string would become
// something the shell interprets.
func npmPath() (string, bool) {
	p, err := exec.LookPath("npm")
	if err != nil {
		return "", false
	}
	return p, true
}

// runGlobalInstall installs the named version and waits for it.
//
// The staged replacement around it is the Windows half: a running executable
// cannot be overwritten there, so this binary moves itself aside first and moves
// itself back if npm fails. A failed update has to leave the previous state
// working — a machine with neither the old CLI nor the new one is worse than a
// machine that is simply out of date.
func runGlobalInstall(ctx context.Context, version string) installResult {
	npm, ok := npmPath()
	if !ok {
		appendInstallLog(version, false, "npm was not found on PATH")
		return installResult{}
	}

	// One install at a time. Two of these against the same global prefix ends
	// with a machine that has neither version — see lease.go.
	release, free := acquireInstallLease(version)
	if !free {
		appendInstallLog(version, false, "another install is already running on this machine")
		return installResult{ok: false, busy: true}
	}
	defer release()

	// Where this package lives, resolved BEFORE npm touches anything. npm
	// renames the package directory aside while it extracts, and on Linux the
	// running executable's own path follows it into that temporary name — so a
	// path worked out afterwards names a directory that is about to be removed.
	pkgDir := ownPackageDir()

	// Clear what an EARLIER update staged before staging again. A binary can
	// only be swept by a run that is not executing it, and this is the last
	// moment that is still true of the previous one.
	SweepStagedReplacements()
	restore := stageRunningExecutable()

	ctx, cancel := context.WithTimeout(ctx, installTimeout)
	defer cancel()
	// --include=optional is the default, and it is spelled out here because a
	// machine that once inherited --omit=optional, or npm's cached "this
	// optional could not be fetched" from a publish it caught mid-propagation,
	// is exactly the machine whose platform binary never installs - and that
	// package is where the Go binaries live. Without it the CLI updates and the
	// binaries beside the hook do not, which reads as an update that did nothing.
	cmd := exec.CommandContext(ctx, npm, "install", "-g", "--include=optional", pkgName+"@"+version)
	out, err := cmd.CombinedOutput()

	if err != nil {
		appendInstallLog(version, false, string(out))
		restore()
		return installResult{ok: false, needsAdmin: needsAdminRe.Match(out)}
	}

	// The platform package, made sure of rather than hoped for. It carries the
	// Go binaries the hook and the browser agent actually run, it is an OPTIONAL
	// dependency of the proxy, and an optional npm skipped is an optional npm
	// stays silent about - so a proxy that installed cleanly can still leave no
	// binary to copy. Installing it by name, best effort, is the belt to the
	// --include suspenders: it either confirms what is already there or fills
	// the gap the skip left, and a failure here is not an update failure.
	if plat := platformPackage(); plat != "" {
		pctx, pcancel := context.WithTimeout(ctx, installTimeout)
		if pcmd := exec.CommandContext(pctx, npm, "install", "-g", plat+"@"+version); pcmd != nil {
			if pout, perr := pcmd.CombinedOutput(); perr != nil {
				appendInstallLog(version, false, "platform package "+plat+": "+string(pout))
			}
		}
		pcancel()
	}

	// npm's exit code is evidence about npm's own process and nothing else.
	// Under the race the lease now prevents, one install exited 0 while another
	// rolled back over it — so the update that "succeeded" had already been
	// removed by the time anybody typed the command.
	if err := verifyInstalledAt(pkgDir, version); err != nil {
		appendInstallLog(version, false, string(out)+"\nverify: "+err.Error())
		restore()
		return installResult{ok: false, ran: true, why: err.Error()}
	}

	appendInstallLog(version, true, string(out))
	return installResult{ok: true, ran: true}
}

// spawnGlobalInstall is the background updater: a detached `npm install -g`
// whose output goes to the update log, so the NEXT run is the new version.
//
// It deliberately does NOT stage the running executable the way the foreground
// path does. Staging means renaming this binary out of the way before npm runs,
// and only a caller that stays around to see npm fail can put it back — a
// detached install that failed would leave the user with no CLI at all. On
// Windows that means a background install cannot replace a running Go binary and
// will log an EBUSY; the CLI keeps working, which is the right way to lose.
func spawnGlobalInstall(version string) bool {
	npm, ok := npmPath()
	if !ok {
		return false
	}
	if err := config.EnsureDir(); err != nil {
		return false
	}

	// The lease is taken and never released here. This process is about to
	// exit and the npm it starts outlives it, so there is nobody left to
	// release one — the lease expires instead, which is what bounds something
	// we no longer hold a handle on. A foreground `solongate update` arriving
	// while it is live steps aside rather than racing it.
	if _, free := acquireInstallLease(version); !free {
		return false
	}
	log, err := os.OpenFile(config.SelfUpdateLogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return false
	}
	defer log.Close()

	cmd := exec.Command(npm, "install", "-g", "--include=optional", pkgName+"@"+version)
	cmd.Stdout, cmd.Stderr = log, log
	detach(cmd)
	if cmd.Start() != nil {
		return false
	}
	// Release, not Wait: this process is about to exit and the install must
	// outlive it.
	_ = cmd.Process.Release()
	return true
}

// appendInstallLog keeps the same one-line header the Node implementation
// writes, so ~/.solongate/self-update.log stays one readable history whichever
// implementation produced the entry.
func appendInstallLog(version string, ok bool, output string) {
	if config.EnsureDir() != nil {
		return
	}
	f, err := os.OpenFile(config.SelfUpdateLogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	status := "ok"
	if !ok {
		status = "FAILED"
	}
	// JavaScript's toISOString, which is what the existing lines in this file
	// look like.
	stamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	_, _ = f.WriteString(stamp + " install " + version + ": " + status + "\n" + output + "\n")
}
