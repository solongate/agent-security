package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/api"
	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// The guard hooks update themselves from the cloud, and this is the same
// mechanism from the other end.
//
// packages/proxy/hooks/guard.mjs asks /api/v1/hooks/<name> for a bundle, checks
// that the served version is higher than the one installed, verifies a sha256
// over the decoded bytes, checks the payload actually looks like the hook it
// claims to be, and only then swaps the file. That is how a guard or audit fix
// reaches every device with no re-login and no reinstall. Everything below
// agrees with it field for field, because the two write the SAME files: a
// version comparison that disagreed would have the CLI and the guard installing
// over each other, and the loser would be whichever ran last rather than
// whichever was newer.
//
// Three deliberate differences from the hook's copy, each of them a rule from
// this port:
//
//   - A hook that is NOT already installed here is never created. The hook
//     writes a file it is running from, so the file exists by definition. This
//     CLI could be asked to refresh on a machine where nothing is registered,
//     and dropping guard.mjs into ~/.solongate/hooks without registering it in
//     any client's settings is a half-installed guard: files that look armed,
//     nothing enforcing. Registering is `repair`'s job.
//   - A locked file is unlocked, written and locked again, instead of being
//     silently left unprotected. Self-protection chmods the hooks read-only (and
//     chattr +i where it can); a plain rename over that succeeds on Linux and
//     leaves a 0644 file behind — the guard's own copy disarms its protection
//     that way, which is worth not reproducing.
//   - Nothing here runs on a decision path. The hook does its refresh AFTER the
//     verdict is emitted for the reason recorded in guard.mjs: the 8s backstop
//     force-exits with `process.exitCode || 0`, so a slow update in front of a
//     verdict turns a DENY into an ALLOW. This runs from `solongate update`,
//     where there is no verdict waiting on it.

// hookSpec is one bundle: where to ask for it, where it goes, and what it has to
// look like before it is allowed to replace anything.
//
// The markers and minimum lengths are the hook's own values. They are the cheap
// half of the integrity check: the sha256 proves the bytes arrived intact, and
// these prove the bytes are the right hook — a server (or a proxy in front of
// one) that answered `audit` with an error page, or with the shield bundle,
// would otherwise pass every other test.
type hookSpec struct {
	endpoint string
	file     string
	marker   string
	minLen   int
}

var hookSpecs = []hookSpec{
	{"guard", "guard.mjs", "SolonGate Cloud Policy Guard", 50000},
	{"audit", "audit.mjs", "SolonGate Audit Hook", 1500},
	{"shield", "shield.mjs", "SolonGate Shield", 1500},
	// The conversation hook, which is also the one that reads what a turn COST.
	//
	// It was not refreshable at all until the cloud served it, and the cost of
	// that was invisible: a machine that had updated still ran the old reader,
	// reported no spend, and looked exactly like a machine whose client cannot
	// report spend. A measurement nobody has and a measurement of zero are the
	// same picture, which is why this is here rather than left to a reinstall.
	{"conversation", "conversation.mjs", "SolonGate Conversation Hook", 5000},
}

// hookShebang is the first line every hook has. A payload that does not start
// with it is not something node should be asked to run.
const hookShebang = "#!/usr/bin/env node"

// hookFetchTimeout matches guard.mjs. The CLI could afford to wait longer, but
// the point of agreeing with the hook is that both give up at the same place.
const hookFetchTimeout = 5 * time.Second

// HookResult is one hook's outcome, so `solongate update` can say what it did
// rather than printing a spinner and a checkmark.
type HookResult struct {
	File    string
	From    int
	To      int
	Updated bool
	// Skipped says why nothing happened. Empty when Updated is true. It is a
	// sentence, not a code: every one of these is shown to a person deciding
	// whether their machine is guarded.
	Skipped string
}

// RefreshHooks brings the guard hooks installed on this device up to whatever
// the cloud serves, and reports what it did for each one.
//
// It never returns an error. A hook that could not be refreshed leaves the
// working one in place, which is the only acceptable failure for this: an
// out-of-date guard still guards, and a half-written one does not.
func RefreshHooks(ctx context.Context, c *api.Client) []HookResult {
	out := make([]HookResult, 0, len(hookSpecs))
	contacted := false

	for _, spec := range hookSpecs {
		target := filepath.Join(config.HooksDir(), spec.file)
		if _, err := os.Stat(target); err != nil {
			out = append(out, HookResult{File: spec.file, Skipped: "not installed on this device"})
			continue
		}
		current := HookVersion(spec.file)

		var payload struct {
			// A pointer so an absent field is distinguishable from version 0, and
			// a float64 so a version sent as a STRING fails the decode instead of
			// being coerced — the hook checks `typeof data.version !== 'number'`
			// and refuses the same payload.
			Version *float64 `json:"version"`
			Content string   `json:"content"`
			SHA256  string   `json:"sha256"`
		}
		err := c.Do(ctx, http.MethodGet, "/hooks/"+spec.endpoint,
			api.RequestOptions{Timeout: hookFetchTimeout}, &payload)
		if err != nil {
			out = append(out, HookResult{File: spec.file, From: current,
				Skipped: "could not ask the cloud: " + err.Error()})
			continue
		}
		contacted = true

		if payload.Version == nil || int(*payload.Version) <= current {
			out = append(out, HookResult{File: spec.file, From: current, To: current,
				Skipped: "already current (v" + strconv.Itoa(current) + ")"})
			continue
		}
		served := int(*payload.Version)

		body, why := verifiedHookBody(payload.Content, payload.SHA256, spec)
		if why != "" {
			out = append(out, HookResult{File: spec.file, From: current, Skipped: why})
			continue
		}

		if err := replaceFile(target, body); err != nil {
			out = append(out, HookResult{File: spec.file, From: current,
				Skipped: "could not replace the installed file: " + err.Error()})
			continue
		}
		out = append(out, HookResult{File: spec.file, From: current, To: served, Updated: true})
	}

	// Only stamp when the cloud actually answered. The guard reads this same
	// file and skips its own blind check for six hours after it, so stamping a
	// pass that never reached the cloud would suppress the guard's check on the
	// strength of work nobody did.
	if contacted {
		markHookRefresh()
	}
	return out
}

// verifiedHookBody decodes and checks a payload, and returns the reason it was
// refused rather than a bare nil — a hook that silently declines to update is
// indistinguishable from one that has nothing to do.
//
// Order matters: the sha256 is verified over the DECODED bytes before anything
// looks at the text, so nothing downstream is deciding anything about bytes
// whose integrity has not been established.
func verifiedHookBody(contentB64, want string, spec hookSpec) ([]byte, string) {
	if contentB64 == "" || want == "" {
		return nil, "the cloud sent no content or no checksum"
	}
	buf, err := base64.StdEncoding.DecodeString(contentB64)
	if err != nil {
		return nil, "the cloud sent content that is not base64"
	}
	sum := sha256.Sum256(buf)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), want) {
		return nil, "sha256 did not match — refusing the download"
	}
	text := string(buf)
	if !strings.HasPrefix(text, hookShebang) {
		return nil, "the download is not a hook script"
	}
	if len(text) < spec.minLen || !strings.Contains(text, spec.marker) {
		return nil, "the download is not " + spec.file
	}
	return buf, ""
}

// replaceFile puts new contents where an existing file is, without ever leaving
// a partial one there.
//
// Two paths, and which one is taken is decided by the file already on disk:
//
// Unlocked: write a temp file beside it and rename. The rename is atomic, so a
// hook launching at that instant reads either the whole old file or the whole
// new one. A torn hook is a syntax error, a syntax error is a non-zero exit, and
// a non-zero exit from a PreToolUse hook is a call that proceeds unguarded.
//
// Locked (self-protection has chmodded it read-only, or chattr'd / chflags'd /
// icacls'd it): hand it to config.WriteProtectedFile, which lifts the lock,
// writes, and puts the lock back. That write is not atomic, and the trade is
// deliberate — a rename over a locked file either fails outright (chattr +i) or
// succeeds and leaves an UNLOCKED 0644 file in place of a protected one, which
// disarms self-protection permanently in exchange for a few microseconds of
// atomicity. The lock is the thing worth keeping.
func replaceFile(target string, contents []byte) error {
	if looksLocked(target) {
		if !config.WriteProtectedFile(target, contents) {
			return os.ErrPermission
		}
		return nil
	}

	tmp := filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".tmp")
	if err := os.WriteFile(tmp, contents, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		// The file looked writable and the rename still failed: an immutable
		// flag this process cannot see, or a directory someone else owns. The
		// protected writer knows how to lift what it set, so give it the last
		// word before reporting failure.
		if config.WriteProtectedFile(target, contents) {
			return nil
		}
		return err
	}
	return nil
}

// looksLocked reports whether self-protection appears to hold this file. The
// write bits are what every one of the three mechanisms clears (chmod 0444 on
// Linux, and Go reports a Windows read-only attribute the same way), and where
// the guess is wrong the rename below simply fails and falls through to the
// protected writer anyway.
func looksLocked(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0o200 == 0
}

// hookVersionRe reads the version baked into an installed hook.
//
// packages/proxy/hooks/guard.mjs carries `const HOOK_VERSION = 80;` and reads
// its siblings' with this same expression. It is a number in a source file
// rather than a manifest because the file IS the unit that ships — there is no
// second place that could be right about it.
var hookVersionRe = regexp.MustCompile(`HOOK_VERSION\s*=\s*(\d+)`)

// HookVersion is the version of an installed hook, or 0 when it is absent or too
// old to carry one.
//
// Zero is deliberately the same answer for both, exactly as the hook's
// installedHookVersion() has it: a hook with no version baked in predates the
// self-update mechanism and is behind anything the cloud can serve.
//
// internal/commands/installstate.go has an unexported twin of this for the
// health check. They must not be allowed to disagree — see the caveat in the
// port notes about which of the two should own it.
func HookVersion(file string) int {
	b, err := os.ReadFile(filepath.Join(config.HooksDir(), file))
	if err != nil {
		return 0
	}
	m := hookVersionRe.FindSubmatch(b)
	if m == nil {
		return 0
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return 0
	}
	return n
}

// hookUpdateStampPath is the throttle the GUARD keeps for its own blind
// six-hourly check. This CLI reads and writes the same file rather than keeping
// a second one, because the thing being rate-limited is the same request to the
// same endpoint.
//
// It belongs beside the other paths in internal/config; it is here because
// nothing over there names it yet and a second declaration of the same path in
// two packages is how the two implementations end up throttling different files.
func hookUpdateStampPath() string { return filepath.Join(config.Dir(), ".hook-update-check") }

func markHookRefresh() {
	if config.EnsureDir() != nil {
		return
	}
	_ = os.WriteFile(hookUpdateStampPath(), []byte(strconv.FormatInt(nowMillis(), 10)), 0o644)
}
