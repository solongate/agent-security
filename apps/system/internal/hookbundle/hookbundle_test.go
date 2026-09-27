package hookbundle

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// These tests are the reason this package can be trusted.
//
// A hook bundle fails in silence: the installed hook verifies the checksum,
// finds a mismatch, returns, and keeps running the version it already had. No
// error reaches this service and no error reaches the user. The only place that
// failure can be caught is here, before the bundle ships.

// hookChecks are the installed hook's OWN acceptance tests, copied from
// packages/proxy/hooks/guard.bundled.mjs (fetchAndInstallHook) and from
// the hooks that fetch them, which agree with it.
//
// They are duplicated deliberately: this is the one place where writing the
// far end's rules down a second time is the point. If the payload we serve
// fails any of them, every hook in the fleet rejects it — and the marker and
// minimum length exist so that a server (or a proxy in front of one) that
// answers `audit` with an error page or with the shield bundle is caught too.
var hookChecks = map[string]struct {
	marker string
	minLen int
}{
	"guard":  {"SolonGate Cloud Policy Guard", 50000},
	"audit":  {"SolonGate Audit Hook", 1500},
	"shield": {"SolonGate Shield", 1500},
	// The one that carries the token reader. Its marker is its own heading,
	// and the length floor is well under the file so a legitimate trim does not
	// fail the build — the point of the floor is to catch an error page served
	// in place of a hook, not to pin a byte count.
	"conversation": {"SolonGate Conversation Hook", 5000},
}

const hookShebang = "#!/usr/bin/env node"

var hookVersionInSource = regexp.MustCompile(`HOOK_VERSION\s*=\s*(\d+)`)

func TestEveryBundleSurvivesTheHooksOwnVerification(t *testing.T) {
	if len(Names()) != len(hookChecks) {
		t.Fatalf("serving %v, want exactly %d hooks", Names(), len(hookChecks))
	}

	for _, name := range Names() {
		check, known := hookChecks[name]
		if !known {
			t.Errorf("%s is served but no installed hook asks for it", name)
			continue
		}
		b, _ := Get(name)

		// StdEncoding, not RawStdEncoding and not URLEncoding: Buffer.from(s,
		// 'base64') on the far end expects padded standard base64.
		raw, err := base64.StdEncoding.DecodeString(b.Content)
		if err != nil {
			t.Errorf("%s: content is not standard base64: %v", name, err)
			continue
		}

		// The digest is over the decoded bytes. This is the assertion that
		// matters: it is the exact computation the hook performs before it
		// agrees to overwrite itself.
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != b.SHA256 {
			t.Errorf("%s: sha256 of the decoded payload is %s, bundle says %s — every hook would refuse this", name, got, b.SHA256)
		}
		if b.SHA256 != strings.ToLower(b.SHA256) {
			t.Errorf("%s: sha256 is not lowercase hex; the hook compares strings", name)
		}

		text := string(raw)
		if !strings.HasPrefix(text, hookShebang) {
			t.Errorf("%s: payload does not start with %q", name, hookShebang)
		}
		if len(text) < check.minLen {
			t.Errorf("%s: payload is %d bytes, the hook refuses anything under %d", name, len(text), check.minLen)
		}
		if !strings.Contains(text, check.marker) {
			t.Errorf("%s: payload does not contain %q, so the hook would decide it is a different file", name, check.marker)
		}

		// The version we advertise has to be the version baked into the bytes we
		// send. They are compared on the far end against the installed file's own
		// HOOK_VERSION, so advertising a higher number than the payload carries
		// makes a hook download, install, and then report the old version — and
		// download again on every single poll, forever.
		m := hookVersionInSource.FindStringSubmatch(text)
		if m == nil {
			t.Errorf("%s: payload carries no HOOK_VERSION", name)
			continue
		}
		inSource, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			t.Errorf("%s: HOOK_VERSION in the payload is unreadable: %v", name, err)
			continue
		}
		if inSource != b.Version {
			t.Errorf("%s: bundle advertises version %d, the payload says %d", name, b.Version, inSource)
		}
		if b.Version <= 0 {
			t.Errorf("%s: version %d is not newer than anything, so no hook would ever install it", name, b.Version)
		}
	}
}

// TestBundlesMatchTheLiveApp compares what this service would serve against
// what apps/api serves today.
//
// The two are generated from the same three files in packages/proxy/hooks, so
// they should agree byte for byte. They will not if bundles_gen.go was not
// regenerated after a hook change — and during the cutover a machine can be
// answered by either implementation, so a disagreement is a hook that installs,
// reverts, and installs again on every poll.
//
// It skips rather than fails when apps/api is not on disk: this module has to
// build on its own.
func TestBundlesMatchTheLiveApp(t *testing.T) {
	generated := map[string]string{
		"guard":  "guard-bundle.ts",
		"audit":  "audit-bundle.ts",
		"shield": "shield-bundle.ts",
	}

	versionRe := regexp.MustCompile(`version:\s*(\d+)`)
	shaRe := regexp.MustCompile(`sha256:\s*"([0-9a-fA-F]+)"`)
	contentRe := regexp.MustCompile(`content:\s*"([A-Za-z0-9+/=]*)"`)

	checked := 0
	for name, file := range generated {
		path := filepath.Join("..", "..", "..", "api", "src", "generated", file)
		src, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		checked++

		b, ok := Get(name)
		if !ok {
			t.Errorf("%s: apps/api serves it, this service does not", name)
			continue
		}

		if m := versionRe.FindSubmatch(src); m == nil {
			t.Errorf("%s: could not read version out of %s", name, file)
		} else if string(m[1]) != strconv.FormatInt(b.Version, 10) {
			t.Errorf("%s: version %d here, %s in the live app — bundles_gen.go is stale", name, b.Version, m[1])
		}
		if m := shaRe.FindSubmatch(src); m == nil {
			t.Errorf("%s: could not read sha256 out of %s", name, file)
		} else if !strings.EqualFold(string(m[1]), b.SHA256) {
			t.Errorf("%s: sha256 %s here, %s in the live app", name, b.SHA256, m[1])
		}
		if m := contentRe.FindSubmatch(src); m == nil {
			t.Errorf("%s: could not read content out of %s", name, file)
		} else if string(m[1]) != b.Content {
			// The bodies are hundreds of kilobytes; printing them would bury the
			// failure. The lengths and the digest of each are enough to tell a
			// stale bundle from a corrupted one.
			live := sha256.Sum256(m[1])
			ours := sha256.Sum256([]byte(b.Content))
			t.Errorf("%s: content differs — %d bytes (%s) here, %d bytes (%s) in the live app",
				name, len(b.Content), hex.EncodeToString(ours[:])[:12],
				len(m[1]), hex.EncodeToString(live[:])[:12])
		}
	}

	if checked == 0 {
		t.Skip("apps/api/src/generated is not on disk; nothing to compare against")
	}
}
