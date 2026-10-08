// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/solongate/agent-security/packages/sgshared"
)

// DefaultAPIURL is where every command talks unless something says otherwise.
//
// The loopback API this repository builds. There is no hosted one to fall back
// to, and a default pointing at somebody else's service is a default that sends
// this machine's audit log there.
const DefaultAPIURL = "http://127.0.0.1:3002"

// Credential is ~/.solongate/cloud-guard.json.
//
// The file may carry other keys written by other versions; this struct decodes
// what it needs and the writers below preserve the rest, because a CLI that
// rewrites the whole file drops whatever it did not understand.
type Credential = sgshared.Credential

// A key has to look real before anything is enforced with it. The guard applies
// the same test and it matters more than it looks: an unusable key means "no
// project selected", which means allow — so a typo silently disarms the guard
// rather than erroring.
//
// The CLI's own credential resolution deliberately does NOT apply this (see
// Resolve): the CLI's failure mode for a bad key is a 401 the user can read,
// not a silent allow, and refusing to even send a key that the API might accept
// would make the two implementations disagree about who is logged in.
var realKeyBody = regexp.MustCompile(`(?i)^[a-f0-9]{16,}$`)

func IsRealKey(k string) bool { return sgshared.IsRealKey(k) }

// LoadCredentialFile reads the active-key file. A missing or unparseable file
// is an empty credential, never an error: every caller's next step is the same
// either way.
func LoadCredentialFile() Credential {
	var c Credential
	if b, err := os.ReadFile(CredentialPath()); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	return c
}

// EnforcingKey is the key this device enforces with, empty when it is unpaired.
// Distinct from whatever the dataroom is currently VIEWING.
// DotenvAPIKey reads SOLONGATE_API_KEY from a .env beside the working
// directory, the way the hooks do. A project .env is a real source of the key
// on machines that were set up before device login existed.
func DotenvAPIKey() string {
	envPath, err := filepath.Abs(".env")
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(envPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		eq := strings.Index(trimmed, "=")
		if eq == -1 {
			continue
		}
		if strings.TrimSpace(trimmed[:eq]) != "SOLONGATE_API_KEY" {
			continue
		}
		return strings.Trim(strings.TrimSpace(trimmed[eq+1:]), `"'`)
	}
	return ""
}

// ── WHAT WAS HERE, AND WHY NONE OF IT IS ─────────────────────────────────────
//
// The account layer: an accounts.json holding every account ever logged in on the
// device, a Resolver that produced a key and URL per request with a five-second cache
// and a "view" override so the dataroom could read one account while another was
// enforcing, and the writers that kept the two files consistent — SaveAccount,
// RemoveAccount, SetActiveAccount, ClearActiveCredential. Plus EnforcingKey,
// IsActiveAccount and ErrNotAuthenticated, whose message named a panel that is gone.
//
// By the end none of them had a caller outside this file except its own tests. What
// the last callers had been doing is worth recording, because each was a bug waiting
// on a machine that had once been paired:
//
//	install    resolved a credential and refused without one. Every machine is
//	           without one, so the product was uninstallable.
//	the guard  hashed the key into an `acct` tag on every local log line, so one
//	           machine's log could be split between two accounts.
//	the TUI    filtered the log BY that tag and dropped unstamped lines. With
//	           nothing stamping them, a leftover credential file would have blanked
//	           the Live panel on precisely the machines that had been upgraded.
//
// TWO THINGS SURVIVE, above. LoadCredentialFile, because a machine upgraded from a
// build that wrote a credential still has the file, and reading a key out of it is
// more honest than pretending it is not there. And IsRealKey, because a key that is
// present and malformed has to count as absent rather than as a working one.
//
// Neither decides anything. See internal/api/client.go for what a "client" is now.
