// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"

	"github.com/solongate/agent-security/packages/shared"
)

// DefaultAPIURL was here, a const pointing at http://127.0.0.1:3002 with a
// comment about where every command talks. Nothing read it. It is deleted rather
// than kept because the README's claim is that this tool makes no network calls,
// and an address constant in the config package is the first thing a reader
// checking that claim finds, a URL nothing dials still has to be explained
// away. core/api/client.go takes no address, which is the real answer.

// Credential is ~/.solongate/cloud-guard.json.
//
// The file may carry other keys written by other versions; this struct decodes
// what it needs and the writers below preserve the rest, because a CLI that
// rewrites the whole file drops whatever it did not understand.
type Credential = shared.Credential

// A key has to look real before anything is enforced with it. The guard applies
// the same test and it matters more than it looks: an unusable key means "no
// project selected", which means allow, so a typo silently disarms the guard
// rather than erroring.
//
// ONE DEFINITION OF "REAL", in packages/shared. A second copy of the body
// pattern lived here as `realKeyBody`, under a comment about a CLI resolver and
// a 401 that no longer exist, while IsRealKey below already delegated to shared.
// Two regexes deciding whether a key counts is the pair that can disagree, and
// the direction it fails in is allow.
func IsRealKey(k string) bool { return shared.IsRealKey(k) }

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

// DotenvAPIKey was here: it read SOLONGATE_API_KEY out of a .env beside the
// working directory, "the way the hooks do", for machines set up before device
// login existed. Nothing called it, and a credential reader aimed at the
// AGENT'S OWN working directory is the wrong shape to leave lying around in a
// tool whose job is to stop secrets leaving that directory, it reads a project
// .env on the hot side of the boundary. The hooks no longer read a credential
// either (see HOOK_VERSION 99 in the Node guard: two file reads left the hot
// path of every tool call).

// ── WHAT WAS HERE, AND WHY NONE OF IT IS ─────────────────────────────────────
//
// The account layer: an accounts.json holding every account ever logged in on the
// device, a Resolver that produced a key and URL per request with a five-second cache
// and a "view" override so the TUI could read one account while another was
// enforcing, and the writers that kept the two files consistent. SaveAccount,
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
// Neither decides anything. See core/api/client.go for what a "client" is now.
