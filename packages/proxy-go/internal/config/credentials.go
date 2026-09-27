package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/codeyevsky/solongate/sgshared"
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

// SavedAccount is one entry of ~/.solongate/accounts.json.
//
// Several accounts can be logged in on one device over time. cloud-guard.json
// holds only the ACTIVE key — the one the guard hooks enforce with — while this
// list accumulates every account so the dataroom can show which it is viewing
// and switch without another device login. Switching changes what is READ, not
// what is enforced.
type SavedAccount struct {
	APIKey  string `json:"apiKey"`
	APIURL  string `json:"apiUrl"`
	Project string `json:"project,omitempty"`
	User    string `json:"user,omitempty"`
	// Email is the primary human-facing label for an account.
	Email   string `json:"email,omitempty"`
	AddedAt int64  `json:"addedAt,omitempty"`
}

// ErrNotAuthenticated is what every credential resolution returns when no key
// can be found anywhere. Callers render its message; nothing above this layer
// should be composing its own wording for "not logged in".
var ErrNotAuthenticated = errors.New("Not logged in. Run `solongate` and log in from the Accounts panel.")

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
func EnforcingKey() string { return LoadCredentialFile().APIKey }

func IsActiveAccount(apiKey string) bool { return LoadCredentialFile().APIKey == apiKey }

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

// Resolver holds the credential state for one process: the resolved key, and
// the dataroom's VIEW override.
//
// The override never touches disk. That is the whole point of it — the account
// switcher changes what the dataroom reads while the guard hooks keep enforcing
// with the real active key, so looking at another project cannot disarm this
// machine.
type Resolver struct {
	mu     sync.Mutex
	view   *Credential
	cached *Credential
}

// SetView points reads at a different account, or clears the override with nil.
// The cache is dropped so the next request re-resolves rather than serving the
// account the user just switched away from.
func (r *Resolver) SetView(c *Credential) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.view = c
	r.cached = nil
}

// Invalidate drops the cached credential. Any writer that changes the
// active-key file must call it, or the process keeps sending the key it read
// before the change — which is how a device revoked in the dashboard stayed
// "logged in" for the rest of the session.
func (r *Resolver) Invalidate() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cached = nil
}

// Resolve produces the key and URL for a request.
//
// Precedence, matching packages/proxy/src/api-client/client.ts exactly:
// env SOLONGATE_API_KEY, then the active-key file, then a .env in the working
// directory. An apiURLOverride (from --api-url) beats every stored URL and also
// bypasses both the view override and the cache, so a one-off request against
// another environment cannot poison what the rest of the process reads.
func (r *Resolver) Resolve(apiURLOverride string) (Credential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if apiURLOverride == "" {
		if r.view != nil {
			return *r.view, nil
		}
		if r.cached != nil {
			return *r.cached, nil
		}
	}

	file := LoadCredentialFile()
	apiKey := os.Getenv("SOLONGATE_API_KEY")
	if apiKey == "" {
		apiKey = file.APIKey
	}
	if apiKey == "" {
		apiKey = DotenvAPIKey()
	}
	if apiKey == "" {
		return Credential{}, ErrNotAuthenticated
	}

	apiURL := apiURLOverride
	if apiURL == "" {
		apiURL = os.Getenv("SOLONGATE_API_URL")
	}
	if apiURL == "" {
		apiURL = file.APIURL
	}
	if apiURL == "" {
		apiURL = DefaultAPIURL
	}

	c := Credential{APIKey: apiKey, APIURL: strings.TrimRight(apiURL, "/")}
	if apiURLOverride == "" {
		r.cached = &c
	}
	return c, nil
}

// Authenticated reports whether a key is available without prompting.
func (r *Resolver) Authenticated() bool {
	_, err := r.Resolve("")
	return err == nil
}

// ── accounts.json ──────────────────────────────────────────────────────────

func readAccountsFile() []SavedAccount {
	b, err := os.ReadFile(AccountsPath())
	if err != nil {
		return nil
	}
	var list []SavedAccount
	if json.Unmarshal(b, &list) != nil {
		return nil
	}
	out := list[:0]
	for _, a := range list {
		if a.APIKey != "" {
			out = append(out, a)
		}
	}
	return out
}

// ListAccounts seeds from the active-key file so the account this device
// enforces with always appears, even on a machine that paired before
// accounts.json existed.
func ListAccounts() []SavedAccount {
	list := readAccountsFile()
	active := LoadCredentialFile()
	if active.APIKey != "" {
		for _, a := range list {
			if a.APIKey == active.APIKey {
				return list
			}
		}
		url := active.APIURL
		if url == "" {
			url = DefaultAPIURL
		}
		list = append([]SavedAccount{{APIKey: active.APIKey, APIURL: url}}, list...)
	}
	return list
}

// SaveAccount upserts by apiKey, newest first. Best-effort by design: failing
// to record an account must not fail the login that just succeeded.
func SaveAccount(acc SavedAccount) {
	if acc.AddedAt == 0 {
		acc.AddedAt = time.Now().UnixMilli()
	}
	list := readAccountsFile()
	next := make([]SavedAccount, 0, len(list)+1)
	next = append(next, acc)
	for _, a := range list {
		if a.APIKey != acc.APIKey {
			next = append(next, a)
		}
	}
	writeAccounts(next)
}

// RemoveAccount forgets an account on this device. It does NOT revoke the key
// in the cloud — that is a dashboard action, and conflating them would mean
// tidying a laptop silently locked out every other machine.
func RemoveAccount(apiKey string) {
	list := readAccountsFile()
	next := make([]SavedAccount, 0, len(list))
	for _, a := range list {
		if a.APIKey != apiKey {
			next = append(next, a)
		}
	}
	writeAccounts(next)
}

func writeAccounts(list []SavedAccount) {
	if list == nil {
		list = []SavedAccount{}
	}
	if EnsureDir() != nil {
		return
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(AccountsPath(), b, 0o644)
}

// SetActiveAccount makes an account the one the guard hooks read.
//
// The existing file is decoded generically and merged into, not replaced: it
// can carry keys written by a newer version of the other implementation, and
// dropping them here would be this port quietly deleting the npm package's
// state.
func SetActiveAccount(c Credential) bool {
	if EnsureDir() != nil {
		return false
	}
	existing := map[string]any{}
	if b, err := os.ReadFile(CredentialPath()); err == nil {
		_ = json.Unmarshal(b, &existing)
	}
	existing["apiKey"] = c.APIKey
	existing["apiUrl"] = c.APIURL
	b, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return false
	}
	return WriteProtectedFile(CredentialPath(), b)
}

// ClearActiveCredential is a local sign-out: it removes the key and URL from
// the active-key file so ListAccounts stops re-seeding them.
//
// That re-seeding is the "ghost account …xxxx" that used to linger after
// removing the account you were logged in as. The guard then has no key until
// the next login, so this only runs when the LAST account is removed.
func ClearActiveCredential() bool {
	b, err := os.ReadFile(CredentialPath())
	if err != nil {
		if os.IsNotExist(err) {
			return true
		}
		return false
	}
	existing := map[string]any{}
	// An unreadable file is overwritten with an empty object rather than left
	// holding a key nobody can see.
	_ = json.Unmarshal(b, &existing)
	delete(existing, "apiKey")
	delete(existing, "apiUrl")
	out, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return false
	}
	return WriteProtectedFile(CredentialPath(), out)
}
