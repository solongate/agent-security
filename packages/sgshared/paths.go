package sgshared

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf16"
)

// SGDir is ~/.solongate, where everything below it lives.
// DirMode is the mode for ~/.solongate, and FileMode for what goes in it.
//
// Owner-only, because this directory holds credentials and the policy cache. It
// is declared HERE rather than at each call site because several programs create
// the same directory — the guard through this package, the CLI through
// internal/config, the hooks in JavaScript — and the first one to run decides the
// mode. They disagreed: one used 0700 and another 0755, so which mode the
// directory ended up with depended on which program a machine happened to run
// first.
const (
	DirMode  = 0o700
	FileMode = 0o600
)

// EnsureSGDir creates ~/.solongate owner-only, correcting a directory that is
// already there.
//
// MkdirAll applies a mode only when it CREATES, so a directory made by an older
// version — or by another one of these programs — keeps whatever it had. Chmod is
// best effort: it must not stop the guard from working on a filesystem with no
// POSIX bits.
func EnsureSGDir() error {
	dir := SGDir()
	if err := os.MkdirAll(dir, DirMode); err != nil {
		return err
	}
	if info, err := os.Stat(dir); err == nil && info.Mode().Perm() != DirMode {
		_ = os.Chmod(dir, DirMode)
	}
	return nil
}

func SGDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	return filepath.Join(home, ".solongate")
}

// AgentKey turns a policy selector into a filename component, as
// `.replace(/[^a-zA-Z0-9_-]/g, '_')` does on the JavaScript side.
//
// The loop is over UTF-16 code units because that regex runs on a UTF-16
// string, so a character outside the basic plane is TWO replacements there. A
// range over runes would produce one, and a cache file named differently by two
// implementations is a policy that appears not to apply.
func AgentKey(agent string) string {
	var b strings.Builder
	for _, u := range utf16.Encode([]rune(agent)) {
		r := rune(u)
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "default"
	}
	return b.String()
}

// ProjectKey is FNV-1a over a path, and it is the reason this package exists.
//
// The per-call flags the guard and the audit hook pass to each other live under
// ~/.solongate/projects/<key>, keyed by a hash of the project path so they stay
// separated per project without being written INTO the project. Four programs
// compute this independently and none of them compares its answer with anyone
// else's: this guard, the Node guard, the audit hook and the dataroom. They just
// each look in the folder their own answer names.
//
// So a disagreement is silent. It is not a wrong number, it is a different
// directory: the dataroom reads an empty ring, evaluation times go missing, and
// the deny flag stops suppressing the audit hook's duplicate entry. Nothing
// logs anything.
//
// The loop is over UTF-16 CODE UNITS because JavaScript's charCodeAt yields
// those. Iterating bytes agrees on ASCII and diverges the moment a path is not:
// /home/müşteri/proj is 98d8e9fc in Node and 1ec69c96 over bytes. That bug
// shipped in guard-go and was found only because a second module was written
// against the same files.
func ProjectKey(dir string) string {
	var h uint32 = 0x811c9dc5
	for _, u := range utf16.Encode([]rune(dir)) {
		h ^= uint32(u)
		h = h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))
	}
	const hexDigits = "0123456789abcdef"
	if h == 0 {
		return "0"
	}
	var out []byte
	for h > 0 {
		out = append([]byte{hexDigits[h&0xf]}, out...)
		h >>= 4
	}
	return string(out)
}

// ProjectFlagDir is where this working directory's per-call flags go.
func ProjectFlagDir() string {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		abs = cwd
	}
	return filepath.Join(SGDir(), "projects", ProjectKey(abs))
}

// A real key is sg_live_ or sg_test_ followed by hex.
//
// It matters more than a format check looks: an unusable key means "no project
// selected", which means ALLOW, so a placeholder in a stray .env silently
// disarms the guard rather than erroring. The sample files ship
// `sg_live_your_key_here`, which passes a truthiness test and nothing else.
var realKeyBody = regexp.MustCompile(`(?i)^[a-f0-9]{16,}$`)

func IsRealKey(k string) bool {
	v := strings.TrimSpace(k)
	if !strings.HasPrefix(v, "sg_live_") && !strings.HasPrefix(v, "sg_test_") {
		return false
	}
	body := v[len("sg_live_"):]
	lower := strings.ToLower(body)
	for _, bad := range []string{"your_key_here", "placeholder", "example"} {
		if strings.Contains(lower, bad) {
			return false
		}
	}
	return realKeyBody.MatchString(body)
}

// GuessPermission is the ENFORCING classifier, and this is the one that has to
// survive: it is `input.permission` in a compiled policy, so a rule scoped to
// WRITE fires or does not fire on this answer.
//
// proxy-go carried a second, smaller version of this from the MCP proxy's core.
// That one misses Codex's apply_patch, which would classify a Codex file edit
// as a READ and let every WRITE-scoped rule miss it. Both callers use this now.
//
// Two entries look like special cases and are not. Codex sends every file edit
// as one tool named apply_patch, which no substring below matches. And `bash`
// is an exact match rather than a substring, so a tool merely named
// `bashful-search` is not treated as a shell.
func GuessPermission(tool string) string {
	n := strings.ToLower(tool)
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(n, s) {
				return true
			}
		}
		return false
	}
	switch {
	case n == "apply_patch" || n == "applypatch":
		return "WRITE"
	case has("exec", "shell", "run", "eval") || n == "bash":
		return "EXECUTE"
	case has("fetch", "http", "request", "curl", "network", "download", "upload") || n == "websearch":
		return "NETWORK"
	// `replace`, `patch` and `modify` are here because Antigravity's edit tool is
	// `replace_file_content`, which matched none of the words above and fell
	// through to READ. A WRITE-scoped rule therefore missed the tool the agent
	// actually edits with, while a READ-scoped one blocked it -- both wrong, and
	// the first is the dangerous direction: "deny writes under config/" left the
	// agent free to rewrite config/ all day.
	//
	// The list is words a tool NAME uses for changing something, not an
	// enumeration of known tools. A client is free to invent a name, and the one
	// that classifies wrong is silently unguarded rather than loudly broken, so
	// it errs wide: `append`, `rename` and `move` are here for the same reason
	// even though nothing ships them today.
	case has("write", "create", "delete", "update", "set", "edit", "remove", "insert",
		"replace", "patch", "modify", "append", "overwrite", "rename", "move", "mkdir", "touch"):
		return "WRITE"
	default:
		return "READ"
	}
}
