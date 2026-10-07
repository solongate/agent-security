// SPDX-License-Identifier: Apache-2.0

package sgpolicy

import (
	"strings"
	"testing"
)

// A path rule names a DIRECTORY. The wildcards say where that directory may
// sit — nested anywhere, or at the root — and whether the rule reaches the
// files inside it. They do not say which characters may surround the word.
//
// The two behaviours this pins were both live, and both wrong in the same
// direction as each other:
//
//   - `*secrets*` blocked `my-secrets-notes.txt`, a file that merely mentions
//     the word, because the matcher compared substrings.
//   - `**/secrets/**` missed `secrets/prod.env` entirely, because a relative
//     path has no separator in front of the first segment, so the rule stopped
//     applying the moment an agent passed a path relative to its cwd.
func TestPathPatternSegments(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Nested anywhere, contents included.
		{"*secrets*", "secrets", true},
		{"*secrets*", "secrets/prod.env", true},
		{"*secrets*", "app/secrets", true},
		{"*secrets*", "app/secrets/deep/prod.env", true},
		{"*secrets*", "/home/u/work/secrets/api-keys.json", true},
		{"*secrets*", "my-secrets-notes.txt", false},
		{"*secrets*", "app/my-secrets-notes.txt", false},
		{"*secrets*", "mysecret", false},
		{"*secrets*", "mysecrets/x", false},
		{"*secrets*", "secretsauce/x", false},

		// Rooted, contents included.
		{"secrets*", "secrets", true},
		{"secrets*", "secrets/prod.env", true},
		{"secrets*", "app/secrets", false},
		{"secrets*", "app/secrets/prod.env", false},

		// Nested anywhere, the directory itself only.
		{"*secrets", "secrets", true},
		{"*secrets", "app/secrets", true},
		{"*secrets", "app/secrets/prod.env", false},
		{"*secrets", "my-secrets", false},

		// No wildcard at all: one exact path.
		{"secrets", "secrets", true},
		{"secrets", "app/secrets", false},
		{"secrets", "secrets/prod.env", false},

		// The `**` spellings people already have in their policies mean the same
		// thing as the single-star form, and now also catch the relative path.
		{"**secrets/**", "secrets/prod.env", true},
		{"**secrets/**", "/home/u/secrets/prod.env", true},
		{"**/secrets/**", "secrets/prod.env", true},
		{"**/secrets/**", "/home/u/secrets/prod.env", true},
		{"**/secrets/**", "my-secrets-notes.txt", false},

		// Multi-segment cores stay one unit.
		{"*var/state*", "workspace/var/state/session.json", true},
		{"*var/state*", "workspace/var/statement.txt", false},
		{"*var/state*", "var/state", true},

		// A `*` inside the pattern is an ordinary wildcard, bounded by the
		// separator — which is how a file pattern is still expressible.
		{"**/*.env", "config/staging.env", true},
		{"**/*.env", "a/b/c/staging.env", true},
		{"**/*.env", "config/settings.json", false},
		{"*.env", ".env", true},
		{"*.env", "config/.env", true},
		{"*.env", "config/staging.env", false},
		{"*stag*.env", "config/staging.env", true},

		// An absolute pattern without a leading wildcard stays rooted.
		{"/etc/ssl*", "/etc/ssl/private/key.pem", true},
		{"/etc/ssl*", "home/etc/ssl/key.pem", false},

		// Case and separator normalisation.
		{"*Secrets*", "APP/SECRETS/x", true},
		{"*secrets*", `app\secrets\prod.env`, true},

		// Nothing but wildcards is a match-everything rule, unchanged.
		{"*", "anything/at/all", true},
		{"**", "anything/at/all", true},
	}

	for _, c := range cases {
		if got := MatchPathGlob(c.path, c.pattern); got != c.want {
			t.Errorf("MatchPathGlob(%q, %q) = %v, want %v  (regex %s)",
				c.path, c.pattern, got, c.want, PathPatternRegex(c.pattern))
		}
	}
}

// The tamper-protection list is written in the same pattern language and is
// matched with the same function, so it has to keep working. These are the
// shapes from guard-go/tamper.go.
func TestPathPatternCoversTamperShapes(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"**/.solongate/hooks/**", "/home/u/.solongate/hooks/guard-file.mjs", true},
		{"**/.solongate/.policy-cache-*.json", "/home/u/.solongate/.policy-cache-claude-code.json", true},
		{"**/.solongate/.policy-cache-*.json", "/home/u/.solongate/other.json", false},
		{"**/.claude/settings.json", "/home/u/.claude/settings.json", true},
		{"**/.claude/settings.json", "/home/u/.claude/settings.local.json", false},
	}
	for _, c := range cases {
		if got := MatchPathGlob(c.path, c.pattern); got != c.want {
			t.Errorf("MatchPathGlob(%q, %q) = %v, want %v  (regex %s)",
				c.path, c.pattern, got, c.want, PathPatternRegex(c.pattern))
		}
	}
}

// The same semantics through the ENGINE that actually decides. EvaluatePolicy
// prefers the compiled Rego and only falls back to the deterministic matcher
// when the policy will not compile, so a test that only exercised
// MatchPathGlob would pass while every real decision came out the old way.
//
// It also proves the generated module compiles at all: the pattern is now a
// regex inside a Rego string literal, and one missed escape is a policy that
// silently drops to the fallback.
func TestPathPatternThroughTheEngine(t *testing.T) {
	pol := policyFrom(t, "denylist", `[{
		"id": "deny-secrets", "effect": "DENY", "priority": 10,
		"toolPattern": "*", "enabled": true,
		"pathConstraints": {"denied": ["*secrets*"]}
	}]`)

	cases := []struct {
		path    string
		blocked bool
	}{
		{"secrets/prod.env", true},
		{"app/secrets/prod.env", true},
		{"/home/u/work/secrets/api-keys.json", true},
		{"my-secrets-notes.txt", false},
		{"mysecret/x.txt", false},
		{"src/app.js", false},
	}

	for _, c := range cases {
		args := map[string]any{"file_path": c.path}
		reason := EvaluatePolicy(pol, args, "Read", "/home/u/work")
		if got := reason != ""; got != c.blocked {
			t.Errorf("EvaluatePolicy(Read %q) blocked = %v, want %v  (reason %q)",
				c.path, got, c.blocked, reason)
		} else if got && !strings.Contains(reason, "OPA") {
			t.Errorf("path %q was decided by the FALLBACK, not the engine: %q", c.path, reason)
		}
	}
}

// An unparseable pattern must match nothing. Matching everything would turn a
// typo in one DENY rule into a block on every call, and a typo in one ALLOW
// rule under whitelist mode into a blanket allow.
func TestPathPatternBadRegexMatchesNothing(t *testing.T) {
	if MatchPathGlob("anything", "[") {
		t.Error("an uncompilable pattern matched")
	}
}
