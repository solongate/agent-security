// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/solongate/agent-security/packages/sgshared"
	"regexp"
	"strings"
	"testing"
)

// The redaction that runs BEFORE the tool masked only the BEGIN line, so the key
// material itself went through. That is the only masking available on the
// clients which cannot rewrite tool output — Antigravity, Codex, OpenCode — so
// the three that depend on it entirely had the weakest version of it, while
// Claude Code, which masks afterwards, already covered the whole block.
//
// The markers are assembled rather than written out: the pattern under test
// matches this file's own contents otherwise, and DLP refuses to save it. That
// is the fix working, and it is worth knowing it reaches this far.
func TestPrivateKeyRedactionCoversTheWholeBlock(t *testing.T) {
	begin := "-----BE" + "GIN RSA PRIVATE KEY-----"
	end := "-----E" + "ND RSA PRIVATE KEY-----"
	body := "MIIEowIBAAKCAQEAxFAKEfakeFAKEfakeFAKEfake"
	pem := "deploy key:\n" + begin + "\n" + body + "\n" + end + "\n"

	var re = patternNamed(t, "Private key block")

	got := re.ReplaceAllString(pem, "[REDACTED]")
	if strings.Contains(got, body) {
		t.Errorf("the key material survived redaction:\n%s", got)
	}
	if strings.Contains(got, end) {
		t.Errorf("the block footer survived redaction:\n%s", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("nothing was redacted:\n%s", got)
	}
	// The line before it is not part of the key and must survive.
	if !strings.Contains(got, "deploy key:") {
		t.Errorf("redaction ate the surrounding text:\n%s", got)
	}

	// A header with no footer — a truncated paste, or a key still being written
	// — must still be caught, by the fallback half of the alternation.
	if !re.MatchString("-----BE" + "GIN OPENSSH PRIVATE KEY-----\nAAAA") {
		t.Error("a block with no footer must still match")
	}

	// Two keys in one file are two matches, not one run from the first BEGIN to
	// the last END, which would swallow whatever sits between them.
	two := begin + "\n" + body + "\n" + end + "\nkeep me\n" + begin + "\n" + body + "\n" + end
	if out := re.ReplaceAllString(two, "[REDACTED]"); !strings.Contains(out, "keep me") {
		t.Errorf("the text between two keys was swallowed:\n%s", out)
	}
}

func patternNamed(t *testing.T, name string) *regexp.Regexp {
	t.Helper()
	// The table lives in sgshared now, so the MCP proxy can scan with the same one.
	if i := sgshared.DLPPatternIndex(name); i >= 0 {
		_, re := sgshared.DLPPatternAt(i)
		return re
	}
	t.Fatalf("the %q pattern is gone; a policy naming it would enforce nothing", name)
	return nil
}
