package solon

import (
	"errors"
	"strings"
	"testing"
)

// The policy meter is the expensive half of the quota: a chat costs one chat,
// but a chat that produced two policies also costs two policy generations, and
// the policy allowance is the smaller of the two. Over-counting takes an
// allowance away from a user who did nothing; under-counting is a way to get
// unlimited policy generations by asking for them one conversation at a time.
func TestCountGeneratedPolicies(t *testing.T) {
	cases := []struct {
		name     string
		markdown string
		want     int
	}{
		{"nothing", "here is some prose with no code at all", 0},
		{
			"one policy",
			"Here you go:\n\n```json\n{\"name\":\"p\",\"rules\":[{\"effect\":\"DENY\"}]}\n```\n\nThat blocks it.",
			1,
		},
		{
			"two policies in one answer",
			"```json\n{\"rules\":[]}\n```\nand another\n```json\n{\"rules\":[{\"effect\":\"ALLOW\"}]}\n```",
			2,
		},
		{
			// A fenced block that is not a policy is not charged for. The model
			// quotes example JSON constantly.
			"a json block with no rules",
			"```json\n{\"denied\":[\"*rm -rf*\"]}\n```",
			0,
		},
		{"rules is an object, not a list", "```json\n{\"rules\":{\"a\":1}}\n```", 0},
		{"not json at all", "```json\nnot json\n```", 0},
		{"json null", "```json\nnull\n```", 0},
		{"a top-level array", "```json\n[1,2,3]\n```", 0},
		{"a fence that is not json", "```js\n{\"rules\":[]}\n```", 0},
		{
			// The expression is lazy in the original; a greedy body would swallow
			// both fences into one block and count one.
			"two adjacent fences are not one",
			"```json\n{\"rules\":[]}\n```\n```json\n{\"rules\":[]}\n```",
			2,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CountGeneratedPolicies(c.markdown); got != c.want {
				t.Errorf("CountGeneratedPolicies = %d, want %d", got, c.want)
			}
		})
	}
}

func TestBuildSystemPrompt(t *testing.T) {
	if !strings.Contains(systemPrompt, "You are Solon") {
		t.Fatal("the embedded system prompt is not the one from src/lib/solon-prompt.ts")
	}

	with := BuildSystemPrompt("payments", "the billing service")
	if !strings.HasSuffix(with, "## Current Project Context\n- **Project**: payments\n- **Description**: the billing service") {
		t.Errorf("project context is wrong:\n%s", with[len(with)-120:])
	}

	// An empty description adds no bullet, matching `if (projectDescription)`.
	// A bullet that says nothing costs tokens on every request.
	without := BuildSystemPrompt("payments", "")
	if strings.Contains(without, "**Description**") {
		t.Error("an empty description should not add a bullet")
	}
	if !strings.HasSuffix(without, "- **Project**: payments") {
		t.Errorf("project context is wrong:\n%s", without[len(without)-60:])
	}
}

// The message goes into a chat window a person is reading, so the strings are
// the original's. What it must never do is put the provider's raw response
// there: that carries request ids and, on some failures, account configuration.
func TestDescribeStreamError(t *testing.T) {
	if got := DescribeStreamError(nil); got != "Stream interrupted" {
		t.Errorf("nil error = %q", got)
	}

	got := DescribeStreamError(errors.New("context deadline exceeded"))
	if got != "AI request failed: context deadline exceeded" {
		t.Errorf("transport error = %q", got)
	}
}

func TestProviderMessageIgnoresAnUnrecognisedBody(t *testing.T) {
	if got := providerMessage(`{"error":{"message":"credit balance is too low"}}`); got != "credit balance is too low" {
		t.Errorf("got %q", got)
	}
	// An HTML error page from something in front of the API must not be pasted
	// into a user's chat window: it names hosts and software versions.
	for _, body := range []string{"", "<html><title>502 Bad Gateway</title>", `{"error":"nope"}`, "null"} {
		if got := providerMessage(body); got != "" {
			t.Errorf("providerMessage(%q) = %q, want empty", body, got)
		}
	}
}
