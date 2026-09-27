// Package solon is the model side of POST /api/v1/ai/chat: the port of
// src/lib/solon-prompt.ts and the Anthropic call in that route.
//
// It is a separate package from the handler for one reason. This is the only
// code in the service that SPENDS MONEY on somebody else's bill, and the quota
// that bounds that spend lives in internal/store, keyed by user. Keeping the
// model call behind a small surface makes it obvious at the call site that a
// request reaches Anthropic exactly once, after the quota has been read and
// charged — and makes it hard for a future route to reach the model without
// passing that gate.
//
// Nothing here writes to a database and nothing here reads a project id. The
// only tenant-shaped values it sees are the project name and description that
// go into the system prompt, and they arrive from the request body, as in the
// live app.
package solon

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// systemPrompt is src/lib/solon-prompt.ts's SOLON_SYSTEM_PROMPT.
//
// It is an embedded file rather than a Go string literal because it is nine
// kilobytes of Markdown containing backticks, quotes and backslashes: a raw
// literal cannot hold the backticks and an interpreted one would need every
// line re-escaped by hand. A file is byte-identical to the TypeScript by
// construction, and a change to it is a diff a person can read.
//
//go:embed system_prompt.txt
var systemPrompt string

// The model call, exactly as the live route makes it.
const (
	// Model is the one the deployed route names. It is not a default to
	// modernise as part of a port: this endpoint bills a real account per token,
	// its quota (five chats) was sized against this model's cost, and its output
	// is parsed by countGeneratedPolicies — so a swap is a product decision with
	// a price attached, not a translation detail.
	Model = "claude-sonnet-5"

	// MaxTokens is the original's 32000, and its comment there is worth keeping:
	// a thorough policy is a threat model, ten to eighteen rules of JSON, a
	// per-rule explanation and the DLP/ghost/rate-limit recommendations. At 4096
	// the answer was cut off mid-policy, which is what made Solon look shallow.
	// The request streams, so a high ceiling costs nothing when the answer is
	// short.
	MaxTokens = 32000
)

// Role is a chat turn's author. Only these two are accepted, as the route's
// validation says.
const (
	RoleUser      = "user"
	RoleAssistant = "assistant"
)

// Message is one turn of the conversation the caller sends.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// BuildSystemPrompt appends the project context, as buildSystemPrompt does.
//
// The description is only appended when it is non-empty, matching the
// original's `if (projectDescription)` — an empty one would otherwise add a
// bullet that says nothing and costs tokens on every request.
func BuildSystemPrompt(projectName, projectDescription string) string {
	var b strings.Builder
	b.WriteString(systemPrompt)
	b.WriteString("\n\n## Current Project Context\n- **Project**: ")
	b.WriteString(projectName)
	if projectDescription != "" {
		b.WriteString("\n- **Description**: ")
		b.WriteString(projectDescription)
	}
	return b.String()
}

// ── the client ──────────────────────────────────────────────────────────────

// Client wraps the Anthropic SDK client. The zero value is not usable; get one
// from Configured.
type Client struct{ api anthropic.Client }

var (
	clientOnce sync.Once
	client     *Client
)

// Configured returns the shared client, or nil when ANTHROPIC_API_KEY is not
// set on this service.
//
// Built once and cached, as the live route's lazy singleton is: constructing a
// client per request would rebuild a connection pool for every chat. The key is
// read from the environment ONCE for the same reason the live app does — and,
// as there, a key added after start does not take effect until a restart.
//
// nil is a first-class answer and not an error. The route turns it into a 503
// with its own code, because "this deployment has no AI key" is a
// configuration state the dashboard shows differently from a failure.
func Configured() *Client {
	clientOnce.Do(func() {
		key := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))
		if key == "" {
			return
		}
		client = &Client{api: anthropic.NewClient(option.WithAPIKey(key))}
	})
	return client
}

// Stream runs the chat and hands each text delta to onText as it arrives.
//
// Only text deltas are forwarded, which is the live route's filter
// (`event.type === 'content_block_delta' && event.delta.type === 'text_delta'`).
// Anything else the model emits — thinking blocks, tool blocks — is dropped
// rather than rendered, because the dashboard's reader expects prose and a
// policy JSON block and would show the rest to the user as text.
//
// `thinking` is deliberately not configured, so this request gets the API's
// default for the model — the same default the Node SDK gets from the same
// omission. Setting it here would make the two implementations behave
// differently for the same account.
//
// An error from onText stops the stream and is returned unchanged: that is how
// the caller reports a client that hung up, and continuing to bill tokens for a
// response nobody is reading would be the wrong answer to it.
func (c *Client) Stream(ctx context.Context, system string, msgs []Message, onText func(string) error) error {
	turns := make([]anthropic.MessageParam, 0, len(msgs))
	for _, m := range msgs {
		block := anthropic.NewTextBlock(m.Content)
		if m.Role == RoleAssistant {
			turns = append(turns, anthropic.NewAssistantMessage(block))
			continue
		}
		turns = append(turns, anthropic.NewUserMessage(block))
	}

	stream := c.api.Messages.NewStreaming(ctx, anthropic.MessageNewParams{
		Model:     Model,
		MaxTokens: MaxTokens,
		System:    []anthropic.TextBlockParam{{Text: system}},
		Messages:  turns,
	})
	defer stream.Close()

	for stream.Next() {
		event := stream.Current()
		delta, ok := event.AsAny().(anthropic.ContentBlockDeltaEvent)
		if !ok {
			continue
		}
		text, ok := delta.Delta.AsAny().(anthropic.TextDelta)
		if !ok {
			continue
		}
		if text.Text == "" {
			continue
		}
		if err := onText(text.Text); err != nil {
			return err
		}
	}
	return stream.Err()
}

// ── error rendering ─────────────────────────────────────────────────────────

// DescribeStreamError is the port of describeStreamError.
//
// Its output is shown to a person in the dashboard's chat window, so the
// strings are the original's word for word. What it must never do is put the
// provider's raw error object on screen: that carries request ids, headers and,
// on some failures, the account's own configuration. Only the provider's
// `error.message` is surfaced, and only because the live app surfaces it and
// because it is the one field that tells a user whether to wait or to tell
// somebody the key expired.
func DescribeStreamError(err error) string {
	if err == nil {
		return "Stream interrupted"
	}

	var apiErr *anthropic.Error
	if errors.As(err, &apiErr) {
		if msg := providerMessage(apiErr.RawJSON()); msg != "" {
			return "AI request failed: " + msg
		}
		switch apiErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return "AI request failed: the server's ANTHROPIC_API_KEY is missing, invalid, or revoked."
		case http.StatusNotFound:
			return "AI request failed: the configured model is not available for this account."
		case http.StatusTooManyRequests:
			return "AI is rate limited or out of credits on the provider. Try again shortly."
		}
		if apiErr.StatusCode >= 500 {
			return "The AI provider is temporarily unavailable. Try again shortly."
		}
	}

	// The live app's last resort is `AI request failed: ${e.message}` for any
	// error carrying one. A transport error's message here is Go's, not the
	// provider's — "context deadline exceeded", a TLS failure — and none of
	// those name anything private, so it is passed through as the original does.
	if msg := strings.TrimSpace(err.Error()); msg != "" {
		return "AI request failed: " + msg
	}
	return "Stream interrupted"
}

// providerMessage digs `error.error.message` out of the provider's response
// body, which is where the SDK's own message is assembled from.
//
// A body that is not the expected envelope yields nothing rather than being
// echoed: an unrecognised body is exactly the case where it might be an HTML
// error page from something in front of the API, and pasting that into a chat
// window is how a proxy's internal hostname ends up on a user's screen.
func providerMessage(raw string) string {
	if raw == "" {
		return ""
	}
	var envelope struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		return ""
	}
	return strings.TrimSpace(envelope.Error.Message)
}

// ── policy accounting ───────────────────────────────────────────────────────

// policyBlockRe finds the ```json fences in the answer.
//
// It is the original's /```json\s*\n([\s\S]*?)```/g. Go's regexp is leftmost-
// first like JavaScript's, and (?s) is what makes `.` cross newlines, so the
// two match the same spans. The laziness matters: a greedy body would swallow
// every fence in a long answer into one block and the count would be one.
var policyBlockRe = regexp.MustCompile("(?s)```json\\s*\\n(.*?)```")

// CountGeneratedPolicies counts the policies in a finished answer.
//
// This is the meter on the expensive half of the quota: a chat costs one chat,
// but a chat that produced two policies also costs two policy generations, and
// the policy allowance is the smaller of the two. The count comes from the
// MODEL'S OUTPUT and never from the request, which is the whole reason it is
// computed here rather than accepted as a number a caller could send.
//
// A block counts only if it parses AND carries a `rules` ARRAY, matching
// `parsed && Array.isArray(parsed.rules)`. A ```json fence holding an example
// snippet, a fragment, or a rules object rather than a list is not a policy and
// is not charged for.
func CountGeneratedPolicies(markdown string) int {
	n := 0
	for _, m := range policyBlockRe.FindAllStringSubmatch(markdown, -1) {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(m[1]), &parsed); err != nil {
			continue
		}
		if parsed == nil {
			// `null` parses in both languages and is falsy in the original.
			continue
		}
		if _, ok := parsed["rules"].([]any); ok {
			n++
		}
	}
	return n
}
