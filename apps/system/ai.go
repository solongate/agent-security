package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/solon"
	"github.com/codeyevsky/solongate/system/internal/store"
)

// /api/v1/ai/* — the port of src/app/api/v1/ai/{chat,usage,usage/reset}/route.ts.
//
// This is the only place in the service that spends money. Every accepted chat
// is a billed request to Anthropic against SolonGate's own account, on behalf of
// a user who is not paying per token, which is why the accounting below is not
// bookkeeping to tidy up but the thing that stops one person from running the
// bill up on everyone else's behalf.
//
// Four separate bounds apply and each of them exists for a different failure:
//
//	an API key             a stranger cannot spend anything at all
//	20 requests a minute    a loop in a client cannot spend it quickly
//	5 chats per USER        a person cannot spend it slowly
//	2 policy generations    and cannot spend it on the expensive answers
//
// The per-user counters are the ones that matter most and the ones easiest to
// get wrong. They are keyed by KeyInfo.OwnerID, NOT by project: a project is
// something a user can create more of in one click, so a per-project quota is
// no quota. src/lib/solon-usage.ts keys them by user for the same reason, and
// internal/store increments them in a single upsert so two requests arriving
// together cannot both read four and both write five.

func init() {
	Register("POST /api/v1/ai/chat", func(s *server) http.Handler {
		// The AI limit, not the standard one: twenty a minute rather than a
		// hundred. It is the original's AI_RATE_LIMIT and it is per API key.
		return s.auth.WithAuthLimit(apiauth.LimitAI, s.aiChat)
	})
	Register("GET /api/v1/ai/usage", func(s *server) http.Handler {
		return s.auth.WithAuth(s.aiUsage)
	})
	Register("POST /api/v1/ai/usage/reset", func(s *server) http.Handler {
		return s.auth.WithAuth(s.aiUsageReset)
	})
}

// GET /api/v1/ai/usage
func (s *server) aiUsage(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	// `await schemaReady` at the top of src/lib/solon-usage.ts. solon_usage is
	// one of the tables src/db/index.ts creates at runtime, so a process that
	// came up before the database did has to be able to catch up. The call is a
	// mutex read once it has succeeded.
	if err := s.store.EnsureRuntimeTables(r.Context()); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	usage, err := s.store.SolonUsageFor(r.Context(), key.OwnerID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, usage)
}

// POST /api/v1/ai/usage/reset
//
// It resets the caller's OWN counters, taken from the key, and there is no way
// to name somebody else's. That is worth stating because a reset endpoint that
// accepted a user id would be a quota anybody could clear.
//
// It is otherwise exactly as permissive as the live route: any valid key resets
// its owner's allowance. That makes the quota a speed bump rather than a hard
// cap, which is a product decision already taken and not one to change in a
// port — but it does mean the twenty-a-minute limit above is the only bound on
// a determined caller, so it must stay.
func (s *server) aiUsageReset(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	if err := s.store.EnsureRuntimeTables(r.Context()); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	usage, err := s.store.ResetSolonUsage(r.Context(), key.OwnerID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, usage)
}

// The request's limits, from the live route's validation block. They are
// checked before the quota is read, so a malformed request never costs anybody
// a chat.
const (
	aiMaxMessages       = 50
	aiMaxContentUnits   = 8000
	aiStreamWriteBudget = 2 * time.Minute
)

// POST /api/v1/ai/chat
//
// Everything that can refuse the request happens before a single byte of the
// response is written, and that ordering is not stylistic. Once the 200 and the
// text/event-stream headers are out, this handler can no longer send a status
// code — a failure after that point can only be an `error` frame inside a
// successful response, which is why the configuration check, the validation,
// the quota check and the quota charge are all above the first write.
func (s *server) aiChat(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	client := solon.Configured()
	if client == nil {
		// 503 and its own code: "this deployment has no AI key" is a
		// configuration state, and the dashboard shows it differently from a
		// failure the user could retry into.
		apiauth.Error(w, http.StatusServiceUnavailable, "AI_NOT_CONFIGURED",
			"AI chat is not configured. Set ANTHROPIC_API_KEY on the server.")
		return
	}

	body, ok := decodeJSONObject(w, r)
	if !ok {
		return
	}
	messages, projectName, projectDescription, ok := parseChatRequest(w, body)
	if !ok {
		return
	}

	if err := s.store.EnsureRuntimeTables(r.Context()); err != nil {
		apiauth.Internal(w, "ai-chat", err)
		return
	}

	usage, err := s.store.SolonUsageFor(r.Context(), key.OwnerID)
	if err != nil {
		apiauth.Internal(w, "ai-chat", err)
		return
	}
	if usage.Locked {
		apiauth.Error(w, http.StatusForbidden, "SOLON_LIMIT", store.SolonLockMessage)
		return
	}

	// Charged BEFORE the model is called, as the live route does. The
	// alternative — charge on success — sounds fairer and is not: a request that
	// fails after the tokens were generated has already cost money, and a caller
	// who hangs up mid-answer would get every attempt free.
	if _, err := s.store.IncrementSolonChat(r.Context(), key.OwnerID); err != nil {
		apiauth.Internal(w, "ai-chat", err)
		return
	}

	s.streamChat(w, r, key, client, solon.BuildSystemPrompt(projectName, projectDescription), messages)
}

// streamChat is everything after the point of no return.
func (s *server) streamChat(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo,
	client *solon.Client, systemPrompt string, messages []solon.Message) {

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	// X-Accel-Buffering has no counterpart in the live app and is here because
	// this one does not run behind Next's own streaming path: a reverse proxy
	// that buffers an event stream turns a live answer into a wall of text at
	// the end, which reads to a user as a hang.
	h.Set("X-Accel-Buffering", "no")
	//
	// Access-Control-Allow-Origin is NOT set here, and that is a deliberate
	// difference from the original. The live route echoes `origin || '*'` back
	// unconditionally, next to Allow-Credentials: true — so any site at all is
	// told it may read this response. The CORS layer in middleware.go already
	// echoed the origin if it is on the whitelist, which covers the dashboard,
	// the only browser client this endpoint has. Widening that from a whitelist
	// to "whoever asked" is not a contract worth carrying across.

	w.WriteHeader(http.StatusOK)

	rc := http.NewResponseController(w)
	// The server-wide WriteTimeout is 90 seconds (see main.go) and a thorough
	// policy takes longer than that to generate. Left alone, the connection
	// would be cut mid-answer every time — reliably, on exactly the long answers
	// this endpoint exists to produce. The deadline is pushed forward on every
	// flush instead of removed, so a client that stops reading still lets go.
	extend := func() {
		if err := rc.SetWriteDeadline(time.Now().Add(aiStreamWriteBudget)); err != nil &&
			!errors.Is(err, http.ErrNotSupported) {
			log.Printf("[API:ai-chat] could not extend the write deadline: %v", err)
		}
	}
	extend()

	var full strings.Builder

	streamErr := client.Stream(r.Context(), systemPrompt, messages, func(text string) error {
		full.WriteString(text)
		if err := writeSSE(w, map[string]string{"text": text}); err != nil {
			return err
		}
		if err := rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return err
		}
		extend()
		return nil
	})

	if streamErr != nil {
		// The chat has already been charged and stays charged: the tokens up to
		// the failure were generated and billed by the provider whether or not
		// they reached the caller.
		if r.Context().Err() != nil {
			// The caller closed the tab. There is nothing to write the frame to
			// and nothing went wrong, so it is not reported as a failure —
			// otherwise every abandoned chat looks like an outage in the log.
			return
		}
		// The error goes to the log in full and to the caller as one sentence.
		// The frame replaces [DONE] rather than preceding it, as the original
		// does, so a reader cannot mistake a truncated answer for a complete one.
		log.Printf("[API:ai-chat] stream error: %v", streamErr)
		_ = writeSSE(w, map[string]string{"error": solon.DescribeStreamError(streamErr)})
		_ = rc.Flush()
		return
	}

	// The policy meter. The count comes from what the MODEL wrote, never from
	// anything the caller sent, and it is charged after the fact because it
	// cannot be known before.
	if generated := solon.CountGeneratedPolicies(full.String()); generated > 0 {
		// Best effort, as the original's `catch { }`. The answer is already on
		// its way to the user and failing the request now would take a policy
		// away from somebody who has it. It is logged so an accounting hole
		// leaves a trace: the id, never the content.
		if _, err := s.store.IncrementSolonPolicy(r.Context(), key.OwnerID, int64(generated)); err != nil {
			log.Printf("[API:ai-chat] could not record %d generated policies: %v", generated, err)
		}
	}

	_, _ = w.Write([]byte("data: [DONE]\n\n"))
	_ = rc.Flush()
}

// writeSSE emits one `data:` frame.
//
// The payload is JSON on one line, which is what makes the framing safe: the
// dashboard's reader splits the stream on newlines and takes everything after
// `data: ` as JSON, so a model delta containing a newline would end the frame
// early if it were not escaped. json.Marshal escapes it; nothing else here has
// to think about it.
//
// HTML escaping is off, matching apiauth.JSON and JSON.stringify. It changes no
// meaning — both spellings parse to the same string — but policy JSON is full of
// `&&`, `<` and `>` and a delta that arrives spelled differently from the way
// the live app spelled it is a difference somebody will chase.
func writeSSE(w http.ResponseWriter, v any) error {
	var buf bytes.Buffer
	buf.WriteString("data: ")
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	// Encode already appended the newline that ends the line; SSE needs a blank
	// line after it to end the event.
	buf.WriteByte('\n')
	_, err := w.Write(buf.Bytes())
	return err
}

// parseChatRequest is the live route's validation block, in its order.
//
// The order is the contract: a request with fifty-one messages is told it has
// too many before it is told the fiftieth has no role, and the dashboard shows
// whichever message comes back. Every failure is a VALIDATION_ERROR, and every
// one of them happens before the quota is read, so a malformed request never
// costs the caller a chat.
func parseChatRequest(w http.ResponseWriter, body map[string]json.RawMessage) (
	msgs []solon.Message, projectName, projectDescription string, ok bool) {

	var raw []json.RawMessage
	if v, present := body["messages"]; !present || json.Unmarshal(v, &raw) != nil || len(raw) == 0 {
		apiauth.ValidationError(w, "messages array is required")
		return nil, "", "", false
	}
	if len(raw) > aiMaxMessages {
		// A bound on the request, not on the conversation: fifty turns of eight
		// thousand characters is already four hundred thousand characters of
		// input this service would pay to send.
		apiauth.ValidationError(w, "Too many messages (max 50)")
		return nil, "", "", false
	}

	name, hasName := jsTruthyString(body["projectName"])
	if !hasName || !isJSONString(body["projectName"]) {
		// `!projectName || typeof projectName !== 'string'` — both halves, so a
		// number that happens to be truthy is still refused.
		apiauth.ValidationError(w, "projectName is required")
		return nil, "", "", false
	}

	msgs = make([]solon.Message, 0, len(raw))
	for _, item := range raw {
		var m map[string]json.RawMessage
		// A non-object element has no `role` and no `content`, which is the
		// original's first check rather than a parse failure.
		_ = json.Unmarshal(item, &m)

		role, hasRole := jsTruthyString(m["role"])
		_, hasContent := jsTruthyString(m["content"])
		if !hasRole || !hasContent {
			apiauth.ValidationError(w, "Each message must have role and content")
			return nil, "", "", false
		}
		if role != solon.RoleUser && role != solon.RoleAssistant {
			apiauth.ValidationError(w, `Message role must be "user" or "assistant"`)
			return nil, "", "", false
		}
		var content string
		if err := json.Unmarshal(m["content"], &content); err != nil || utf16Len(content) > aiMaxContentUnits {
			apiauth.ValidationError(w, "Message content must be a string under 8000 chars")
			return nil, "", "", false
		}
		msgs = append(msgs, solon.Message{Role: role, Content: content})
	}

	// The description is optional and used only when truthy, as
	// buildSystemPrompt has it. Unlike projectName it is not required to be a
	// string, because the original interpolates whatever it is.
	projectDescription, _ = jsTruthyString(body["projectDescription"])
	return msgs, name, projectDescription, true
}

// isJSONString reports whether a raw value is a JSON string, for the checks the
// original spells `typeof x !== 'string'`.
func isJSONString(raw json.RawMessage) bool {
	var s string
	return len(raw) > 0 && json.Unmarshal(raw, &s) == nil
}

// utf16Len counts a string the way JavaScript's String.prototype.length does.
//
// `msg.content.length > 8000` counts UTF-16 code units, so a character outside
// the basic plane — an emoji, most historic scripts — counts as two there and
// would count as one under a rune count here. Counting bytes would be stricter
// in the other direction and would refuse a message of 8000 accented characters
// that the live app accepts. This counts what the original counts.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n++
		if r > 0xFFFF {
			n++
		}
	}
	return n
}
