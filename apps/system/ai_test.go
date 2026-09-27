package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
)

func TestAIRoutesAreClaimed(t *testing.T) {
	for _, pattern := range []string{
		"POST /api/v1/ai/chat",
		"GET /api/v1/ai/usage",
		"POST /api/v1/ai/usage/reset",
	} {
		if _, ok := routeHandlers[pattern]; !ok {
			t.Errorf("%s is not registered", pattern)
		}
	}
}

// The validation messages and their ORDER are the contract: the dashboard shows
// whichever one comes back, and every one of them has to fire before the quota
// is read so a malformed request never costs anybody a chat.
func TestChatValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"no messages", `{"projectName":"p"}`, "messages array is required"},
		{"messages is not an array", `{"messages":"hi","projectName":"p"}`, "messages array is required"},
		{"empty messages", `{"messages":[],"projectName":"p"}`, "messages array is required"},
		{
			"too many messages",
			`{"messages":[` + strings.TrimSuffix(strings.Repeat(`{"role":"user","content":"x"},`, 51), ",") + `],"projectName":"p"}`,
			"Too many messages (max 50)",
		},
		{"no project name", `{"messages":[{"role":"user","content":"x"}]}`, "projectName is required"},
		{"empty project name", `{"messages":[{"role":"user","content":"x"}],"projectName":""}`, "projectName is required"},
		{"numeric project name", `{"messages":[{"role":"user","content":"x"}],"projectName":7}`, "projectName is required"},
		{"message with no role", `{"messages":[{"content":"x"}],"projectName":"p"}`, "Each message must have role and content"},
		{"message with empty content", `{"messages":[{"role":"user","content":""}],"projectName":"p"}`, "Each message must have role and content"},
		{"message is not an object", `{"messages":["hello"],"projectName":"p"}`, "Each message must have role and content"},
		{"bad role", `{"messages":[{"role":"system","content":"x"}],"projectName":"p"}`, `Message role must be "user" or "assistant"`},
		{
			"content too long",
			`{"messages":[{"role":"user","content":"` + strings.Repeat("a", 8001) + `"}],"projectName":"p"}`,
			"Message content must be a string under 8000 chars",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var body map[string]json.RawMessage
			if err := json.Unmarshal([]byte(c.body), &body); err != nil {
				t.Fatalf("test body is not JSON: %v", err)
			}
			rec := httptest.NewRecorder()
			if _, _, _, ok := parseChatRequest(rec, body); ok {
				t.Fatalf("accepted %s", c.body)
			}
			var got apiauth.ErrorBody
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("response is not JSON: %v", err)
			}
			if got.Error.Message != c.want {
				t.Errorf("message = %q, want %q", got.Error.Message, c.want)
			}
			if got.Error.Code != "VALIDATION_ERROR" {
				t.Errorf("code = %q, want VALIDATION_ERROR", got.Error.Code)
			}
		})
	}
}

func TestChatAcceptsAValidRequest(t *testing.T) {
	var body map[string]json.RawMessage
	if err := json.Unmarshal([]byte(`{
		"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"hello"}],
		"projectName":"payments",
		"projectDescription":"the billing service"
	}`), &body); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	msgs, name, desc, ok := parseChatRequest(rec, body)
	if !ok {
		t.Fatalf("refused a valid request: %s", rec.Body.String())
	}
	if len(msgs) != 2 || msgs[0].Role != "user" || msgs[1].Role != "assistant" {
		t.Errorf("messages = %+v", msgs)
	}
	if name != "payments" || desc != "the billing service" {
		t.Errorf("name = %q, description = %q", name, desc)
	}
}

// The dashboard's reader splits the stream on newlines and JSON-parses whatever
// follows `data: `. A delta containing a newline would end the frame early if
// it were not escaped, and the answer would arrive truncated with no error.
func TestSSEFrameSurvivesANewlineInTheDelta(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := writeSSE(rec, map[string]string{"text": "line one\nline two"}); err != nil {
		t.Fatalf("writeSSE: %v", err)
	}

	frame := rec.Body.String()
	if !strings.HasSuffix(frame, "\n\n") {
		t.Errorf("frame does not end with a blank line: %q", frame)
	}
	lines := strings.Split(strings.TrimSuffix(frame, "\n\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("frame spans %d lines, want 1: %q", len(lines), frame)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[0], "data: ")), &got); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if got["text"] != "line one\nline two" {
		t.Errorf("text = %q, the newline did not survive the round trip", got["text"])
	}
}

// JSON.stringify does not escape < > &, and policy JSON is full of them. Both
// spellings parse to the same string, but a delta that arrives spelled
// differently from the way the live app spelled it is a difference somebody
// will spend an afternoon on.
func TestSSEFrameDoesNotEscapeHTML(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := writeSSE(rec, map[string]string{"text": `"denied": ["*a && b*", "<x>"]`}); err != nil {
		t.Fatalf("writeSSE: %v", err)
	}
	frame := rec.Body.String()
	// Go's encoder rewrites these three characters into their \u00xx forms by
	// default. JSON.stringify does not, so neither may this. The needles are the
	// six-character escape sequences, not the characters themselves.
	for _, escaped := range []string{"\\u0026", "\\u003c", "\\u003e"} {
		if strings.Contains(frame, escaped) {
			t.Errorf("frame contains %s; JSON.stringify leaves that character alone: %s", escaped, frame)
		}
	}
	if !strings.Contains(frame, "&& b") || !strings.Contains(frame, "<x>") {
		t.Errorf("frame does not carry the characters verbatim: %s", frame)
	}
}

func TestUTF16LenCountsTheWayJavaScriptDoes(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"abc", 3},
		{"café", 4}, // é is one UTF-16 unit and two bytes
		{"👋", 2},    // a surrogate pair: JavaScript says 2
		{"a👋b", 4},
	}
	for _, c := range cases {
		if got := utf16Len(c.in); got != c.want {
			t.Errorf("utf16Len(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
