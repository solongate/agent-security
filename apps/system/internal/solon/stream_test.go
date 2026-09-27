package solon

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// Stream's job is to pull the text out of the provider's event stream, and the
// type switch that does it is the one place in this package where getting the
// SDK's shape wrong compiles cleanly and produces nothing: no error, no text,
// an empty answer and a charged quota. These tests run it against a fake
// provider so that failure is a test failure.

func testClient(t *testing.T, handler http.HandlerFunc) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	return &Client{api: anthropic.NewClient(
		option.WithAPIKey("sk-ant-test"),
		option.WithBaseURL(srv.URL),
		// A retry would replay the whole stream and double every assertion
		// below; the handler answers once.
		option.WithMaxRetries(0),
	)}, srv.Close
}

func sse(w http.ResponseWriter, frames ...string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	for _, f := range frames {
		_, _ = io.WriteString(w, f)
	}
}

const (
	frameMessageStart = "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-5","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}}` + "\n\n"
	frameBlockStart = "event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n"
	frameBlockStop = "event: content_block_stop\n" + `data: {"type":"content_block_stop","index":0}` + "\n\n"
	frameMsgDelta  = "event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":5}}` + "\n\n"
	frameMessageStop = "event: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n"
)

func textDelta(text string) string {
	return "event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"` + text + `"}}` + "\n\n"
}

func TestStreamForwardsTextDeltasInOrder(t *testing.T) {
	client, closeSrv := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/v1/messages") {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		sse(w,
			frameMessageStart,
			frameBlockStart,
			textDelta("Here is "),
			// A thinking delta must NOT be forwarded: the dashboard renders what
			// arrives as the answer, so reasoning would appear as prose.
			"event: content_block_delta\n"+
				`data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"pondering"}}`+"\n\n",
			textDelta("your policy."),
			frameBlockStop,
			frameMsgDelta,
			frameMessageStop,
		)
	})
	defer closeSrv()

	var got []string
	err := client.Stream(context.Background(), "system", []Message{{Role: RoleUser, Content: "hi"}},
		func(text string) error {
			got = append(got, text)
			return nil
		})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if strings.Join(got, "") != "Here is your policy." {
		t.Errorf("deltas = %q, want the two text deltas and nothing else", got)
	}
}

// A caller that hangs up mid-answer must stop the stream. Continuing would keep
// billing tokens for a response nobody is reading.
func TestStreamStopsWhenTheWriterFails(t *testing.T) {
	client, closeSrv := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		sse(w, frameMessageStart, frameBlockStart,
			textDelta("one"), textDelta("two"), textDelta("three"),
			frameBlockStop, frameMsgDelta, frameMessageStop)
	})
	defer closeSrv()

	hangUp := errors.New("client went away")
	seen := 0
	err := client.Stream(context.Background(), "system", []Message{{Role: RoleUser, Content: "hi"}},
		func(string) error {
			seen++
			return hangUp
		})
	if !errors.Is(err, hangUp) {
		t.Fatalf("err = %v, want the writer's error unchanged", err)
	}
	if seen != 1 {
		t.Errorf("kept streaming after the writer failed: %d deltas", seen)
	}
}

// A provider failure has to arrive as an *anthropic.Error so DescribeStreamError
// can turn it into the sentence the live app shows. If it did not, every
// provider failure would read as "Stream interrupted" and nobody would learn
// that the key was revoked.
func TestStreamSurfacesAProviderError(t *testing.T) {
	client, closeSrv := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
	})
	defer closeSrv()

	err := client.Stream(context.Background(), "system", []Message{{Role: RoleUser, Content: "hi"}},
		func(string) error { return nil })
	if err == nil {
		t.Fatal("a 401 from the provider produced no error")
	}

	var apiErr *anthropic.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %T, want *anthropic.Error", err)
	}
	if apiErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", apiErr.StatusCode)
	}
	if got := DescribeStreamError(err); got != "AI request failed: invalid x-api-key" {
		t.Errorf("DescribeStreamError = %q", got)
	}
}

// The status-code branches only fire when the provider sent no message of its
// own, which is what a gateway in front of the API produces.
func TestDescribeStreamErrorFallsBackToTheStatus(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{http.StatusUnauthorized, "AI request failed: the server's ANTHROPIC_API_KEY is missing, invalid, or revoked."},
		{http.StatusNotFound, "AI request failed: the configured model is not available for this account."},
		{http.StatusTooManyRequests, "AI is rate limited or out of credits on the provider. Try again shortly."},
		{http.StatusBadGateway, "The AI provider is temporarily unavailable. Try again shortly."},
	}

	for _, c := range cases {
		client, closeSrv := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(c.status)
			_, _ = io.WriteString(w, "<html><title>gateway</title></html>")
		})

		err := client.Stream(context.Background(), "system", []Message{{Role: RoleUser, Content: "hi"}},
			func(string) error { return nil })
		closeSrv()

		if err == nil {
			t.Fatalf("%d produced no error", c.status)
		}
		if got := DescribeStreamError(err); got != c.want {
			t.Errorf("%d: DescribeStreamError = %q, want %q", c.status, got, c.want)
		}
	}
}

// The request has to carry the system prompt and the turns in the roles the
// caller gave them: a conversation replayed with every turn as `user` is a
// different conversation.
func TestStreamSendsTheConversation(t *testing.T) {
	var body string
	client, closeSrv := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		sse(w, frameMessageStart, frameBlockStart, textDelta("ok"), frameBlockStop, frameMsgDelta, frameMessageStop)
	})
	defer closeSrv()

	err := client.Stream(context.Background(), "SYSTEM PROMPT", []Message{
		{Role: RoleUser, Content: "first"},
		{Role: RoleAssistant, Content: "second"},
		{Role: RoleUser, Content: "third"},
	}, func(string) error { return nil })
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	for _, want := range []string{
		`"model":"claude-sonnet-5"`,
		`"max_tokens":32000`,
		`SYSTEM PROMPT`,
		`"role":"user"`,
		`"role":"assistant"`,
		`"stream":true`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("request body is missing %s:\n%s", want, body)
		}
	}
	if strings.Count(body, `"role":"assistant"`) != 1 {
		t.Errorf("assistant turns = %d, want 1", strings.Count(body, `"role":"assistant"`))
	}
}
