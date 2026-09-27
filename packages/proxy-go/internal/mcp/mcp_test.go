package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// newTestPair wires a client to a server over an in-memory pipe and returns the
// connected client.
func newTestPair(t *testing.T, configure func(*Server)) *Client {
	t.Helper()

	clientSide, serverSide := NewPipe()
	server := NewServer(Implementation{Name: "test-server", Version: "1.0.0"})
	configure(server)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = server.Serve(ctx, serverSide) }()

	client := NewClient(Implementation{Name: "test-client", Version: "1.0.0"})
	connectCtx, connectCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer connectCancel()
	if err := client.Connect(connectCtx, clientSide); err != nil {
		cancel()
		t.Fatalf("connect: %v", err)
	}

	t.Cleanup(func() {
		_ = client.Close()
		cancel()
	})
	return client
}

func TestInitializeEchoesTheClientsProtocolVersion(t *testing.T) {
	// A client that asked for 2024-11-05 and is answered with a later revision
	// treats the session as unusable, so the answer has to be its own number.
	clientSide, serverSide := NewPipe()
	server := NewServer(Implementation{Name: "s", Version: "1"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx, serverSide) }()

	req := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`
	if err := clientSide.Send(ctx, json.RawMessage(req)); err != nil {
		t.Fatal(err)
	}
	frame, err := clientSide.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var msg Message
	if err := json.Unmarshal(frame, &msg); err != nil {
		t.Fatal(err)
	}
	var result InitializeResult
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatal(err)
	}
	if result.ProtocolVersion != "2024-11-05" {
		t.Fatalf("got protocol version %q, want the client's own", result.ProtocolVersion)
	}
}

func TestInitializeFallsBackForAnUnknownProtocolVersion(t *testing.T) {
	clientSide, serverSide := NewPipe()
	server := NewServer(Implementation{Name: "s", Version: "1"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx, serverSide) }()

	req := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`
	_ = clientSide.Send(ctx, json.RawMessage(req))
	frame, err := clientSide.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var msg Message
	_ = json.Unmarshal(frame, &msg)
	var result InitializeResult
	_ = json.Unmarshal(msg.Result, &result)
	if result.ProtocolVersion != ProtocolVersion {
		t.Fatalf("got %q, want %q", result.ProtocolVersion, ProtocolVersion)
	}
}

func TestOnInitializedCarriesClientInfo(t *testing.T) {
	got := make(chan Implementation, 1)
	newTestPair(t, func(s *Server) {
		s.OnInitialized = func(client Implementation) { got <- client }
	})

	select {
	case client := <-got:
		if client.Name != "test-client" {
			t.Fatalf("clientInfo name = %q", client.Name)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("OnInitialized never fired")
	}
}

func TestRequestAndResponseRoundTrip(t *testing.T) {
	client := newTestPair(t, func(s *Server) {
		s.SetRequestHandler("tools/list", func(context.Context, *Request) (any, error) {
			return listToolsResult{Tools: []Tool{{Name: "read_file", InputSchema: map[string]any{"type": "object"}}}}, nil
		})
	})

	tools, err := client.ListTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 || tools[0].Name != "read_file" {
		t.Fatalf("tools = %+v", tools)
	}
}

func TestUnknownMethodIsMethodNotFound(t *testing.T) {
	client := newTestPair(t, func(*Server) {})

	err := client.Request(context.Background(), "resources/list", map[string]any{}, nil)
	var rpcErr *RPCError
	if err == nil {
		t.Fatal("expected an error for an unregistered method")
	}
	if !asRPCError(err, &rpcErr) || rpcErr.Code != CodeMethodNotFound {
		t.Fatalf("got %v, want method-not-found", err)
	}
}

func TestPingIsAnsweredWithoutAHandler(t *testing.T) {
	// A client that pings and gets method-not-found treats the connection as
	// unhealthy, so this is answered by the server itself.
	client := newTestPair(t, func(*Server) {})
	if err := client.Request(context.Background(), "ping", map[string]any{}, nil); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestDifferentRequestsAreHandledConcurrently(t *testing.T) {
	// The proxy serialises calls to the same tool itself. If the server handled
	// requests one at a time, calls to DIFFERENT tools would queue behind the
	// slowest one too.
	release := make(chan struct{})
	client := newTestPair(t, func(s *Server) {
		s.SetRequestHandler("slow", func(ctx context.Context, _ *Request) (any, error) {
			<-release
			return map[string]any{}, nil
		})
		s.SetRequestHandler("fast", func(context.Context, *Request) (any, error) {
			return map[string]any{}, nil
		})
	})

	slowDone := make(chan error, 1)
	go func() { slowDone <- client.Request(context.Background(), "slow", map[string]any{}, nil) }()

	fastCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Request(fastCtx, "fast", map[string]any{}, nil); err != nil {
		t.Fatalf("the fast request queued behind the slow one: %v", err)
	}
	close(release)
	if err := <-slowDone; err != nil {
		t.Fatal(err)
	}
}

func TestLargeIDsAreEchoedExactly(t *testing.T) {
	// Decoding an id into a float64 and re-encoding it silently changes it, and
	// the peer is then holding a reply it cannot match to any request.
	clientSide, serverSide := NewPipe()
	server := NewServer(Implementation{Name: "s", Version: "1"})
	server.SetRequestHandler("noop", func(context.Context, *Request) (any, error) {
		return map[string]any{}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx, serverSide) }()

	_ = clientSide.Send(ctx, json.RawMessage(`{"jsonrpc":"2.0","id":10000000000000001,"method":"noop"}`))
	frame, err := clientSide.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(frame, []byte(`"id":10000000000000001`)) {
		t.Fatalf("id was rewritten: %s", frame)
	}
}

func TestNotificationsGetNoReply(t *testing.T) {
	clientSide, serverSide := NewPipe()
	server := NewServer(Implementation{Name: "s", Version: "1"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx, serverSide) }()

	_ = clientSide.Send(ctx, json.RawMessage(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	_ = clientSide.Send(ctx, json.RawMessage(`{"jsonrpc":"2.0","id":7,"method":"ping"}`))

	frame, err := clientSide.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// If the notification had been answered, this would be that answer.
	if !bytes.Contains(frame, []byte(`"id":7`)) {
		t.Fatalf("a notification was answered: %s", frame)
	}
}

func TestFramesLongerThanTheReadBufferSurviveIntact(t *testing.T) {
	// A frame split across two reads used to arrive as two halves, each of
	// which fails to parse, and the tool call it belonged to looked malformed
	// rather than large.
	client := newTestPair(t, func(s *Server) {
		s.SetRequestHandler("big", func(context.Context, *Request) (any, error) {
			return map[string]any{"blob": strings.Repeat("x", 300_000)}, nil
		})
	})
	var out map[string]any
	if err := client.Request(context.Background(), "big", map[string]any{}, &out); err != nil {
		t.Fatal(err)
	}
	if len(out["blob"].(string)) != 300_000 {
		t.Fatalf("blob length = %d", len(out["blob"].(string)))
	}
}

// ── Streamable HTTP server transport ───────────────────────────────────────

func TestHTTPServerTransportAnswersOnThePost(t *testing.T) {
	transport := NewHTTPServerTransport()
	server := NewServer(Implementation{Name: "s", Version: "1"})
	server.SetRequestHandler("tools/list", func(context.Context, *Request) (any, error) {
		return listToolsResult{Tools: []Tool{{Name: "t", InputSchema: map[string]any{}}}}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx, transport) }()

	httpServer := httptest.NewServer(http.HandlerFunc(transport.ServeHTTP))
	defer httpServer.Close()

	res, err := http.Post(httpServer.URL, "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var msg Message
	if err := json.NewDecoder(res.Body).Decode(&msg); err != nil {
		t.Fatal(err)
	}
	if msg.Error != nil {
		t.Fatalf("error response: %v", msg.Error)
	}
}

func TestHTTPServerTransportMintsASessionOnInitialize(t *testing.T) {
	transport := NewHTTPServerTransport()
	server := NewServer(Implementation{Name: "s", Version: "1"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx, transport) }()

	httpServer := httptest.NewServer(http.HandlerFunc(transport.ServeHTTP))
	defer httpServer.Close()

	res, err := http.Post(httpServer.URL, "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.Header.Get("Mcp-Session-Id") == "" {
		t.Fatal("no session id on the initialize response")
	}
}

func TestHTTPServerTransportAcknowledgesNotifications(t *testing.T) {
	transport := NewHTTPServerTransport()
	server := NewServer(Implementation{Name: "s", Version: "1"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx, transport) }()

	httpServer := httptest.NewServer(http.HandlerFunc(transport.ServeHTTP))
	defer httpServer.Close()

	res, err := http.Post(httpServer.URL, "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", res.StatusCode)
	}
}

func TestHTTPServerTransportRefusesGet(t *testing.T) {
	transport := NewHTTPServerTransport()
	httpServer := httptest.NewServer(http.HandlerFunc(transport.ServeHTTP))
	defer httpServer.Close()

	res, err := http.Get(httpServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", res.StatusCode)
	}
}

// ── SSE framing ────────────────────────────────────────────────────────────

func TestSSEFramingSplitsOnBlankLines(t *testing.T) {
	stream := "event: endpoint\ndata: /messages?sessionId=abc\n\n" +
		": keep-alive\n\n" +
		"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"

	type got struct {
		event string
		data  string
	}
	var events []got
	forEachSSEMessage(strings.NewReader(stream), func(event string, data []byte) {
		events = append(events, got{event, string(data)})
	})

	if len(events) != 2 {
		t.Fatalf("got %d events: %+v", len(events), events)
	}
	if events[0].event != "endpoint" || events[0].data != "/messages?sessionId=abc" {
		t.Fatalf("endpoint event = %+v", events[0])
	}
	if events[1].event != "message" || !strings.Contains(events[1].data, `"id":1`) {
		t.Fatalf("message event = %+v", events[1])
	}
}

func TestSSEFramingJoinsMultilineData(t *testing.T) {
	var data string
	forEachSSEMessage(strings.NewReader("data: line one\ndata: line two\n\n"),
		func(_ string, d []byte) { data = string(d) })
	if data != "line one\nline two" {
		t.Fatalf("data = %q", data)
	}
}

func asRPCError(err error, out **RPCError) bool {
	e, ok := err.(*RPCError)
	if ok {
		*out = e
	}
	return ok
}

// ── the child-process transport ────────────────────────────────────────────

// TestMain doubles as a tiny MCP server so the stdio client transport can be
// exercised against a REAL child process rather than a pipe. The framing is the
// same either way; what only a real child covers is the spawn, the environment
// replacement and the reaping.
func TestMain(m *testing.M) {
	if os.Getenv("MCP_TEST_CHILD") == "1" {
		runChildServer()
		return
	}
	os.Exit(m.Run())
}

func runChildServer() {
	server := NewServer(Implementation{Name: "child-server", Version: "1.0.0"})
	server.SetRequestHandler("tools/list", func(context.Context, *Request) (any, error) {
		return listToolsResult{Tools: []Tool{{Name: "child_tool", InputSchema: map[string]any{"type": "object"}}}}, nil
	})
	server.SetRequestHandler("env/dump", func(context.Context, *Request) (any, error) {
		return map[string]any{"leaked": os.Getenv("SOLONGATE_SECRET_FOR_TEST")}, nil
	})
	_ = server.Serve(context.Background(), NewStdioServerTransport())
}

func TestStdioClientTransportTalksToARealChild(t *testing.T) {
	transport, err := NewStdioClientTransport(StdioClientOptions{
		Command: os.Args[0],
		Env:     map[string]string{"MCP_TEST_CHILD": "1", "PATH": os.Getenv("PATH")},
		Stderr:  io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}

	client := NewClient(Implementation{Name: "test-client", Version: "1.0.0"})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.Connect(ctx, transport); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	tools, err := client.ListTools(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 || tools[0].Name != "child_tool" {
		t.Fatalf("tools = %+v", tools)
	}
	if client.ServerInfo().Name != "child-server" {
		t.Fatalf("serverInfo = %+v", client.ServerInfo())
	}
}

func TestTheChildGetsOnlyTheEnvironmentItWasGiven(t *testing.T) {
	// A tool server should get what it needs to find binaries and a home
	// directory, not every secret this process happens to be carrying.
	t.Setenv("SOLONGATE_SECRET_FOR_TEST", "do-not-leak")

	transport, err := NewStdioClientTransport(StdioClientOptions{
		Command: os.Args[0],
		Env:     map[string]string{"MCP_TEST_CHILD": "1", "PATH": os.Getenv("PATH")},
		Stderr:  io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}

	client := NewClient(Implementation{Name: "test-client", Version: "1.0.0"})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.Connect(ctx, transport); err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var out map[string]any
	if err := client.Request(ctx, "env/dump", map[string]any{}, &out); err != nil {
		t.Fatal(err)
	}
	if out["leaked"] != "" {
		t.Fatalf("the child inherited a variable it was not given: %v", out["leaked"])
	}
}
