package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The two HTTP client transports.
//
// `http` is Streamable HTTP: one endpoint, every message POSTed to it, and the
// reply either as a JSON body or as an SSE stream on the same response.
// `sse` is the older HTTP+SSE transport: a long-lived GET that first announces
// where to POST, with every reply arriving back on the GET stream.
//
// Both are here because packages/proxy/src/proxy.ts offers both, and which one
// a hosted MCP server speaks is not something the user gets to choose.

// httpTransportBase is the queue both share. A reply arrives on whichever
// goroutine happened to receive it, and Recv above this line is a plain stream,
// so the queue is what reconciles the two.
type httpTransportBase struct {
	incoming  chan json.RawMessage
	closeOnce sync.Once
	closed    chan struct{}
}

func newHTTPTransportBase() httpTransportBase {
	return httpTransportBase{
		// Buffered so a burst of notifications from the server cannot block the
		// goroutine reading the socket, which would stall the reply the caller
		// is actually waiting for.
		incoming: make(chan json.RawMessage, 64),
		closed:   make(chan struct{}),
	}
}

func (b *httpTransportBase) Recv(ctx context.Context) (json.RawMessage, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-b.closed:
		return nil, ErrTransportClosed
	case msg := <-b.incoming:
		return msg, nil
	}
}

func (b *httpTransportBase) offer(msg json.RawMessage) {
	select {
	case b.incoming <- msg:
	case <-b.closed:
	}
}

func (b *httpTransportBase) shutdown() {
	b.closeOnce.Do(func() { close(b.closed) })
}

// HTTPClientOptions configures either HTTP transport.
type HTTPClientOptions struct {
	URL     string
	Client  *http.Client
	Headers map[string]string
}

func (o HTTPClientOptions) client() *http.Client {
	if o.Client != nil {
		return o.Client
	}
	// No client timeout: an SSE stream is meant to stay open, and a timeout on
	// the client applies to the whole body read rather than to establishing the
	// connection. Cancellation is done with the request context instead.
	return &http.Client{}
}

// ── Streamable HTTP ────────────────────────────────────────────────────────

type streamableHTTPTransport struct {
	httpTransportBase
	url  string
	hc   *http.Client
	hdrs map[string]string

	mu         sync.Mutex
	sessionID  string
	negotiated string
}

// NewStreamableHTTPClientTransport connects to a single MCP endpoint.
func NewStreamableHTTPClientTransport(opts HTTPClientOptions) (Transport, error) {
	if _, err := url.Parse(opts.URL); err != nil {
		return nil, err
	}
	return &streamableHTTPTransport{
		httpTransportBase: newHTTPTransportBase(),
		url:               opts.URL,
		hc:                opts.client(),
		hdrs:              opts.Headers,
	}, nil
}

func (t *streamableHTTPTransport) Send(ctx context.Context, frame json.RawMessage) error {
	select {
	case <-t.closed:
		return ErrTransportClosed
	default:
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(frame))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	t.mu.Lock()
	if t.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", t.sessionID)
	}
	if t.negotiated != "" {
		req.Header.Set("MCP-Protocol-Version", t.negotiated)
	}
	t.mu.Unlock()
	for k, v := range t.hdrs {
		req.Header.Set(k, v)
	}

	res, err := t.hc.Do(req)
	if err != nil {
		return err
	}

	if sid := res.Header.Get("Mcp-Session-Id"); sid != "" {
		t.mu.Lock()
		t.sessionID = sid
		t.mu.Unlock()
	}

	if res.StatusCode == http.StatusAccepted || res.StatusCode == http.StatusNoContent {
		res.Body.Close()
		return nil
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		res.Body.Close()
		return errors.New("mcp: upstream returned " + res.Status + ": " + strings.TrimSpace(string(body)))
	}

	ctype := res.Header.Get("Content-Type")
	if strings.HasPrefix(ctype, "text/event-stream") {
		// The reply may be several frames and the stream stays open until the
		// server has sent them all, so it is drained on its own goroutine and
		// the caller is released as soon as the POST is accepted.
		go func() {
			defer res.Body.Close()
			t.drainSSE(res.Body)
		}()
		return nil
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	t.offerFrame(body)
	return nil
}

// offerFrame splits a batch into its members before queueing. The client above
// correlates one reply per id, so handing it a whole array would leave every
// request in the batch waiting.
func (t *streamableHTTPTransport) offerFrame(body []byte) {
	body = trimSpace(body)
	if len(body) == 0 {
		return
	}
	if body[0] == '[' {
		var batch []json.RawMessage
		if json.Unmarshal(body, &batch) == nil {
			for _, m := range batch {
				t.rememberVersion(m)
				t.offer(m)
			}
			return
		}
	}
	t.rememberVersion(body)
	t.offer(json.RawMessage(body))
}

// rememberVersion picks the negotiated revision out of the initialize reply so
// later requests can carry the MCP-Protocol-Version header the spec asks for.
func (t *streamableHTTPTransport) rememberVersion(frame json.RawMessage) {
	t.mu.Lock()
	already := t.negotiated != ""
	t.mu.Unlock()
	if already {
		return
	}
	var msg Message
	if json.Unmarshal(frame, &msg) != nil || len(msg.Result) == 0 {
		return
	}
	var r InitializeResult
	if json.Unmarshal(msg.Result, &r) != nil || r.ProtocolVersion == "" {
		return
	}
	t.mu.Lock()
	t.negotiated = r.ProtocolVersion
	t.mu.Unlock()
}

func (t *streamableHTTPTransport) drainSSE(body io.Reader) {
	forEachSSEMessage(body, func(_ string, data []byte) {
		t.offerFrame(data)
	})
}

func (t *streamableHTTPTransport) Close() error {
	t.shutdown()
	return nil
}

// ── legacy HTTP+SSE ────────────────────────────────────────────────────────

type sseTransport struct {
	httpTransportBase
	baseURL *url.URL
	hc      *http.Client
	hdrs    map[string]string

	cancel context.CancelFunc

	endpointOnce sync.Once
	endpointCh   chan string
	endpoint     string
	endpointMu   sync.RWMutex
}

// NewSSEClientTransport opens the long-lived GET and waits for the server to
// say where messages should be POSTed.
func NewSSEClientTransport(ctx context.Context, opts HTTPClientOptions) (Transport, error) {
	base, err := url.Parse(opts.URL)
	if err != nil {
		return nil, err
	}

	streamCtx, cancel := context.WithCancel(context.Background())
	t := &sseTransport{
		httpTransportBase: newHTTPTransportBase(),
		baseURL:           base,
		hc:                opts.client(),
		hdrs:              opts.Headers,
		cancel:            cancel,
		endpointCh:        make(chan string, 1),
	}

	req, err := http.NewRequestWithContext(streamCtx, http.MethodGet, opts.URL, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-store")
	for k, v := range opts.Headers {
		req.Header.Set(k, v)
	}

	res, err := t.hc.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		res.Body.Close()
		cancel()
		return nil, errors.New("mcp: SSE endpoint returned " + res.Status + ": " + strings.TrimSpace(string(body)))
	}

	go func() {
		defer res.Body.Close()
		defer t.shutdown()
		forEachSSEMessage(res.Body, func(event string, data []byte) {
			switch event {
			case "endpoint":
				t.setEndpoint(string(bytes.TrimSpace(data)))
			case "", "message":
				t.offer(json.RawMessage(bytes.TrimSpace(data)))
			}
		})
	}()

	// The endpoint announcement is the handshake: nothing can be sent before it
	// arrives, so a server that never sends one is a connection failure rather
	// than a proxy that silently accepts calls it cannot forward.
	select {
	case <-t.endpointCh:
		return t, nil
	case <-t.closed:
		cancel()
		return nil, errors.New("mcp: the SSE stream closed before announcing an endpoint")
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	case <-time.After(30 * time.Second):
		cancel()
		return nil, errors.New("mcp: the SSE server never announced a message endpoint")
	}
}

func (t *sseTransport) setEndpoint(raw string) {
	resolved := raw
	if u, err := url.Parse(raw); err == nil {
		resolved = t.baseURL.ResolveReference(u).String()
	}
	t.endpointMu.Lock()
	t.endpoint = resolved
	t.endpointMu.Unlock()
	t.endpointOnce.Do(func() { close(t.endpointCh) })
}

func (t *sseTransport) Send(ctx context.Context, frame json.RawMessage) error {
	t.endpointMu.RLock()
	endpoint := t.endpoint
	t.endpointMu.RUnlock()
	if endpoint == "" {
		return errors.New("mcp: no message endpoint yet")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(frame))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range t.hdrs {
		req.Header.Set(k, v)
	}
	res, err := t.hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return errors.New("mcp: upstream returned " + res.Status)
	}
	return nil
}

func (t *sseTransport) Close() error {
	t.cancel()
	t.shutdown()
	return nil
}

// ── SSE framing ────────────────────────────────────────────────────────────

// forEachSSEMessage reads text/event-stream and calls fn once per event.
//
// Only `event` and `data` are read. `id` and `retry` are for resumable streams,
// which neither of these transports attempts: a resumed stream would replay
// messages the proxy has already acted on, and a tool call that runs twice is
// worse than a connection that has to be re-established.
func forEachSSEMessage(body io.Reader, fn func(event string, data []byte)) {
	reader := bufio.NewReaderSize(body, 64*1024)
	var event string
	var data []byte

	flush := func() {
		if len(data) == 0 {
			event = ""
			return
		}
		fn(event, data)
		event = ""
		data = nil
	}

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			trimmed := bytes.TrimRight(line, "\r\n")
			switch {
			case len(trimmed) == 0:
				flush()
			case trimmed[0] == ':':
				// A comment, used as a keep-alive.
			default:
				field, value, found := bytes.Cut(trimmed, []byte(":"))
				if !found {
					field, value = trimmed, nil
				}
				value = bytes.TrimPrefix(value, []byte(" "))
				switch string(field) {
				case "event":
					event = string(value)
				case "data":
					if len(data) > 0 {
						data = append(data, '\n')
					}
					data = append(data, value...)
				}
			}
		}
		if err != nil {
			flush()
			return
		}
	}
}
