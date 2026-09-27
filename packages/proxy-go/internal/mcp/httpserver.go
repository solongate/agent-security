package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sync"
)

// HTTPServerTransport serves MCP over Streamable HTTP.
//
// It answers each POST with `application/json` rather than opening an SSE
// stream. The spec allows either, and the proxy has nothing to stream: every
// reply it produces is the answer to exactly one request, and a stream would
// add a second way for a connection to be half-open.
//
// A GET is refused. That is the server-initiated notification channel, and the
// proxy forwards no server-initiated messages — the Node proxy does not either,
// because the upstream client it holds is not wired to push anything downstream.
type HTTPServerTransport struct {
	// MaxBodyBytes caps one request body. The tool-argument ceiling is enforced
	// again in the proxy, on the decoded arguments; this one exists so a body
	// that would never parse cannot be streamed into memory first.
	MaxBodyBytes int64

	// OnRequest runs before a body is handed to the server, with the HTTP
	// request that carried it. The proxy reads agent identity headers there.
	OnRequest func(r *http.Request)

	incoming chan json.RawMessage

	mu        sync.Mutex
	pending   map[string]chan json.RawMessage
	sessionID string
	closed    bool
	closeCh   chan struct{}
}

// NewHTTPServerTransport builds the transport. The session id is minted on the
// first initialize, the way the Node SDK's sessionIdGenerator is invoked.
func NewHTTPServerTransport() *HTTPServerTransport {
	return &HTTPServerTransport{
		MaxBodyBytes: 8 << 20,
		incoming:     make(chan json.RawMessage, 64),
		pending:      map[string]chan json.RawMessage{},
		closeCh:      make(chan struct{}),
	}
}

// SessionID is the id handed to the client, empty until initialize.
func (t *HTTPServerTransport) SessionID() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sessionID
}

func (t *HTTPServerTransport) Recv(ctx context.Context) (json.RawMessage, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.closeCh:
		return nil, ErrTransportClosed
	case msg := <-t.incoming:
		return msg, nil
	}
}

// Send routes a reply back to the HTTP request that is still holding open for
// it. A message with no waiting request is dropped: without a GET stream there
// is nowhere for it to go, and buffering it would mean delivering it to
// whichever unrelated request happened to arrive next.
func (t *HTTPServerTransport) Send(_ context.Context, frame json.RawMessage) error {
	var msg Message
	if err := json.Unmarshal(frame, &msg); err != nil {
		return err
	}
	if !msg.HasID() {
		return nil
	}
	t.mu.Lock()
	reply := t.pending[msg.idKey()]
	delete(t.pending, msg.idKey())
	t.mu.Unlock()
	if reply == nil {
		return nil
	}
	reply <- frame
	return nil
}

func (t *HTTPServerTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	close(t.closeCh)
	t.mu.Unlock()
	return nil
}

// ServeHTTP is the /mcp handler.
func (t *HTTPServerTransport) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		t.post(w, r)
	case http.MethodDelete:
		// Ending the session closes the transport, which ends Serve, which ends
		// the process's downstream half. That is what the client asked for.
		_ = t.Close()
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "This endpoint does not open a server-to-client stream. POST JSON-RPC messages instead.",
			http.StatusMethodNotAllowed)
	default:
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (t *HTTPServerTransport) post(w http.ResponseWriter, r *http.Request) {
	if t.OnRequest != nil {
		t.OnRequest(r)
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, t.MaxBodyBytes))
	if err != nil {
		t.writeError(w, http.StatusBadRequest, nil, CodeParseError, "Could not read the request body")
		return
	}

	msgs, batched, err := decodeFrame(body)
	if err != nil {
		t.writeError(w, http.StatusBadRequest, nil, CodeParseError, "Parse error")
		return
	}

	// A session id is minted on initialize and returned on that response only,
	// which is where a client looks for it.
	hasInitialize := false
	for i := range msgs {
		if msgs[i].Method == "initialize" {
			hasInitialize = true
		}
	}
	if hasInitialize {
		t.mu.Lock()
		if t.sessionID == "" {
			t.sessionID = randomSessionID()
		}
		sid := t.sessionID
		t.mu.Unlock()
		w.Header().Set("Mcp-Session-Id", sid)
	}

	// Reply slots are registered BEFORE anything is handed to the server. The
	// server answers on its own goroutines and a fast handler can reply before
	// this function reaches the wait below.
	replies := make([]chan json.RawMessage, 0, len(msgs))
	keys := make([]string, 0, len(msgs))
	t.mu.Lock()
	closed := t.closed
	for i := range msgs {
		if !msgs[i].IsRequest() {
			continue
		}
		ch := make(chan json.RawMessage, 1)
		t.pending[msgs[i].idKey()] = ch
		replies = append(replies, ch)
		keys = append(keys, msgs[i].idKey())
	}
	t.mu.Unlock()

	if closed {
		t.releaseKeys(keys)
		http.Error(w, "Session closed", http.StatusGone)
		return
	}

	for i := range msgs {
		select {
		case t.incoming <- json.RawMessage(mustMarshal(msgs[i])):
		case <-t.closeCh:
			t.releaseKeys(keys)
			http.Error(w, "Session closed", http.StatusGone)
			return
		case <-r.Context().Done():
			t.releaseKeys(keys)
			return
		}
	}

	// Nothing to answer: notifications and responses get an acknowledgement
	// with no body, as the spec requires.
	if len(replies) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	collected := make([]json.RawMessage, 0, len(replies))
	for _, ch := range replies {
		select {
		case frame := <-ch:
			collected = append(collected, frame)
		case <-r.Context().Done():
			t.releaseKeys(keys)
			return
		case <-t.closeCh:
			t.releaseKeys(keys)
			http.Error(w, "Session closed", http.StatusGone)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if batched {
		out, _ := json.Marshal(collected)
		_, _ = w.Write(out)
		return
	}
	_, _ = w.Write(collected[0])
}

// releaseKeys drops reply slots for a request that went away, so a client that
// disconnects mid-call does not leave the map growing for the life of the proxy.
func (t *HTTPServerTransport) releaseKeys(keys []string) {
	if len(keys) == 0 {
		return
	}
	t.mu.Lock()
	for _, k := range keys {
		delete(t.pending, k)
	}
	t.mu.Unlock()
}

func (t *HTTPServerTransport) writeError(w http.ResponseWriter, status int, id json.RawMessage, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(newErrorResponse(id, code, message))
}

func mustMarshal(m Message) []byte {
	b, err := json.Marshal(m)
	if err != nil {
		return []byte("{}")
	}
	return b
}

// randomSessionID is 128 bits of randomness, hex encoded.
//
// It is not a credential — the policy is enforced whatever the session id says
// — but a predictable one would let anything else on the machine join a session
// and read the replies meant for the agent.
func randomSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not recoverable and must not silently produce a
		// guessable id, so the session simply has none and the client is told so
		// by its absence.
		return ""
	}
	return hex.EncodeToString(b[:])
}
