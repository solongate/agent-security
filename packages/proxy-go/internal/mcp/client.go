package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"
)

// DefaultRequestTimeout matches the Node SDK's DEFAULT_REQUEST_TIMEOUT_MSEC.
//
// It applies to tools/call as well, which means a tool that runs for more than
// a minute fails here exactly as it fails under the npm proxy today. That is
// deliberate: raising it would make the Go build succeed where the Node build
// gives up, and the two have to agree about what a working tool is.
const DefaultRequestTimeout = 60 * time.Second

// Client is the proxy's connection to the upstream server it is guarding.
type Client struct {
	info      Implementation
	transport Transport

	mu      sync.Mutex
	nextID  int64
	pending map[string]chan *Message
	closed  bool
	closeCh chan struct{}

	// serverInfo and protocolVersion are what the upstream answered with.
	serverInfo      Implementation
	protocolVersion string
	capabilities    map[string]any
}

// NewClient builds a client. It does not connect.
func NewClient(info Implementation) *Client {
	return &Client{
		info:    info,
		pending: map[string]chan *Message{},
		closeCh: make(chan struct{}),
	}
}

// Connect performs the initialize handshake and starts the read loop.
func (c *Client) Connect(ctx context.Context, t Transport) error {
	c.transport = t
	go c.readLoop()

	params := InitializeParams{
		ProtocolVersion: ProtocolVersion,
		Capabilities:    map[string]any{},
		ClientInfo:      c.info,
	}
	var result InitializeResult
	if err := c.Request(ctx, "initialize", params, &result); err != nil {
		return err
	}
	c.serverInfo = result.ServerInfo
	c.protocolVersion = result.ProtocolVersion
	c.capabilities = result.Capabilities

	// Whatever the server answered with is accepted, including a revision this
	// build has never heard of. The Node SDK refuses an unknown one; refusing
	// here would mean a proxy that is pickier than the client it stands in for,
	// and the frames are identical across every revision in the wild.
	return c.Notify(ctx, "notifications/initialized", map[string]any{})
}

// ServerInfo is who answered, for logging.
func (c *Client) ServerInfo() Implementation { return c.serverInfo }

// ProtocolVersion is the revision the upstream agreed to.
func (c *Client) ProtocolVersion() string { return c.protocolVersion }

// Capabilities is what the upstream said it supports.
func (c *Client) Capabilities() map[string]any { return c.capabilities }

// Request sends one request and waits for its reply.
func (c *Client) Request(ctx context.Context, method string, params any, out any) error {
	if c.transport == nil {
		return errors.New("mcp: client is not connected")
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrTransportClosed
	}
	c.nextID++
	id := json.RawMessage(strconv.FormatInt(c.nextID, 10))
	reply := make(chan *Message, 1)
	c.pending[string(id)] = reply
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.pending, string(id))
		c.mu.Unlock()
	}()

	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		rawParams = b
	}
	frame, err := json.Marshal(Message{JSONRPC: "2.0", ID: id, Method: method, Params: rawParams})
	if err != nil {
		return err
	}
	if err := c.transport.Send(ctx, frame); err != nil {
		return err
	}

	timeout := time.NewTimer(DefaultRequestTimeout)
	defer timeout.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timeout.C:
		return errors.New("mcp: request timed out: " + method)
	case <-c.closeCh:
		return ErrTransportClosed
	case msg := <-reply:
		if msg.Error != nil {
			return msg.Error
		}
		if out == nil {
			return nil
		}
		if len(msg.Result) == 0 {
			return nil
		}
		return json.Unmarshal(msg.Result, out)
	}
}

// Notify sends a notification: no id, no reply.
func (c *Client) Notify(ctx context.Context, method string, params any) error {
	if c.transport == nil {
		return errors.New("mcp: client is not connected")
	}
	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		rawParams = b
	}
	frame, err := json.Marshal(Message{JSONRPC: "2.0", Method: method, Params: rawParams})
	if err != nil {
		return err
	}
	return c.transport.Send(ctx, frame)
}

// readLoop dispatches every frame the upstream sends.
func (c *Client) readLoop() {
	defer c.failPending()
	for {
		frame, err := c.transport.Recv(context.Background())
		if err != nil {
			return
		}
		msgs, _, err := decodeFrame(frame)
		if err != nil {
			// An unparseable frame from the upstream is dropped rather than
			// answered. There is no id to answer, and a proxy that dies on one
			// bad line takes a whole agent session with it.
			continue
		}
		for i := range msgs {
			c.dispatch(&msgs[i])
		}
	}
}

func (c *Client) dispatch(msg *Message) {
	if msg.IsResponse() {
		c.mu.Lock()
		reply := c.pending[msg.idKey()]
		c.mu.Unlock()
		if reply != nil {
			// Buffered, so a caller that has already given up on its deadline
			// cannot wedge the read loop for every other in-flight request.
			select {
			case reply <- msg:
			default:
			}
		}
		return
	}
	if msg.IsRequest() {
		// The upstream asking US for something — sampling, roots, elicitation.
		// None of it is supported: the proxy declares no client capabilities, so
		// a server that asks anyway gets a clean refusal instead of silence it
		// would wait out.
		frame := newErrorResponse(msg.ID, CodeMethodNotFound,
			"Method not found: "+msg.Method+" (the SolonGate proxy declares no client capabilities)")
		_ = c.transport.Send(context.Background(), frame)
	}
	// Notifications are dropped. tools/list_changed is the common one, and
	// acting on it would mean re-registering the tool list mid-session, which
	// the Node proxy does not do either.
}

func (c *Client) failPending() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	close(c.closeCh)
	c.mu.Unlock()
}

// Close shuts the connection down and unblocks every waiting request.
func (c *Client) Close() error {
	c.failPending()
	if c.transport == nil {
		return nil
	}
	return c.transport.Close()
}

// ── the calls the proxy makes ──────────────────────────────────────────────

// ListTools is tools/list.
func (c *Client) ListTools(ctx context.Context) ([]Tool, error) {
	var out listToolsResult
	if err := c.Request(ctx, "tools/list", map[string]any{}, &out); err != nil {
		return nil, err
	}
	return out.Tools, nil
}

// CallTool is tools/call. The result comes back as raw bytes so a field this
// version does not model still reaches the caller.
func (c *Client) CallTool(ctx context.Context, params CallToolParams) (json.RawMessage, error) {
	var out json.RawMessage
	// arguments is sent even when empty: a server that requires the member and
	// gets none reports invalid params, and "no arguments" is a legitimate call.
	if params.Arguments == nil {
		params.Arguments = map[string]any{}
	}
	if err := c.Request(ctx, "tools/call", params, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Raw is any pass-through method: the result is returned exactly as it arrived.
func (c *Client) Raw(ctx context.Context, method string, params any) (json.RawMessage, error) {
	var out json.RawMessage
	if err := c.Request(ctx, method, params, &out); err != nil {
		return nil, err
	}
	return out, nil
}
