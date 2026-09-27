package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
)

// Request is one inbound call, as a handler sees it.
type Request struct {
	Method string
	// Params are the raw request params. A handler decodes what it needs and
	// leaves the rest alone, which is how `_meta` survives to the sub-agent
	// extraction without every params type having to declare it.
	Params json.RawMessage
}

// Handler answers one request. Returning an error produces a JSON-RPC error
// response; returning a value marshals it as the result.
//
// A POLICY DENIAL IS NOT AN ERROR HERE. It is a CallToolResult with IsError
// set, returned as a normal value. Sending a denial as a JSON-RPC error would
// tell the client the call failed in transit, and clients retry those.
type Handler func(ctx context.Context, req *Request) (any, error)

// ServerError makes a handler failure carry a specific JSON-RPC code.
type ServerError struct {
	Code    int
	Message string
}

func (e *ServerError) Error() string { return e.Message }

// Server is the downstream half of the proxy: the MCP server the agent talks
// to.
type Server struct {
	info Implementation
	// Capabilities is what this server announces. The proxy declares tools,
	// resources and prompts because it forwards all three.
	Capabilities map[string]any

	handlers map[string]Handler

	// OnInitialized fires after the client's initialized notification, which is
	// the first point at which clientInfo is known to be final.
	OnInitialized func(client Implementation)

	mu              sync.RWMutex
	clientInfo      Implementation
	protocolVersion string

	transport Transport
	wg        sync.WaitGroup
}

// NewServer builds a server with the three pass-through capabilities the proxy
// needs and no handlers.
func NewServer(info Implementation) *Server {
	return &Server{
		info: info,
		Capabilities: map[string]any{
			"tools":     map[string]any{},
			"resources": map[string]any{},
			"prompts":   map[string]any{},
		},
		handlers: map[string]Handler{},
	}
}

// SetRequestHandler registers the handler for one method.
func (s *Server) SetRequestHandler(method string, h Handler) {
	s.handlers[method] = h
}

// ClientInfo is who connected, once initialize has been seen.
func (s *Server) ClientInfo() Implementation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clientInfo
}

// Serve reads frames until the transport closes.
//
// Every request is handled on its own goroutine. The proxy serialises calls to
// the SAME tool with a mutex of its own for rate-limiter accuracy; handling
// them one at a time here instead would serialise calls to DIFFERENT tools too,
// and an agent running three independent tools would wait for the slowest.
func (s *Server) Serve(ctx context.Context, t Transport) error {
	s.transport = t
	defer s.wg.Wait()

	for {
		frame, err := t.Recv(ctx)
		if err != nil {
			if errors.Is(err, ErrTransportClosed) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		msgs, _, err := decodeFrame(frame)
		if err != nil {
			_ = t.Send(ctx, newErrorResponse(nil, CodeParseError, "Parse error"))
			continue
		}
		for i := range msgs {
			msg := msgs[i]
			switch {
			case msg.IsRequest():
				s.wg.Add(1)
				go func() {
					defer s.wg.Done()
					s.handle(ctx, &msg)
				}()
			case msg.IsNotification():
				s.notified(&msg)
			}
		}
	}
}

func (s *Server) handle(ctx context.Context, msg *Message) {
	result, err := s.route(ctx, msg)
	if err != nil {
		code := CodeInternalError
		var se *ServerError
		if errors.As(err, &se) {
			code = se.Code
		}
		_ = s.transport.Send(ctx, newErrorResponse(msg.ID, code, err.Error()))
		return
	}
	frame, marshalErr := newResponse(msg.ID, result)
	if marshalErr != nil {
		_ = s.transport.Send(ctx, newErrorResponse(msg.ID, CodeInternalError,
			"The result could not be encoded: "+marshalErr.Error()))
		return
	}
	_ = s.transport.Send(ctx, frame)
}

func (s *Server) route(ctx context.Context, msg *Message) (any, error) {
	switch msg.Method {
	case "initialize":
		return s.initialize(msg.Params)
	case "ping":
		// Answered here rather than left to a handler: a client that pings and
		// gets method-not-found treats the connection as unhealthy.
		return map[string]any{}, nil
	}
	h := s.handlers[msg.Method]
	if h == nil {
		return nil, &ServerError{Code: CodeMethodNotFound, Message: "Method not found: " + msg.Method}
	}
	return h(ctx, &Request{Method: msg.Method, Params: msg.Params})
}

func (s *Server) initialize(params json.RawMessage) (any, error) {
	var p InitializeParams
	if len(params) > 0 {
		// A params block this version cannot read is not fatal. The only field
		// that matters is clientInfo, and refusing the session because of an
		// unexpected capability shape would break a client that added one.
		_ = json.Unmarshal(params, &p)
	}

	// Echo the client's revision when it is one we understand. A client that
	// asked for 2024-11-05 and is answered with a later number treats the
	// session as unusable, and the frames are identical either way.
	version := ProtocolVersion
	if knownProtocolVersions[p.ProtocolVersion] {
		version = p.ProtocolVersion
	}

	s.mu.Lock()
	s.clientInfo = p.ClientInfo
	s.protocolVersion = version
	s.mu.Unlock()

	return InitializeResult{
		ProtocolVersion: version,
		Capabilities:    s.Capabilities,
		ServerInfo:      s.info,
	}, nil
}

func (s *Server) notified(msg *Message) {
	if msg.Method != "notifications/initialized" {
		// Everything else — cancellation, progress, roots changes — is dropped.
		// Answering a notification is a protocol error, and acting on one the
		// proxy does not forward would put it out of step with the upstream.
		return
	}
	if s.OnInitialized != nil {
		s.OnInitialized(s.ClientInfo())
	}
}
