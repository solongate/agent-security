// Package mcp is the Model Context Protocol wire layer: JSON-RPC 2.0 carried
// over stdio, over Streamable HTTP, and over the legacy HTTP+SSE transport.
//
// It exists because the proxy has to be BOTH ends of the protocol at once — a
// server to the agent, and a client to the tool server it is guarding. The npm
// package gets both from @modelcontextprotocol/sdk; there is no equivalent
// dependency in this module, so what is here is the subset packages/proxy/src/proxy.ts
// actually uses and nothing else. Anything the proxy only passes through is
// kept as raw bytes rather than modelled, so a field this version has never
// heard of still reaches the other side intact.
package mcp

import (
	"encoding/json"
	"strconv"
)

// The JSON-RPC error codes MCP inherits. Only these five are ever produced
// here; a policy denial is NOT one of them, because a denial is a tool RESULT
// with isError set. The distinction is load-bearing: a transport error is
// something a client retries or reports as a fault, while an error result is
// something the model reads and works around.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// Message is one JSON-RPC frame in either direction.
//
// ID stays as raw bytes instead of being decoded. The spec allows a string or a
// number, and a response has to echo back the id it was given EXACTLY — decode
// a number into a float64 and re-encode it and `10000000000000001` comes back
// as something else, leaving the peer with a reply it cannot match to its
// request.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is the error member of a response.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	return "MCP error " + strconv.Itoa(e.Code) + ": " + e.Message
}

// HasID separates a request from a notification. A literal `null` id counts as
// absent: it is what a peer sends when it could not parse far enough to find
// the real one, so treating it as an id would have us open a reply slot that
// nothing will ever answer.
func (m *Message) HasID() bool { return len(m.ID) > 0 && string(m.ID) != "null" }

func (m *Message) IsRequest() bool      { return m.Method != "" && m.HasID() }
func (m *Message) IsNotification() bool { return m.Method != "" && !m.HasID() }
func (m *Message) IsResponse() bool     { return m.Method == "" && m.HasID() }

// idKey is the map key for correlating a reply with its request. The raw bytes
// are used verbatim so `1` and `"1"` stay different keys — they are different
// ids to the peer that sent them.
func (m *Message) idKey() string { return string(m.ID) }

func newResponse(id json.RawMessage, result any) (json.RawMessage, error) {
	body, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	// A result of `null` would be dropped by omitempty and the peer would see a
	// response with neither result nor error, which is not a valid frame.
	if len(body) == 0 || string(body) == "null" {
		body = json.RawMessage("{}")
	}
	return json.Marshal(Message{JSONRPC: "2.0", ID: id, Result: body})
}

func newErrorResponse(id json.RawMessage, code int, message string) json.RawMessage {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	// Marshalling this cannot fail: every field is a string, an int or bytes
	// that were valid JSON on the way in.
	body, _ := json.Marshal(Message{
		JSONRPC: "2.0", ID: id,
		Error: &RPCError{Code: code, Message: message},
	})
	return body
}

// decodeFrame accepts both a single message and a JSON-RPC batch, because a
// client is allowed to send either and a proxy that only reads the first shape
// looks like a broken server rather than an unimplemented one.
func decodeFrame(raw []byte) ([]Message, bool, error) {
	trimmed := trimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var batch []Message
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			return nil, true, err
		}
		return batch, true, nil
	}
	var one Message
	if err := json.Unmarshal(trimmed, &one); err != nil {
		return nil, false, err
	}
	return []Message{one}, false, nil
}

func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\t' || b[j-1] == '\n' || b[j-1] == '\r') {
		j--
	}
	return b[i:j]
}
