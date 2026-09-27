package mcp

import "encoding/json"

// ProtocolVersion is what this implementation announces.
//
// As a SERVER it is only a fallback: the version the client asked for is echoed
// back when it is one this code understands, because a client that negotiated
// down and then receives a higher number treats the session as unusable. As a
// CLIENT it is what gets offered, and whatever the upstream answers with is
// accepted — a proxy that refused an older server would be stricter than the
// thing it is standing in front of.
const ProtocolVersion = "2025-06-18"

// knownProtocolVersions are the revisions this wire layer is compatible with.
// The frames it exchanges are identical across all of them; the differences are
// in features (elicitation, structured output) that the proxy passes through
// untouched.
var knownProtocolVersions = map[string]bool{
	"2024-11-05": true,
	"2025-03-26": true,
	"2025-06-18": true,
}

// Implementation names one side of the connection.
type Implementation struct {
	Name    string `json:"name"`
	Title   string `json:"title,omitempty"`
	Version string `json:"version"`
}

// InitializeParams is what a client sends to open a session.
type InitializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ClientInfo      Implementation `json:"clientInfo"`
}

// InitializeResult is the server's answer.
type InitializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ServerInfo      Implementation `json:"serverInfo"`
	Instructions    string         `json:"instructions,omitempty"`
}

// Tool is one entry of tools/list.
//
// It carries the three fields packages/proxy/src/proxy.ts keeps and no more.
// That IS lossy — a tool's annotations, title and outputSchema do not survive
// the hop — and it is preserved rather than fixed, because the npm proxy has
// always presented tools this way and a Go build that presented them
// differently would make the two disagree about what a server offers. See the
// caveat.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema"`
}

type listToolsResult struct {
	Tools []Tool `json:"tools"`
}

// CallToolParams is a tools/call request.
type CallToolParams struct {
	Name      string          `json:"name"`
	Arguments map[string]any  `json:"arguments,omitempty"`
	Meta      json.RawMessage `json:"_meta,omitempty"`
}

// ContentBlock is one piece of a tool result. Text is the only field the proxy
// reads; the rest are here so a block survives the round trip.
type ContentBlock struct {
	Type     string          `json:"type"`
	Text     string          `json:"text,omitempty"`
	Data     string          `json:"data,omitempty"`
	MimeType string          `json:"mimeType,omitempty"`
	Resource json.RawMessage `json:"resource,omitempty"`
	URI      string          `json:"uri,omitempty"`
	Name     string          `json:"name,omitempty"`
	Meta     json.RawMessage `json:"_meta,omitempty"`
}

// CallToolResult is what a tool returns. IsError is NOT omitempty: `false` has
// to be on the wire, because a client that sees no isError field and one that
// sees `isError: false` should reach the same conclusion, and some do not.
type CallToolResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError"`
}

// TextResult is the shorthand for the one shape the proxy generates itself: a
// refusal, in words, addressed to the model.
func TextResult(text string, isError bool) CallToolResult {
	return CallToolResult{
		Content: []ContentBlock{{Type: "text", Text: text}},
		IsError: isError,
	}
}

// ReadResourceParams is a resources/read request.
type ReadResourceParams struct {
	URI string `json:"uri"`
}

// GetPromptParams is a prompts/get request.
type GetPromptParams struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

// Empty results for the pass-through list methods. They exist so a proxy in
// front of a tools-only server answers resources/list and prompts/list with an
// empty list instead of an error — the Node proxy does the same, and a client
// that gets an error for either stops asking for both.
type emptyResources struct {
	Resources []json.RawMessage `json:"resources"`
}

type emptyResourceTemplates struct {
	ResourceTemplates []json.RawMessage `json:"resourceTemplates"`
}

type emptyPrompts struct {
	Prompts []json.RawMessage `json:"prompts"`
}
