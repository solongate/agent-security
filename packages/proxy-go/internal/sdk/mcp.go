package sdk

import (
	"encoding/json"

	"github.com/codeyevsky/solongate/proxy/internal/core"
)

// DeniedToolResult is what the model gets back when a call is refused.
//
// It is a normal tool RESULT with isError set, not a transport error. The
// difference matters: a transport error is something the client retries or
// reports as a fault, while an error result is something the model reads and
// works around. A denial is the second — the tool did not fail, it was not
// allowed, and the model should stop asking rather than try again.
//
// The reason handed in here has already been filtered by the caller. With
// verboseErrors off it is a fixed sentence, because the real reason names rules
// and paths and the model is the untrusted party.
//
// This belongs in internal/core next to the other MCP bridge types
// (packages/proxy/src/core/mcp-types.ts is where the original lives). It is here
// because core does not have it yet; see dependsOn.
func DeniedToolResult(reason string) core.McpCallToolResult {
	body, err := json.Marshal(map[string]string{
		"error":   "POLICY_DENIED",
		"message": reason,
		"hint":    "This tool call was blocked by SolonGate security policy. Check your policy configuration.",
	})
	if err != nil {
		body = []byte(`{"error":"POLICY_DENIED"}`)
	}
	return core.McpCallToolResult{
		Content: []core.McpToolResultContent{{Type: "text", Text: string(body)}},
		IsError: true,
	}
}
