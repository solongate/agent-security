package core

import (
	"fmt"
	"strings"
	"time"
)

// Base is what every SolonGate security error carries: a machine-readable code
// so callers can branch without matching on prose, and details for the audit
// trail.
//
// There is deliberately no stack trace. These errors are serialised into audit
// entries and API responses, and a stack trace there is an information leak
// about the machine that produced it.
type Base struct {
	Message   string         `json:"message"`
	Code      string         `json:"code"`
	Timestamp string         `json:"timestamp"`
	Details   map[string]any `json:"details"`
	Name      string         `json:"name"`
}

func newBase(message, code string, details map[string]any) Base {
	if details == nil {
		details = map[string]any{}
	}
	return Base{
		Message:   message,
		Code:      code,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Details:   details,
		Name:      "SolonGateError",
	}
}

func (b Base) Error() string { return b.Message }

// NewError builds the generic case, for a failure that has no more specific
// type yet.
func NewError(message, code string, details map[string]any) *Base {
	b := newBase(message, code, details)
	return &b
}

// PolicyDeniedError — a tool call refused by policy.
type PolicyDeniedError struct{ Base }

func NewPolicyDeniedError(toolName, reason string, details map[string]any) *PolicyDeniedError {
	d := map[string]any{"toolName": toolName, "reason": reason}
	for k, v := range details {
		d[k] = v
	}
	b := newBase(fmt.Sprintf("Policy denied execution of tool %q: %s", toolName, reason), "POLICY_DENIED", d)
	b.Name = "PolicyDeniedError"
	return &PolicyDeniedError{b}
}

// TrustEscalationError — an illegal trust transition was attempted.
type TrustEscalationError struct{ Base }

// SchemaValidationError — tool input did not match the tool's schema.
type SchemaValidationError struct{ Base }

func NewSchemaValidationError(toolName string, validationErrors []string) *SchemaValidationError {
	b := newBase(
		fmt.Sprintf("Schema validation failed for tool %q: %s", toolName, strings.Join(validationErrors, "; ")),
		"SCHEMA_VALIDATION_FAILED",
		map[string]any{"toolName": toolName, "validationErrors": validationErrors},
	)
	b.Name = "SchemaValidationError"
	return &SchemaValidationError{b}
}

// RateLimitError — a tool exceeded its allowance.
type RateLimitError struct{ Base }

func NewRateLimitError(toolName string, limitPerMinute int) *RateLimitError {
	b := newBase(
		fmt.Sprintf("Rate limit exceeded for tool %q: max %d/min", toolName, limitPerMinute),
		"RATE_LIMIT_EXCEEDED",
		map[string]any{"toolName": toolName, "limitPerMinute": limitPerMinute},
	)
	b.Name = "RateLimitError"
	return &RateLimitError{b}
}

// ToolNotFoundError — the registry has no such tool on that server.
type ToolNotFoundError struct{ Base }

func NewToolNotFoundError(toolName, serverName string) *ToolNotFoundError {
	b := newBase(
		fmt.Sprintf("Tool %q not found on server %q", toolName, serverName),
		"TOOL_NOT_FOUND",
		map[string]any{"toolName": toolName, "serverName": serverName},
	)
	b.Name = "ToolNotFoundError"
	return &ToolNotFoundError{b}
}

// UnsafeConfigurationError — a setting that would weaken the model.
type UnsafeConfigurationError struct{ Base }

func NewUnsafeConfigurationError(message, field string) *UnsafeConfigurationError {
	b := newBase("Unsafe configuration detected: "+message, "UNSAFE_CONFIGURATION", map[string]any{"field": field})
	b.Name = "UnsafeConfigurationError"
	return &UnsafeConfigurationError{b}
}

// InputGuardError — the input guard found something in the arguments.
type InputGuardError struct{ Base }

func NewInputGuardError(toolName string, threats []DetectedThreat) *InputGuardError {
	descriptions := make([]string, 0, len(threats))
	generic := make([]any, 0, len(threats))
	for _, t := range threats {
		descriptions = append(descriptions, t.Description)
		generic = append(generic, map[string]any{
			"type": string(t.Type), "field": t.Field, "description": t.Description,
		})
	}
	b := newBase(
		fmt.Sprintf("Input guard blocked tool %q: %s", toolName, strings.Join(descriptions, "; ")),
		"INPUT_GUARD_BLOCKED",
		map[string]any{"toolName": toolName, "threatCount": len(threats), "threats": generic},
	)
	b.Name = "InputGuardError"
	return &InputGuardError{b}
}

// NetworkError — an API call or cloud sync failed.
type NetworkError struct{ Base }

func NewNetworkError(operation string, statusCode int, details map[string]any) *NetworkError {
	msg := "Network error during " + operation
	if statusCode != 0 {
		msg = fmt.Sprintf("%s (HTTP %d)", msg, statusCode)
	}
	d := map[string]any{"operation": operation, "statusCode": statusCode}
	for k, v := range details {
		d[k] = v
	}
	b := newBase(msg, "NETWORK_ERROR", d)
	b.Name = "NetworkError"
	return &NetworkError{b}
}
