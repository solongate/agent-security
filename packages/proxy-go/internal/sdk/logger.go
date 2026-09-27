package sdk

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/codeyevsky/solongate/proxy/internal/core"
)

type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
)

var logLevelOrder = map[LogLevel]int{LevelDebug: 0, LevelInfo: 1, LevelWarn: 2, LevelError: 3}

// SecurityLogger writes one JSON object per decision.
//
// Everything goes to STDERR, including info and debug. The npm implementation
// sends those to stdout via console.info, which is a latent protocol bug: an
// MCP server speaks JSON-RPC over stdout, so a log line there is a malformed
// message to whatever is on the other end. There is no case where a gateway
// should be writing its own diagnostics into the channel it is proxying.
type SecurityLogger struct {
	minLevel LogLevel
	enabled  bool
}

func NewSecurityLogger(level LogLevel, enabled bool) *SecurityLogger {
	if level == "" {
		level = LevelInfo
	}
	return &SecurityLogger{minLevel: level, enabled: enabled}
}

// LogDecision records one pipeline outcome. Denials and errors are warnings;
// an allow is information.
func (l *SecurityLogger) LogDecision(result core.ExecutionResult) {
	if l == nil || !l.enabled {
		return
	}

	entry := map[string]any{
		"type":       "security_decision",
		"status":     string(result.Status),
		"toolName":   result.Request.ToolName,
		"permission": string(result.Request.RequiredPermission),
		"trustLevel": string(result.Request.Context.TrustLevel),
		"requestId":  result.Request.Context.RequestID,
		"timestamp":  result.Timestamp,
	}

	level := LevelInfo
	switch result.Status {
	case core.StatusAllowed:
		entry["durationMs"] = result.DurationMs
	case core.StatusDenied:
		level = LevelWarn
		if result.Decision != nil {
			entry["reason"] = result.Decision.Reason
		}
	case core.StatusError:
		level = LevelWarn
		// The CODE, not the message: the message can carry a path or an
		// argument value, and this line is written to a log somebody else may
		// read.
		entry["error"] = errorCode(result.Err)
	}

	l.log(level, entry)
}

func (l *SecurityLogger) log(level LogLevel, data map[string]any) {
	if logLevelOrder[level] < logLevelOrder[l.minLevel] {
		return
	}
	out := map[string]any{"level": string(level)}
	for k, v := range data {
		out[k] = v
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return
	}
	fmt.Fprintf(os.Stderr, "[SolonGate] %s\n", encoded)
}

// Warn is the channel the gateway uses for configuration problems, which are
// not decisions and have no request behind them.
func (l *SecurityLogger) Warn(message string) {
	fmt.Fprintf(os.Stderr, "[SolonGate] WARNING: %s\n", message)
}

// errorCode pulls the machine-readable code out of a core error.
//
// The core error types embed core.Base by value rather than exposing a getter,
// so this switch is the only way to reach the field without reflection. An
// unrecognised error logs as "ERROR" rather than as its message, because the
// point of logging the code is to avoid logging the message.
func errorCode(err error) string {
	switch e := err.(type) {
	case nil:
		return ""
	case *core.Base:
		return e.Code
	case *core.PolicyDeniedError:
		return e.Code
	case *core.TrustEscalationError:
		return e.Code
	case *core.SchemaValidationError:
		return e.Code
	case *core.RateLimitError:
		return e.Code
	case *core.ToolNotFoundError:
		return e.Code
	case *core.UnsafeConfigurationError:
		return e.Code
	case *core.InputGuardError:
		return e.Code
	case *core.NetworkError:
		return e.Code
	}
	return "ERROR"
}
