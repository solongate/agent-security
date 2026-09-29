package sdk

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/codeyevsky/solongate/proxy/internal/config"
	"github.com/codeyevsky/solongate/sgshared"
)

type auditEntry struct {
	Tool             string         `json:"tool"`
	Arguments        map[string]any `json:"arguments"`
	Decision         string         `json:"decision"`
	Reason           string         `json:"reason"`
	MatchedRule      string         `json:"matchedRule,omitempty"`
	EvaluationTimeMs float64        `json:"evaluationTimeMs"`
}

// postAuditLog delivers one audit entry. The caller does NOT wait for it — see
// SolonGate.sendAuditLog.

// writeAuditEntry appends one decision to THIS MACHINE's audit trail, the same file
// the guard, the hooks and the MCP proxy append to.
//
// This file was the SDK's service client: a policy fetched from /policies/default
// and polled for changes, and an audit POST. A gate embedded in somebody's tool
// server has no more business shipping their tool calls off the machine than the
// guard did.
func writeAuditEntry(entry auditEntry, warn func(string)) {
	body, err := json.Marshal(entry)
	if err != nil {
		warn("could not encode an audit entry: " + err.Error())
		return
	}
	dir := config.LocalLogsDir()
	if err := os.MkdirAll(dir, sgshared.DirMode); err != nil {
		warn("could not create " + dir + ": " + err.Error())
		return
	}
	path := filepath.Join(dir, "solongate-audit.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, sgshared.FileMode)
	if err != nil {
		warn("could not write " + path + ": " + err.Error())
		return
	}
	defer f.Close()
	if _, err := f.Write(append(body, '\n')); err != nil {
		warn("could not write " + path + ": " + err.Error())
	}
}
