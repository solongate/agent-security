package proxy

// Where the proxy's record goes.
//
// This file is what is left of cloud.go, which was the whole service integration:
// a licence check against /auth/me, a policy fetched and pushed back, the upstream's
// tools and the server itself registered on a dashboard, and an audit POST with a
// retry. All of it is gone with the service.
//
// The POST had a fallback worth remembering as a shape to avoid: when every attempt
// failed it appended the entry to `.solongate-audit-backup.jsonl` in whatever
// directory the proxy happened to start in. A second log, in a place nothing else
// reads, holding exactly the entries somebody would most want to find.

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/codeyevsky/solongate/proxy/internal/config"
	"github.com/codeyevsky/solongate/sgshared"
)

// writeAuditEntry appends one decision to THIS MACHINE's audit trail — the same
// file the guard and the hooks append to, so a machine has one log rather than two.
//
// Owner-only, because the line records the tool, its arguments and the reason: a log
// of what somebody was working on.
func writeAuditEntry(entry auditEntry, log func(string)) {
	body, err := json.Marshal(entry)
	if err != nil {
		log("could not encode an audit entry: " + err.Error())
		return
	}
	dir := config.LocalLogsDir()
	if err := os.MkdirAll(dir, sgshared.DirMode); err != nil {
		log("could not create " + dir + ": " + err.Error())
		return
	}
	path := filepath.Join(dir, "solongate-audit.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, sgshared.FileMode)
	if err != nil {
		log("could not write " + path + ": " + err.Error())
		return
	}
	defer f.Close()
	if _, err := f.Write(append(body, '\n')); err != nil {
		log("could not write " + path + ": " + err.Error())
	}
}

// auditEntry is one decision, as it lands in the file.
//
// The shape is the one the service's ingest route accepted, kept rather than
// reshaped: the CLI and the TUI read this log through the same AuditEntry mapping
// they read the hooks' lines with, and renaming a field here would mean renaming it
// in two readers for no gain.
type auditEntry struct {
	Tool             string         `json:"tool"`
	Arguments        map[string]any `json:"arguments"`
	Decision         string         `json:"decision"`
	Reason           string         `json:"reason"`
	Permission       string         `json:"permission,omitempty"`
	MatchedRule      string         `json:"matchedRule,omitempty"`
	EvaluationTimeMs int64          `json:"evaluationTimeMs"`
	AgentID          string         `json:"agent_id,omitempty"`
	AgentName        string         `json:"agent_name,omitempty"`
	SubAgentID       string         `json:"sub_agent_id,omitempty"`
	SubAgentName     string         `json:"sub_agent_name,omitempty"`
	// Timestamp used to be written only to a local backup, because the service
	// stamped its own and "sending one would let a clock-skewed machine reorder
	// somebody else's audit trail". The file is the record now, so it is always
	// written — the readers sort on it.
	Timestamp string `json:"timestamp,omitempty"`
}

// orDefault and orOne survive from the same file: small helpers the proxy's own
// logging and registration shared.
func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func orOne(v int) int {
	if v == 0 {
		return 1
	}
	return v
}
