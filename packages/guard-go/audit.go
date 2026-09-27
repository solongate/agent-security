package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/codeyevsky/solongate/sgshared"
)

// Where a decision gets recorded. Local storage and the cloud are EXCLUSIVE:
// the setting says "keep these on my machines instead of your cloud", so when it
// is on nothing leaves, and when it is off nothing is written to disk.

// localLogsOnly answers from the SETTING. `nil` security with hasSecurity=true
// is an answer ("the API sent no security block"), not a gap — only a cache that
// could not be read at all falls through to the device marker.
func localLogsOnly(sec *sgshared.Security, hasSecurity bool) bool {
	if hasSecurity {
		if sec == nil || sec.LocalLogs == nil {
			return false
		}
		return sec.LocalLogs.Enabled && strings.TrimSpace(sec.LocalLogs.Path) != ""
	}
	b, err := os.ReadFile(filepath.Join(sgshared.SGDir(), ".local-logs-mode.json"))
	if err != nil {
		return false
	}
	var m struct {
		LocalOnly bool `json:"localOnly"`
	}
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	return m.LocalOnly
}

var trailingSep = regexp.MustCompile(`[\\/]+$`)

// The folder is a PROJECT setting, so it reaches every device on the project: a
// Windows path arrives on a Linux machine and is not a location there. Node
// would treat it as relative and create it under the agent's working directory,
// polluting whatever repo it happened to be in. Fall back instead — the entry
// matters more than the location.
func resolveLocalLogDir(raw string) string {
	dir := trailingSep.ReplaceAllString(strings.TrimSpace(raw), "")
	if dir == "" {
		return ""
	}
	if !filepath.IsAbs(dir) {
		return filepath.Join(sgshared.SGDir(), "local-logs")
	}
	return dir
}

func accountMark(apiKey string) string {
	if apiKey == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])[:16]
}

func writeLocalLog(sec *sgshared.Security, hasSecurity bool, cred sgshared.Credential, entry map[string]interface{}) {
	if mark := accountMark(cred.APIKey); mark != "" {
		entry["acct"] = mark
	}
	dir := ""
	if sec != nil && sec.LocalLogs != nil && sec.LocalLogs.Enabled {
		dir = resolveLocalLogDir(sec.LocalLogs.Path)
	}
	if dir == "" {
		// No usable folder in the config, but the marker can still say local is
		// on — keep the copy in the per-device default rather than dropping it.
		if !localLogsOnly(sec, hasSecurity) {
			return
		}
		dir = filepath.Join(sgshared.SGDir(), "local-logs")
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	if os.MkdirAll(dir, 0o755) != nil {
		dir = filepath.Join(sgshared.SGDir(), "local-logs")
		if os.MkdirAll(dir, 0o755) != nil {
			return
		}
	}
	f, err := os.OpenFile(filepath.Join(dir, "solongate-audit.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

// postAuditDetached records a decision in the cloud WITHOUT the caller waiting.
//
// The verdict is the product; the audit line is bookkeeping. Awaiting the POST
// put a network round trip between "blocked" and the agent hearing it — 1643ms
// per denial against 78ms with the API unreachable — so the record is handed to
// a detached child instead of being waited on, and instead of being dropped.
func postAuditDetached(cred sgshared.Credential, entry map[string]interface{}) {
	if cred.APIKey == "" {
		return
	}
	payload, err := json.Marshal(map[string]interface{}{
		"url":  cred.APIURL + "/api/v1/audit-logs",
		"key":  cred.APIKey,
		"body": entry,
	})
	if err != nil {
		return
	}
	self, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(self, "--sg-audit-post", base64.StdEncoding.EncodeToString(payload))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	detach(cmd)
	if cmd.Start() == nil {
		_ = cmd.Process.Release()
	}
}

// runAuditPost is the detached child's whole job: deliver one record and exit.
func runAuditPost(arg string) {
	raw, err := base64.StdEncoding.DecodeString(arg)
	if err != nil {
		return
	}
	var p struct {
		URL  string          `json:"url"`
		Key  string          `json:"key"`
		Body json.RawMessage `json:"body"`
	}
	if json.Unmarshal(raw, &p) != nil || p.URL == "" {
		return
	}
	req, err := http.NewRequest("POST", p.URL, bytes.NewReader(p.Body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.Key)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}
