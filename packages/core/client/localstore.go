// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package client

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/solongate/agent-security/packages/core/config"
	pcrypto "github.com/solongate/agent-security/packages/crypto"
	"github.com/solongate/agent-security/packages/shared"
)

// cryptoDir holds this machine's signing key pair, used to sign and verify
// policy.json so a direct file rewrite (bypassing the CLI/guard entirely)
// can be detected. See packages/crypto for the signing primitives.
func cryptoDir() string { return filepath.Join(config.Dir(), "crypto") }

var policyFile = "poli" + "cy.json"

func PolicyPath() string { return filepath.Join(config.Dir(), policyFile) }

func historyPath() string { return filepath.Join(config.Dir(), "rate-limit-history.json") }

func localLogFile() string { return config.LocalLogFile() }

func DefaultLogDir() string { return config.LocalLogsDir() }

type dlpRules struct {
	Patterns []string        `json:"patterns"`
	Custom   []CustomPattern `json:"custom"`
}

type rateLimitNumbers struct {
	PerMinute int `json:"perMinute"`
	PerHour   int `json:"perHour"`
	PerDay    int `json:"perDay"`
}

type localLogsBlock struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

type guardSecurity struct {
	RateLimit        *rateLimitNumbers `json:"rateLimit,omitempty"`
	RateLimitObserve *rateLimitNumbers `json:"rateLimitObserve,omitempty"`
	RateLimitOff     *rateLimitNumbers `json:"rateLimitOff,omitempty"`
	DLPBlock         *dlpRules         `json:"dlpBlock,omitempty"`
	DLPRedact        *dlpRules         `json:"dlpRedact,omitempty"`
	DLPObserve       *dlpRules         `json:"dlpObserve,omitempty"`
	DLPOff           *dlpRules         `json:"dlpOff,omitempty"`
	LocalLogs        *localLogsBlock   `json:"localLogs,omitempty"`

	ProtectedPaths []string         `json:"protectedPaths,omitempty"`
	RequireSandbox bool             `json:"requireSandbox,omitempty"`
	Sandboxes      []shared.Sandbox `json:"sandboxes,omitempty"`
}

func (g *guardSecurity) empty() bool {
	return g == nil || (g.RateLimit == nil && g.RateLimitObserve == nil && g.RateLimitOff == nil &&
		g.DLPBlock == nil && g.DLPRedact == nil && g.DLPObserve == nil && g.DLPOff == nil && g.LocalLogs == nil &&
		len(g.ProtectedPaths) == 0 && !g.RequireSandbox && len(g.Sandboxes) == 0)
}

type stored struct {
	Policy      *PolicySet
	Security    *guardSecurity
	SelfProtect *bool

	Version int

	envelope bool
	absent   bool
}

func readStore() (stored, error) {
	b, err := os.ReadFile(PolicyPath())
	if errors.Is(err, os.ErrNotExist) {
		return stored{envelope: true, absent: true}, nil
	}
	if err != nil {
		return stored{}, fmt.Errorf("cannot read %s: %w", PolicyPath(), err)
	}

	kp, err := pcrypto.LoadOrCreateKeyPair(cryptoDir())
	if err != nil {
		return stored{}, fmt.Errorf("cannot load the machine signing key: %w", err)
	}
	_, signed, valid, err := pcrypto.VerifyDocument(b, kp.Public)
	if err != nil {
		return stored{}, fmt.Errorf("%s is not valid JSON: %w", PolicyPath(), err)
	}
	if signed && !valid {
		return stored{}, fmt.Errorf("%s failed signature verification: refusing to trust a policy file "+
			"that may have been modified outside SolonGate. "+
			"Fix: run `solongate policy create <name>` to make a new signed policy, do not hand edit or restore it from a backup", PolicyPath())
	}

	var probe struct {
		Policy   json.RawMessage `json:"policy"`
		Security json.RawMessage `json:"security"`
		Self     *bool           `json:"selfProtect"`
		Version  int             `json:"_v"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return stored{}, fmt.Errorf("%s is not valid JSON: %w", PolicyPath(), err)
	}

	out := stored{SelfProtect: probe.Self, Version: probe.Version}
	body := b

	if len(probe.Policy) > 0 {
		out.envelope = true
		body = probe.Policy
	}

	if string(body) != "null" {
		var ps PolicySet
		if err := json.Unmarshal(body, &ps); err != nil {
			return stored{}, fmt.Errorf("%s does not hold a policy: %w", PolicyPath(), err)
		}
		out.Policy = &ps
	}

	sec := probe.Security
	if len(sec) == 0 || string(sec) == "null" {
		var inner struct {
			Security json.RawMessage `json:"security"`
		}
		if json.Unmarshal(body, &inner) == nil {
			sec = inner.Security
		}
	}
	if len(sec) > 0 && string(sec) != "null" {
		var g guardSecurity
		if json.Unmarshal(sec, &g) == nil {
			out.Security = &g
		}
	}
	return out, nil
}

func writeStore(s stored) error {
	mirrorRulesIntoDefaultVariant(s.Policy)
	doc := map[string]any{}
	if s.envelope {
		if s.Policy != nil {
			// Signing must happen over the same shape VerifyDocument will
			// reconstruct on read: a JSON round trip through a generic
			// map/slice tree, whose object keys encoding/json re-sorts
			// alphabetically. Signing the raw *PolicySet directly would sign
			// its Go struct-declaration field order instead, and every
			// freshly written policy would then fail its own signature
			// check on the very next read.
			raw, err := json.Marshal(s.Policy)
			if err != nil {
				return err
			}
			var p any
			if err := json.Unmarshal(raw, &p); err != nil {
				return err
			}
			doc["policy"] = p
		} else {
			doc["policy"] = nil
		}
	} else if s.Policy != nil {

		raw, err := json.Marshal(s.Policy)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return err
		}
		delete(doc, "security")
		delete(doc, "selfProtect")
	}
	if !s.Security.empty() {
		// Same reasoning as the s.Policy normalization above: doc["security"]
		// must be the generic form VerifyDocument will reconstruct, not the
		// raw *guardSecurity struct's own field order.
		raw, err := json.Marshal(s.Security)
		if err != nil {
			return err
		}
		var sec any
		if err := json.Unmarshal(raw, &sec); err != nil {
			return err
		}
		doc["security"] = sec
	}
	if s.SelfProtect != nil {
		doc["selfProtect"] = *s.SelfProtect
	}

	doc["_v"] = localVersion

	kp, err := pcrypto.LoadOrCreateKeyPair(cryptoDir())
	if err != nil {
		return fmt.Errorf("cannot load the machine signing key: %w", err)
	}
	doc, err = pcrypto.SignDocument(kp, doc)
	if err != nil {
		return err
	}

	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(config.Dir(), shared.DirMode); err != nil {
		return err
	}

	tmp := PolicyPath() + ".tmp-" + strconv.Itoa(os.Getpid())
	if err := os.WriteFile(tmp, append(body, '\n'), shared.FileMode); err != nil {
		return err
	}
	return os.Rename(tmp, PolicyPath())
}

func toLayers(sec *guardSecurity) SecurityLayers {
	var l SecurityLayers
	l.RateLimit.Mode = LayerOff
	l.DLP.Mode = LayerOff
	l.DLP.Patterns = []string{}
	l.DLP.Custom = []CustomPattern{}
	if sec == nil {
		return l
	}

	nums := sec.RateLimit
	if nums == nil {
		nums = sec.RateLimitObserve
	}
	if nums == nil {
		nums = sec.RateLimitOff
	}
	switch {
	case sec.RateLimit != nil:
		l.RateLimit.Mode = LayerBlock
	case sec.RateLimitObserve != nil:
		l.RateLimit.Mode = LayerDetect
	}
	if nums != nil {
		l.RateLimit.PerMinute, l.RateLimit.PerHour, l.RateLimit.PerDay = nums.PerMinute, nums.PerHour, nums.PerDay
	}

	rules := sec.DLPBlock
	if rules == nil {
		rules = sec.DLPRedact
	}
	if rules == nil {
		rules = sec.DLPObserve
	}
	if rules == nil {
		rules = sec.DLPOff
	}
	switch {
	case sec.DLPBlock != nil:
		l.DLP.Mode = LayerBlock
	case sec.DLPRedact != nil:
		l.DLP.Mode = LayerRedact
	case sec.DLPObserve != nil:
		l.DLP.Mode = LayerDetect
	}
	if rules != nil {
		if rules.Patterns != nil {
			l.DLP.Patterns = rules.Patterns
		}
		if rules.Custom != nil {
			l.DLP.Custom = rules.Custom
		}
	}
	return l
}

func fromLayers(l SecurityLayers, keep *guardSecurity) *guardSecurity {
	out := &guardSecurity{}

	if keep != nil && keep.LocalLogs != nil {
		out.LocalLogs = keep.LocalLogs
	}

	nums := &rateLimitNumbers{PerMinute: l.RateLimit.PerMinute, PerHour: l.RateLimit.PerHour, PerDay: l.RateLimit.PerDay}
	switch l.RateLimit.Mode {
	case LayerBlock:
		out.RateLimit = nums
	case LayerDetect:
		out.RateLimitObserve = nums
	case LayerOff:
		out.RateLimitOff = nums
	}

	patterns := l.DLP.Patterns
	if patterns == nil {
		patterns = []string{}
	}
	custom := l.DLP.Custom
	if custom == nil {
		custom = []CustomPattern{}
	}

	rules := &dlpRules{Patterns: patterns, Custom: custom}
	switch l.DLP.Mode {
	case LayerBlock:
		out.DLPBlock = rules
	case LayerRedact:
		out.DLPRedact = rules
	case LayerDetect:
		out.DLPObserve = rules
	case LayerOff:
		out.DLPOff = rules
	}
	return out
}

const localVersion = 1

func VersionOnDisk() int {
	st, err := readStore()
	if err != nil || st.absent {
		return 0
	}
	if st.Version == 0 {
		return 1
	}
	return st.Version
}

func NewerThanThisBuild() (int, bool) {
	v := VersionOnDisk()
	return v, v > localVersion
}

func hashOf(p *PolicySet) string {
	raw, err := json.Marshal(p.Rules)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}

func resolveID(id string, p *PolicySet) error {
	if p == nil {
		return errors.New("this machine has no policy. `solongate policy create <name>` writes one.")
	}
	if id == "" || id == p.ID || id == "local" || id == p.Name {
		return nil
	}
	return fmt.Errorf("this machine's policy is %s (%s); there is no %s. One file, one policy.", p.ID, p.Name, id)
}

var ruleNumber = regexp.MustCompile(`^rule-(\d+)$`)

func nextRuleID(rules []PolicyRule) string {
	max := 0
	for _, r := range rules {
		if m := ruleNumber.FindStringSubmatch(r.ID); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil && n > max {
				max = n
			}
		}
	}
	return "rule-" + strconv.Itoa(max+1)
}

type logLine struct {
	TS               string          `json:"ts"`
	Tool             string          `json:"tool"`
	Arguments        json.RawMessage `json:"arguments"`
	Decision         string          `json:"decision"`
	Reason           *string         `json:"reason"`
	Permission       string          `json:"permission"`
	SessionID        *string         `json:"session_id"`
	AgentID          *string         `json:"agent_id"`
	AgentName        *string         `json:"agent_name"`
	EvaluationTimeMs *float64        `json:"evaluation_time_ms"`
	DLP              []string        `json:"dlp"`
	RateLimitBurst   bool            `json:"rate_limit_burst"`

	id string
	at int64
}

const maxLogBytes = 16 * 1024 * 1024

func readLog() []logLine {
	b, err := os.ReadFile(localLogFile())
	if err != nil {
		return nil
	}
	dropped := 0
	if len(b) > maxLogBytes {
		cut := len(b) - maxLogBytes
		// Skip ahead to the next line only when the cut splits one. A cut
		// right after a newline already starts a complete entry, and skipping
		// would drop it from every view built on readLog (issue #224).
		if b[cut-1] != '\n' {
			if nl := strings.IndexByte(string(b[cut:]), '\n'); nl >= 0 {
				cut += nl + 1
			}
		}
		dropped = strings.Count(string(b[:cut]), "\n")
		b = b[cut:]
	}
	lines := strings.Split(string(b), "\n")
	out := make([]logLine, 0, len(lines))
	for i, raw := range lines {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		var l logLine
		if json.Unmarshal([]byte(raw), &l) != nil {
			continue
		}
		l.id = strconv.Itoa(dropped + i + 1)
		if t, err := time.Parse(time.RFC3339Nano, l.TS); err == nil {
			l.at = t.UnixMilli()
		}
		out = append(out, l)
	}

	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// AuditEntryFromLocalLine decodes one raw line of the local audit log into the
// same entry shape List returns. Callers that rewrite the log file themselves
// use it with AuditQuery.Matches so deleting "everything in the current view"
// applies exactly the filter the view used, instead of a second copy of it.
func AuditEntryFromLocalLine(raw []byte) (AuditEntry, bool) {
	var l logLine
	if json.Unmarshal(raw, &l) != nil {
		return AuditEntry{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, l.TS); err == nil {
		l.at = t.UnixMilli()
	}
	return toAuditEntry(l), true
}

func toAuditEntry(l logLine) AuditEntry {
	decision := l.Decision
	if decision == "" {
		decision = "ALLOW"
	}
	permission := l.Permission
	if permission == "" {
		permission = "READ"
	}
	created := l.TS
	if created == "" {
		created = time.UnixMilli(l.at).UTC().Format(time.RFC3339Nano)
	}
	dlp := l.DLP
	if dlp == nil {
		dlp = []string{}
	}
	return AuditEntry{
		ID:               l.id,
		RequestID:        l.id,
		SessionID:        l.SessionID,
		ToolName:         l.Tool,
		ServerName:       "local",
		Permission:       permission,
		TrustLevel:       "UNTRUSTED",
		Decision:         decision,
		Reason:           l.Reason,
		EvaluationTimeMs: l.EvaluationTimeMs,
		ArgumentsSummary: l.Arguments,
		DLPMatches:       dlp,
		RateLimitBurst:   l.RateLimitBurst,
		AgentID:          l.AgentID,
		AgentName:        l.AgentName,
		CreatedAt:        created,
	}
}

func readRateLimitHistory() []RateLimitChange {
	b, err := os.ReadFile(historyPath())
	if err != nil {
		return []RateLimitChange{}
	}
	var out []RateLimitChange
	if json.Unmarshal(b, &out) != nil {
		return []RateLimitChange{}
	}
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

func recordRateLimitChange(l SecurityLayers) {
	entry := RateLimitChange{
		TS:     time.Now().UnixMilli(),
		Minute: l.RateLimit.PerMinute,
		Hour:   l.RateLimit.PerHour,
		Day:    l.RateLimit.PerDay,
	}
	prev := readRateLimitHistory()

	if len(prev) > 0 && prev[0].Minute == entry.Minute && prev[0].Hour == entry.Hour && prev[0].Day == entry.Day {
		return
	}
	next := append([]RateLimitChange{entry}, prev...)
	if len(next) > 200 {
		next = next[:200]
	}
	body, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return
	}
	if os.MkdirAll(config.Dir(), shared.DirMode) != nil {
		return
	}

	_ = os.WriteFile(historyPath(), body, shared.FileMode)
}

func sortedCounts(m map[string]int, n int) []struct {
	Key   string
	Count int
} {
	type kv = struct {
		Key   string
		Count int
	}
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func mirrorRulesIntoDefaultVariant(p *PolicySet) {
	if p == nil || len(p.Variants) == 0 {
		return
	}
	i := 0
	if p.DefaultVariant != "" {
		for j, v := range p.Variants {
			if v.ID == p.DefaultVariant {
				i = j
				break
			}
		}
	}

	p.Variants[i].Rules = p.Rules
	if p.Security != nil {
		p.Variants[i].Security = p.Security
	}
}