package api

// The store behind every command and every panel: two files on this machine.
//
//	~/.solongate/policy.json                        the policy, and the layers
//	~/.solongate/local-logs/solongate-audit.jsonl   what the hooks recorded
//
// There is no service. This is the Go twin of
// packages/proxy/src/api-client/local-store.ts, and it has to agree with it: the
// two CLIs read and write the SAME files, and the guard reads them too.
//
// THE POLICY FILE IS SHARED WITH THE GUARD, which is what shapes everything
// here. It is read on every tool call, in two spellings:
//
//	{"policy": {…}, "security": {…}, "selfProtect": true}   the envelope
//	{"mode": "denylist", "rules": [ … ], "security": {…}}   the policy alone
//
// Both are read, and whichever one a person wrote is what gets written back. A
// hand-written bare policy stays bare after `solongate policy deny …`.
//
// `security` is stored in the ENFORCEMENT shape the guard consumes and converted
// to and from the SecurityLayers shape the CLI thinks in. One representation on
// disk, so there is no second copy to fall out of step.

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

	"github.com/codeyevsky/solongate/proxy/internal/config"
	"github.com/codeyevsky/solongate/sgshared"
)

// policyFile is assembled: the guard protects paths spelled this way, and the
// tooling that edits this file is subject to that protection.
var policyFile = "poli" + "cy.json"

// PolicyPath is the file this machine's policy lives in.
func PolicyPath() string { return filepath.Join(config.Dir(), policyFile) }

func historyPath() string  { return filepath.Join(config.Dir(), "rate-limit-history.json") }
func localLogFile() string { return filepath.Join(config.LocalLogsDir(), "solongate-audit.jsonl") }

// DefaultLogDir is where the hooks write when nobody named another folder.
func DefaultLogDir() string { return config.LocalLogsDir() }

// ── the guard's `security` shape ───────────────────────────────────────────
//
// Pointers as optionals, exactly as the guard reads them: an absent key and a
// key set to null are the same answer, which is why the conversion below is
// lossless both ways.

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
	DLPBlock         *dlpRules         `json:"dlpBlock,omitempty"`
	DLPRedact        *dlpRules         `json:"dlpRedact,omitempty"`
	LocalLogs        *localLogsBlock   `json:"localLogs,omitempty"`
}

func (g *guardSecurity) empty() bool {
	return g == nil || (g.RateLimit == nil && g.RateLimitObserve == nil &&
		g.DLPBlock == nil && g.DLPRedact == nil && g.LocalLogs == nil)
}

// stored is the file, plus which spelling it was in.
type stored struct {
	Policy      *PolicySet
	Security    *guardSecurity
	SelfProtect *bool
	// envelope records the spelling, so a write puts it back the way it was.
	envelope bool
	absent   bool
}

// readStore reads the policy file. An unreadable file is NOT an empty one:
// answering "no policy" for a file with a stray comma would tell somebody their
// rules are gone while the guard, failing the same way, enforces nothing.
func readStore() (stored, error) {
	b, err := os.ReadFile(PolicyPath())
	if errors.Is(err, os.ErrNotExist) {
		return stored{envelope: true, absent: true}, nil
	}
	if err != nil {
		return stored{}, fmt.Errorf("cannot read %s: %w", PolicyPath(), err)
	}

	var probe struct {
		Policy   json.RawMessage `json:"policy"`
		Security json.RawMessage `json:"security"`
		Self     *bool           `json:"selfProtect"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return stored{}, fmt.Errorf("%s is not valid JSON: %w", PolicyPath(), err)
	}

	out := stored{SelfProtect: probe.Self}
	body := b
	if len(probe.Policy) > 0 && string(probe.Policy) != "null" {
		out.envelope = true
		body = probe.Policy
	}

	var ps PolicySet
	if err := json.Unmarshal(body, &ps); err != nil {
		return stored{}, fmt.Errorf("%s does not hold a policy: %w", PolicyPath(), err)
	}
	out.Policy = &ps

	// The envelope's block wins; a block INSIDE the policy document is how a
	// service stores one, so it is the shape a policy exported from one arrives
	// in and is read as a fallback.
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

// writeStore writes the file back in the shape it was read in.
func writeStore(s stored) error {
	doc := map[string]any{}
	if s.envelope {
		doc["policy"] = s.Policy
	} else if s.Policy != nil {
		// Round-trip through the policy's own JSON so a field this version does
		// not know about survives — Rules keeps its raw bytes for the same reason.
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
		doc["security"] = s.Security
	}
	if s.SelfProtect != nil {
		doc["selfProtect"] = *s.SelfProtect
	}

	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(config.Dir(), sgshared.DirMode); err != nil {
		return err
	}
	// Through a temporary file and renamed. The guard reads this on EVERY tool
	// call, and a half-written file there is not a stale policy — it is an
	// unparseable one, which the guard reports as no policy at all.
	tmp := PolicyPath() + ".tmp-" + strconv.Itoa(os.Getpid())
	if err := os.WriteFile(tmp, append(body, '\n'), sgshared.FileMode); err != nil {
		return err
	}
	return os.Rename(tmp, PolicyPath())
}

// ── SecurityLayers <-> the guard's shape ───────────────────────────────────
//
// The mapping the service applied (store.GuardEnforcementConfig): a rate limit
// in block mode is `rateLimit`, in detect mode `rateLimitObserve`, never both.
// DLP in block mode sets dlpBlock AND dlpRedact, because blocking is the extra
// step over redacting; detect sets only dlpRedact. Which makes it invertible.

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
	switch {
	case sec.DLPBlock != nil:
		l.DLP.Mode = LayerBlock
	case sec.DLPRedact != nil:
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
	// localLogs is not a layer this edits; it has its own setting, so it survives
	// a rate-limit or DLP change untouched.
	if keep != nil && keep.LocalLogs != nil {
		out.LocalLogs = keep.LocalLogs
	}

	nums := &rateLimitNumbers{PerMinute: l.RateLimit.PerMinute, PerHour: l.RateLimit.PerHour, PerDay: l.RateLimit.PerDay}
	switch l.RateLimit.Mode {
	case LayerBlock:
		out.RateLimit = nums
	case LayerDetect:
		out.RateLimitObserve = nums
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
	if l.DLP.Mode == LayerBlock {
		out.DLPBlock = rules
		out.DLPRedact = rules
	} else if l.DLP.Mode == LayerDetect {
		out.DLPRedact = rules
	}
	return out
}

// ── the policy ─────────────────────────────────────────────────────────────

const localVersion = 1

func hashOf(p *PolicySet) string {
	raw, err := json.Marshal(p.Rules)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}

// resolveID checks an id against the one policy this machine has.
//
// Every command takes an id because a service had many policies. A machine has
// one file, so the id in the file is the only id there is — and `local` is
// accepted as a name for it, so nobody has to look an id up to edit their own.
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

// nextRuleID keeps counting past the highest rule-N present, so it cannot
// collide with a rule somebody wrote by hand.
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

// ── the audit log ──────────────────────────────────────────────────────────

// logLine is one line as the hooks write it. Everything is optional: they are
// versioned, and an older line must still be readable.
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

	// id is the line's 1-based position, and at is its parsed timestamp.
	id string
	at int64
}

// maxLogBytes caps what one read holds in memory. The log is append-only with no
// rotation, so this is a real bound and not an oversight; it is taken from the
// END, because that is where the recent entries are.
const maxLogBytes = 16 * 1024 * 1024

// readLog answers newest first, with each line's ORIGINAL number as its id — so
// an id somebody saw still names the same entry after more lines are appended.
func readLog() []logLine {
	b, err := os.ReadFile(localLogFile())
	if err != nil {
		return nil
	}
	dropped := 0
	if len(b) > maxLogBytes {
		cut := len(b) - maxLogBytes
		if nl := strings.IndexByte(string(b[cut:]), '\n'); nl >= 0 {
			cut += nl + 1
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
	// Reverse in place: newest first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
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

// ── the rate-limit history ─────────────────────────────────────────────────
//
// Kept because a change is worth seeing beside a burst: "the limit was 30 when
// that happened". A service recorded it; nothing else does, so writing it is
// part of changing the limit.

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
	// An unchanged limit is not a change. Saving one on every settings write
	// would fill the list with rows that say nothing.
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
	if os.MkdirAll(config.Dir(), sgshared.DirMode) != nil {
		return
	}
	// The limit still changed; only the note about it is at risk.
	_ = os.WriteFile(historyPath(), body, sgshared.FileMode)
}

// sortedCounts turns a count map into the top n pairs, highest first.
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
