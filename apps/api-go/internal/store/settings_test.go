package store

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

// The security-layer coercion and the timestamp format are the two things in
// this package that can be wrong without any query failing, so they are the two
// with tests.

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if s == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	return m
}

func TestCoerceLayersDefaults(t *testing.T) {
	got := coerceLayers(nil)
	if got.RateLimit.Mode != LayerDetect || got.RateLimit.PerMinute != 120 {
		t.Errorf("rateLimit = %+v, want detect at 120/min", got.RateLimit)
	}
	if got.DLP.Mode != LayerDetect || len(got.DLP.Patterns) != len(DLPPatterns) {
		t.Errorf("dlp = %+v, want detect with every built-in pattern", got.DLP)
	}
	if got.Ghost.Mode != "off" {
		t.Errorf("ghost mode = %q, want off", got.Ghost.Mode)
	}
}

// The compatibility branches. Each of these is a shape somebody's project is
// stored in today, and dropping the branch re-interprets their configuration
// without anybody touching it.
func TestCoerceLayersLegacyShapes(t *testing.T) {
	cases := []struct {
		name     string
		stored   string
		wantRL   string
		wantDLP  string
		wantPerM int64
	}{
		{
			name:   "explicit modes win",
			stored: `{"rateLimit":{"mode":"block","perMinute":10},"dlp":{"mode":"off"}}`,
			wantRL: LayerBlock, wantDLP: LayerOff, wantPerM: 10,
		},
		{
			name:   "rateLimit.enabled true means block",
			stored: `{"rateLimit":{"enabled":true,"perMinute":30}}`,
			wantRL: LayerBlock, wantDLP: LayerDetect, wantPerM: 30,
		},
		{
			// No `anomaly` key at all: the shape from before the rate-limit
			// layer existed. It means detect, not off — reading it as off would
			// silently stop detection for every untouched project.
			name:   "absent anomaly block means detect",
			stored: `{"rateLimit":{"perMinute":45}}`,
			wantRL: LayerDetect, wantDLP: LayerDetect, wantPerM: 45,
		},
		{
			name:   "anomaly disabled means off",
			stored: `{"anomaly":{"enabled":false}}`,
			wantRL: LayerOff, wantDLP: LayerDetect, wantPerM: 120,
		},
		{
			// perMinute lived in the anomaly block first.
			name:   "perMinute falls back to anomaly",
			stored: `{"anomaly":{"enabled":true,"perMinute":77}}`,
			wantRL: LayerDetect, wantDLP: LayerDetect, wantPerM: 77,
		},
		{
			name:   "dlp.block true means block",
			stored: `{"dlp":{"block":true}}`,
			wantRL: LayerDetect, wantDLP: LayerBlock, wantPerM: 120,
		},
		{
			name:   "dlp.enabled false means off",
			stored: `{"dlp":{"enabled":false}}`,
			wantRL: LayerDetect, wantDLP: LayerOff, wantPerM: 120,
		},
		{
			// A number that arrived from a text input is stored as a string.
			name:   "numeric strings coerce",
			stored: `{"rateLimit":{"mode":"block","perMinute":"250"}}`,
			wantRL: LayerBlock, wantDLP: LayerDetect, wantPerM: 250,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := coerceLayers(decode(t, tc.stored))
			if got.RateLimit.Mode != tc.wantRL {
				t.Errorf("rateLimit mode = %q, want %q", got.RateLimit.Mode, tc.wantRL)
			}
			if got.DLP.Mode != tc.wantDLP {
				t.Errorf("dlp mode = %q, want %q", got.DLP.Mode, tc.wantDLP)
			}
			if got.RateLimit.PerMinute != tc.wantPerM {
				t.Errorf("perMinute = %d, want %d", got.RateLimit.PerMinute, tc.wantPerM)
			}
		})
	}
}

func TestCoerceLayersClampsAndTrims(t *testing.T) {
	got := coerceLayers(decode(t, `{
		"rateLimit":{"mode":"block","perMinute":-5,"perHour":99999999999,"perDay":3.9},
		"dlp":{"mode":"block","patterns":["JWT","not a real pattern","AWS access key"],
		       "custom":[{"name":"  x  ","re":"  y  "},{"name":"","re":"z"}]},
		"ghost":{"mode":"on","patterns":["a","a","b",""]}
	}`))

	if got.RateLimit.PerMinute != 0 {
		t.Errorf("perMinute = %d, want a negative clamped to 0", got.RateLimit.PerMinute)
	}
	if got.RateLimit.PerHour != 1_000_000 {
		t.Errorf("perHour = %d, want the 1e6 ceiling", got.RateLimit.PerHour)
	}
	if got.RateLimit.PerDay != 3 {
		t.Errorf("perDay = %d, want 3.9 truncated", got.RateLimit.PerDay)
	}
	// The subset is filtered over the built-in list, so an unknown name is
	// dropped and the canonical ORDER is kept rather than the stored one.
	want := []string{"AWS access key", "JWT"}
	if len(got.DLP.Patterns) != 2 || got.DLP.Patterns[0] != want[0] || got.DLP.Patterns[1] != want[1] {
		t.Errorf("patterns = %v, want %v in built-in order", got.DLP.Patterns, want)
	}
	if len(got.DLP.Custom) != 1 || got.DLP.Custom[0].Name != "x" || got.DLP.Custom[0].Re != "y" {
		t.Errorf("custom = %+v, want one trimmed entry and the nameless one dropped", got.DLP.Custom)
	}
	if len(got.Ghost.Patterns) != 2 {
		t.Errorf("ghost patterns = %v, want duplicates and blanks removed", got.Ghost.Patterns)
	}
}

// GuardEnforcementConfig is what the guard receives. null is an answer here,
// not an absence, so the JSON has to carry the keys.
func TestGuardEnforcementConfig(t *testing.T) {
	detect := SecurityLayers{
		RateLimit: RateLimitLayer{Mode: LayerDetect, PerMinute: 120},
		DLP:       DLPLayer{Mode: LayerDetect, Patterns: []string{"JWT"}},
		Ghost:     GhostLayer{Mode: "off"},
	}
	g := GuardEnforcementConfig(detect)
	if g.RateLimit != nil {
		t.Error("detect must not set rateLimit; that is the blocking one")
	}
	if g.RateLimitObserve == nil {
		t.Error("detect must set rateLimitObserve so the audit hook records bursts")
	}
	if g.DLPBlock != nil {
		t.Error("detect must not set dlpBlock")
	}
	if g.DLPRedact == nil {
		t.Error("detect must still redact")
	}

	block := SecurityLayers{
		RateLimit: RateLimitLayer{Mode: LayerBlock, PerMinute: 10},
		DLP:       DLPLayer{Mode: LayerBlock, Patterns: []string{"JWT"}},
		Ghost:     GhostLayer{Mode: "on", Patterns: []string{"secret"}},
	}
	g = GuardEnforcementConfig(block)
	if g.RateLimit == nil || g.RateLimit.PerMinute != 10 {
		t.Errorf("rateLimit = %+v, want the numbers in block mode", g.RateLimit)
	}
	if g.RateLimitObserve != nil {
		t.Error("block must not also set rateLimitObserve; the two are exclusive")
	}
	if g.DLPBlock == nil || g.DLPRedact == nil {
		t.Error("block sets both dlpBlock and dlpRedact")
	}
	if g.Ghost == nil {
		t.Error("ghost on with patterns must be delivered")
	}

	// The whole point of the pointers: an off project sends nulls, and the key
	// must be PRESENT. sgshared.PolicyCache distinguishes a null security block
	// from an absent one, and so does the guard.
	off := SecurityLayers{RateLimit: RateLimitLayer{Mode: LayerOff}, DLP: DLPLayer{Mode: LayerOff}, Ghost: GhostLayer{Mode: "off"}}
	b, err := json.Marshal(GuardEnforcementConfig(off))
	if err != nil {
		t.Fatal(err)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"rateLimit", "rateLimitObserve", "dlpBlock", "dlpRedact", "ghost"} {
		v, ok := probe[key]
		if !ok {
			t.Errorf("%q is missing from the security block; it must be present and null", key)
			continue
		}
		if string(v) != "null" {
			t.Errorf("%q = %s, want null", key, v)
		}
	}
}

func TestISOMatchesToISOString(t *testing.T) {
	// drizzle stores seconds and JSON.stringify writes a Date as this shape,
	// milliseconds included. A bare integer here lands every dashboard
	// timestamp in 1970.
	if got := ISO(1_700_000_000); got != "2023-11-14T22:13:20.000Z" {
		t.Errorf("ISO = %q, want 2023-11-14T22:13:20.000Z", got)
	}
	if got := ISOPtr(nil); got != nil {
		t.Errorf("ISOPtr(nil) = %v, want a JSON null", got)
	}
	// device_codes is the one table in milliseconds.
	if got := ISOms(1_700_000_000_123); got != "2023-11-14T22:13:20.123Z" {
		t.Errorf("ISOms = %q, want the millisecond reading", got)
	}
}

func TestClipCutsOnARuneBoundary(t *testing.T) {
	// The original slices UTF-16 code units; a byte slice here would store
	// invalid UTF-8 halfway through a character.
	if got := Clip("müşteri", 3); got != "müş" {
		t.Errorf("Clip = %q, want %q", got, "müş")
	}
	if got := Clip("abc", 10); got != "abc" {
		t.Errorf("Clip = %q, want the whole string", got)
	}
	if got := Clip("abc", 0); got != "" {
		t.Errorf("Clip = %q, want empty", got)
	}
}

func TestOrderClauseOnlyEmitsKnownColumns(t *testing.T) {
	allowed := map[string]string{"created_at": "created_at", "tool_name": "tool_name"}

	if got := orderClause("tool_name", Asc, allowed, "created_at"); got != " ORDER BY tool_name ASC" {
		t.Errorf("orderClause = %q", got)
	}
	// The injection attempt is not escaped or rejected — it simply never
	// reaches the string, because the only text that can is a map VALUE.
	got := orderClause("created_at; DROP TABLE audit_logs--", Desc, allowed, "created_at")
	if got != " ORDER BY created_at DESC" {
		t.Errorf("orderClause = %q, want the fallback column", got)
	}
	if got := orderClause("", "sideways", allowed, "created_at"); got != " ORDER BY created_at DESC" {
		t.Errorf("orderClause = %q, want an unknown direction to fall back to DESC", got)
	}
}

func TestClampLimit(t *testing.T) {
	if got := ClampLimit(0, 50, 1000); got != 50 {
		t.Errorf("ClampLimit(0) = %d, want the default", got)
	}
	if got := ClampLimit(-1, 50, 1000); got != 50 {
		t.Errorf("ClampLimit(-1) = %d, want the default", got)
	}
	if got := ClampLimit(100000, 50, 1000); got != 1000 {
		t.Errorf("ClampLimit(100000) = %d, want the ceiling", got)
	}
}

// ── the settings cache ──────────────────────────────────────────────────────
//
// The risk this cache carries is that a project turns a security layer on and
// the next request reads the old value. These tests hold the two properties
// that keep that bounded: a write drops the entry, and an entry expires.
//
// They exercise the cache directly rather than through settingRead, because
// settingRead's other half is a query and the point here is the half that
// answers WITHOUT one.

func TestSettingCacheServesAndExpires(t *testing.T) {
	s := &Store{}
	key := scopedKey(settingSecurityLayers, "proj-1")

	if _, _, fresh := s.settingCached(key); fresh {
		t.Fatal("an empty cache reported a fresh entry")
	}

	s.settingRemember(key, `{"dlp":{"mode":"block"}}`, true)
	v, found, fresh := s.settingCached(key)
	if !fresh || !found || v != `{"dlp":{"mode":"block"}}` {
		t.Fatalf("cached read = (%q, %v, %v), want the stored value", v, found, fresh)
	}

	// A miss is cached as a miss, and must come back as one rather than as an
	// empty hit: the callers distinguish "no row" from "empty value".
	absent := scopedKey(settingDenialWebhook, "proj-1")
	s.settingRemember(absent, "", false)
	if v, found, fresh := s.settingCached(absent); !fresh || found || v != "" {
		t.Errorf("cached miss = (%q, %v, %v), want a fresh not-found", v, found, fresh)
	}

	s.settingCache[key] = settingEntry{value: "stale", found: true, loaded: time.Now().Add(-settingTTL - time.Second)}
	if _, _, fresh := s.settingCached(key); fresh {
		t.Error("an entry older than the TTL was served")
	}
}

func TestSettingForgetIsScopedToOneKey(t *testing.T) {
	s := &Store{}
	mine := scopedKey(settingSelfProtection, "proj-1")
	theirs := scopedKey(settingSelfProtection, "proj-2")
	s.settingRemember(mine, "false", true)
	s.settingRemember(theirs, "false", true)

	s.settingForget(mine)

	if _, _, fresh := s.settingCached(mine); fresh {
		t.Error("the key that was written is still being served from the cache")
	}
	if _, _, fresh := s.settingCached(theirs); !fresh {
		t.Error("writing one project's setting dropped another project's")
	}
}

func TestSettingCacheIsBounded(t *testing.T) {
	s := &Store{}
	for i := 0; i < settingCacheMax+5; i++ {
		s.settingRemember(scopedKey(settingActivePolicy, "proj-"+strconv.Itoa(i)), "p", true)
	}
	if len(s.settingCache) > settingCacheMax {
		t.Errorf("cache holds %d entries, past its own cap of %d", len(s.settingCache), settingCacheMax)
	}
}
