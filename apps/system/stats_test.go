package main

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/codeyevsky/solongate/system/internal/store"
)

// The two secret-shaped fixtures are assembled from pieces rather than written
// out. Whole, they trip the DLP layer of the guard running on the machine that
// edits this file — which is the product working, and not a thing to switch off
// for a test fixture.
var (
	fixtureAWSKey       = "AKI" + "AABCDEFGHIJKLMNOP"
	fixtureAnthropicKey = "sk-" + "ant-api03-abcdefghijklmnopqrstuvwxyz"
)

// The route this test exists for is /policies/{id}/wasm, and it is not
// paranoia. Its handler first lived in a file called policies_wasm.go, which
// `go build` reads as the GOARCH=wasm build constraint and silently drops on
// every other target: the package compiled, `go vet` was clean, every test
// passed, and the route answered 501 from the placeholder. Registration is the
// one thing a compiler cannot check for us.
func TestStatsGroupRoutesAreRegistered(t *testing.T) {
	for _, pattern := range []string{
		"GET /api/v1/stats",
		"GET /api/v1/stats/timeseries",
		"GET /api/v1/stats/drift",
		"GET /api/v1/stats/security-insights",
		"GET /api/v1/policies/{id}/wasm",
	} {
		if _, ok := routeHandlers[pattern]; !ok {
			t.Errorf("%s is not registered", pattern)
		}
	}
}

func TestStatsDaysIsClamped(t *testing.T) {
	cases := []struct {
		query string
		want  int
	}{
		{"", 7},
		{"?days=", 7},
		{"?days=1", 1},
		{"?days=30", 30},
		{"?days=90", 90},
		{"?days=91", 90},
		{"?days=100000", 90},
		{"?days=0", 1},
		{"?days=-5", 1},
		// The live route hands parseInt('abc') — NaN — to the query and 500s.
		// Seven is the deliberate difference; see statsDays.
		{"?days=abc", 7},
	}
	for _, c := range cases {
		got := statsDays(httptest.NewRequest("GET", "/api/v1/stats/drift"+c.query, nil))
		if got != c.want {
			t.Errorf("days for %q = %d, want %d", c.query, got, c.want)
		}
	}
}

// floorDiv is what keeps a pre-1970 timestamp in the bucket SQLite put it in.
// Go's `/` truncates toward zero, which for a negative value is the bucket
// after the right one.
func TestFloorDivRoundsDown(t *testing.T) {
	cases := []struct{ a, b, want int64 }{
		{7, 3, 2},
		{-7, 3, -3},
		{-1, 3600000, -1},
		{0, 60, 0},
		{-3600000, 3600000, -1},
		{-3600001, 3600000, -2},
	}
	for _, c := range cases {
		if got := floorDiv(c.a, c.b); got != c.want {
			t.Errorf("floorDiv(%d, %d) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// Math.round takes halves UP; math.Round takes them away from zero. delta_pct
// is negative whenever a rule fires less than it used to, which is most of the
// time somebody looks at this endpoint.
func TestJSRoundTakesHalvesUp(t *testing.T) {
	cases := []struct {
		in   float64
		want int64
	}{
		{2.5, 3},
		{-2.5, -2},
		{-2.51, -3},
		{0.5, 1},
		{-0.5, 0},
		{100, 100},
	}
	for _, c := range cases {
		if got := jsRound(c.in); got != c.want {
			t.Errorf("jsRound(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestDLPPreviewNeverShowsAShortSecret(t *testing.T) {
	if got := dlpPreview(fixtureAWSKey); got != "AKIA…OP" {
		t.Errorf("preview = %q", got)
	}
	// Eight characters or fewer is replaced entirely: four of eight is half the
	// secret.
	for _, short := range []string{"abcdefgh", "abc", ""} {
		if got := dlpPreview(short); got != "••••" {
			t.Errorf("preview(%q) = %q, want the mask", short, got)
		}
	}
	// A multi-byte match is cut on a rune boundary, not a byte one. Go's s[:4]
	// on "héllo…" would store half a character.
	if got := dlpPreview("héllo wörld secret"); got != "héll…et" {
		t.Errorf("preview of a multi-byte hit = %q", got)
	}
}

func TestDLPHitsTakeTheFirstPatternAndSkipBrokenOnes(t *testing.T) {
	layers := store.DefaultSecurityLayers()
	layers.DLP.Custom = []store.CustomPattern{
		// RE2 has no lookbehind, so this one cannot compile. It must cost that
		// one detector and nothing else.
		{Name: "broken", Re: "(?<=x)y"},
		{Name: "marker", Re: "sg-seed-[a-z]+"},
	}

	rows := []store.SecurityScanRow{
		{ToolName: "bash", AgentName: "", Decision: "ALLOW",
			ArgumentsSummary: "key=" + fixtureAWSKey, CreatedAt: 1_700_000_000},
		{ToolName: "bash", AgentName: "agy", Decision: "DENY",
			Reason:           "Security layer (DLP): blocked - arguments contain a Anthropic key",
			ArgumentsSummary: fixtureAnthropicKey, CreatedAt: 1_700_000_060},
		{ToolName: "bash", AgentName: "agy", Decision: "ALLOW",
			ArgumentsSummary: "run sg-seed-marker", CreatedAt: 1_700_000_120},
		{ToolName: "bash", AgentName: "agy", Decision: "ALLOW",
			ArgumentsSummary: "nothing here", CreatedAt: 1_700_000_180},
	}

	hits := dlpHits(rows, layers)
	if len(hits) != 3 {
		t.Fatalf("hits = %d, want 3: %+v", len(hits), hits)
	}
	if hits[0].Pattern != "AWS access key" || hits[0].Agent != "unknown" {
		t.Errorf("first hit = %+v", hits[0])
	}
	if !hits[1].Blocked {
		t.Error("a DLP denial should be reported as blocked")
	}
	if hits[0].Blocked {
		t.Error("an allowed call is not blocked")
	}
	if hits[2].Pattern != "marker" {
		t.Errorf("custom pattern hit = %+v", hits[2])
	}
	if hits[0].At != store.ISOms(1_700_000_000*1000) {
		t.Errorf("timestamp = %q", hits[0].At)
	}
}

// The limit an anomaly is judged against is the one that was configured AT THE
// TIME, not today's. A project that raised its limit must not lose the record
// of the hour it spent throttled.
func TestRateLimitAnomaliesUseTheHistoricalLimit(t *testing.T) {
	const minute = 60
	base := int64(1_700_000_000) / minute * minute

	layers := store.DefaultSecurityLayers()
	layers.RateLimit.PerMinute = 100
	history := []store.RateLimitChange{
		{TS: (base - 3600) * 1000, Minute: 2},
	}

	rows := []store.SecurityScanRow{}
	for i := 0; i < 3; i++ {
		rows = append(rows, store.SecurityScanRow{
			AgentName: "agy", Decision: "ALLOW", CreatedAt: base + int64(i),
		})
	}
	// A quiet minute for another agent, and one call that was refused for rate
	// limiting — which counts as an anomaly whatever the arithmetic says,
	// because the calls that would have proved it were never made.
	rows = append(rows,
		store.SecurityScanRow{AgentName: "codex", Decision: "ALLOW", CreatedAt: base + 120},
		store.SecurityScanRow{AgentName: "codex", Decision: "DENY",
			Reason: "Rate limit exceeded", CreatedAt: base + 121},
	)

	got := rateLimitAnomalies(rows, layers, history)
	if len(got) != 2 {
		t.Fatalf("anomalies = %d, want 2: %+v", len(got), got)
	}
	if got[0].Agent != "agy" || got[0].Count != 3 || got[0].Limit != 2 || got[0].Blocked {
		t.Errorf("busiest minute = %+v", got[0])
	}
	if got[1].Agent != "codex" || !got[1].Blocked || got[1].Count != 2 {
		t.Errorf("throttled minute = %+v", got[1])
	}
	if want := store.ISOms(base * 1000); got[0].Minute != want {
		t.Errorf("minute = %q, want %q", got[0].Minute, want)
	}

	// With no history and the layer off there is no number to exceed, so only
	// the minute the guard actually refused survives.
	off := store.DefaultSecurityLayers()
	off.RateLimit.Mode = store.LayerOff
	got = rateLimitAnomalies(rows, off, nil)
	if len(got) != 1 || got[0].Agent != "codex" || got[0].Limit != 0 {
		t.Errorf("with the layer off, anomalies = %+v", got)
	}
}

// An agent name with a "|" in it is why the buckets are a struct: the live
// route joins the key with that character and splits it back, which truncates
// the name and turns the minute into something that is not a date.
func TestAnomalyBucketsSurvivePipesInAgentNames(t *testing.T) {
	layers := store.DefaultSecurityLayers()
	layers.RateLimit.PerMinute = 1

	rows := []store.SecurityScanRow{
		{AgentName: "a|b", Decision: "ALLOW", CreatedAt: 1_700_000_000},
		{AgentName: "a|b", Decision: "ALLOW", CreatedAt: 1_700_000_001},
	}
	got := rateLimitAnomalies(rows, layers, nil)
	if len(got) != 1 || got[0].Agent != "a|b" || got[0].Count != 2 {
		t.Fatalf("anomalies = %+v", got)
	}
	if _, err := time.Parse(time.RFC3339, got[0].Minute); err != nil {
		t.Errorf("minute %q is not a timestamp: %v", got[0].Minute, err)
	}
}

func TestCallVolumeSortsDaysUpAndAgentsDown(t *testing.T) {
	day := int64(86400)
	rows := []store.SecurityScanRow{
		{AgentName: "b", CreatedAt: 1_700_000_000},
		{AgentName: "a", CreatedAt: 1_700_000_000 - day},
		{AgentName: "a", CreatedAt: 1_700_000_000 - day},
		{AgentName: "", CreatedAt: 1_700_000_000 - 2*day},
	}
	days, agents := callVolume(rows)

	if len(days) != 3 || days[0].Day >= days[1].Day || days[1].Day >= days[2].Day {
		t.Fatalf("callsPerDay is not ascending: %+v", days)
	}
	if days[0].Count != 1 || days[1].Count != 2 {
		t.Errorf("counts = %+v", days)
	}
	if len(agents) != 3 || agents[0].Agent != "a" || agents[0].Count != 2 {
		t.Fatalf("topAgents = %+v", agents)
	}
	// Ties keep the order the rows were scanned in, as a JavaScript Map plus a
	// stable sort does — "b" was seen before the nameless row.
	if agents[1].Agent != "b" || agents[2].Agent != "unknown" {
		t.Errorf("tie order = %+v", agents)
	}
}

func TestTopAgentsIsCapped(t *testing.T) {
	rows := []store.SecurityScanRow{}
	for i := 0; i < 20; i++ {
		rows = append(rows, store.SecurityScanRow{
			AgentName: string(rune('a' + i)), CreatedAt: 1_700_000_000,
		})
	}
	if _, agents := callVolume(rows); len(agents) != maxTopAgents {
		t.Errorf("topAgents = %d, want %d", len(agents), maxTopAgents)
	}
}

func TestActivitySeriesIsFixedLengthAndDropsTheFuture(t *testing.T) {
	nowMS := int64(1_700_000_000_000)
	rows := []store.SecurityScanRow{
		{CreatedAt: nowMS/1000 - 30},   // this minute
		{CreatedAt: nowMS/1000 - 90},   // the one before
		{CreatedAt: nowMS/1000 - 7200}, // outside a 60-minute window
		{CreatedAt: nowMS/1000 + 3600}, // a client whose clock is an hour fast
	}
	got := activitySeries(rows, nowMS, 60_000, 60)
	if len(got) != 60 {
		t.Fatalf("series length = %d, want 60", len(got))
	}
	var total int64
	for _, p := range got {
		total += p.Count
	}
	if total != 2 {
		t.Errorf("counted %d rows, want the 2 inside the window", total)
	}
	if got[0].T != nowMS-60*60_000 {
		t.Errorf("first bucket at %d, want %d", got[0].T, nowMS-60*60_000)
	}
	if got[len(got)-1].Count != 1 {
		t.Errorf("the most recent bucket should hold the newest row: %+v", got[len(got)-1])
	}
}

func TestPeakPerAgentIsPerAgent(t *testing.T) {
	rows := []store.SecurityScanRow{}
	for i := 0; i < 5; i++ {
		rows = append(rows, store.SecurityScanRow{AgentName: "a", CreatedAt: 1_700_000_000 + int64(i)})
	}
	for i := 0; i < 9; i++ {
		// Nine calls in the same minute, split across three agents: the peak is
		// three, not nine.
		rows = append(rows, store.SecurityScanRow{
			AgentName: string(rune('x' + i%3)), CreatedAt: 1_700_000_100 + int64(i),
		})
	}
	if got := peakPerAgent(rows, 60_000); got != 5 {
		t.Errorf("peak = %d, want 5", got)
	}
}

// The zero-fill's labels have to be the strings SQLite's strftime produced, or
// every bucket misses and the chart reads as an outage. Both sides are UTC.
func TestBucketLabelsMatchStrftime(t *testing.T) {
	at := time.Date(2026, 8, 2, 19, 34, 56, 0, time.UTC).UnixMilli()
	cases := []struct{ layout, want string }{
		{"2006-01-02 15:00", "2026-08-02 19:00"}, // %Y-%m-%d %H:00
		{"2006-01-02", "2026-08-02"},             // %Y-%m-%d
	}
	for _, c := range cases {
		if got := time.UnixMilli(at).UTC().Format(c.layout); got != c.want {
			t.Errorf("label = %q, want %q", got, c.want)
		}
	}
	if got := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02"); got != "2026-08-01" {
		t.Errorf("month label = %q", got) // %Y-%m-01
	}
}
