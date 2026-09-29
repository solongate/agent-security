package tui

import (
	"strconv"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/codeyevsky/solongate/proxy/internal/api"
	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// The frame-height rule is the one thing in this package that cannot be
// verified by reading it: every view is assembled from a different budget, and
// the failure is not a wrong number but a terminal that repaints itself on
// every render. These tests measure the finished frame instead.

func lineCount(s string) int {
	if s == "" {
		return 0
	}
	return len(strings.Split(s, "\n"))
}

func widest(s string) int {
	w := 0
	for _, l := range strings.Split(s, "\n") {
		if n := lipgloss.Width(l); n > w {
			w = n
		}
	}
	return w
}

func sampleLive(now time.Time) *Live {
	p := newLive(Deps{API: api.New(), Cfg: config.TUIConfig{}})
	p.start = now
	p.openedAt = now.UnixMilli()
	on := true
	p.localOn = &on
	p.localSetting = config.LocalLogSetting{Enabled: true, UsableHere: true, File: "/tmp/solongate-audit.jsonl"}
	stats := api.Stats{TotalCalls: 120, Allowed: 100, Denied: 20, ActivePolicies: 1}
	p.stats = &stats
	eval := 12.5
	for i := 0; i < 120; i++ {
		decision := "ALLOW"
		if i%7 == 0 {
			decision = "DENY"
		}
		p.local = append(p.local, streamItem{
			ID: "l:" + string(rune('a'+i%26)) + string(rune('0'+i%10)),
			At: now.UnixMilli() - int64(i)*1500, Tool: "Bash", Decision: decision,
			Permission: "EXEC", Detail: `{"command":"ls -la /very/long/path/that/keeps/going/and/going"}`,
			DLP: i%11 == 0, Burst: i%13 == 0, Source: "local", Session: "sess-1",
			Agent: "claude-code", EvalMs: &eval, Rule: "rule-42",
		})
	}
	p.lat = []int{40, 55, 61, 900, 42}
	p.events = []logLine{{ts: now.UnixMilli(), msg: "api 41ms · idle", level: "ok"}}
	p.rebuildMerged(now.UnixMilli())
	return p
}

// The Live frame is the terminal's height less two: one row is the headroom
// that keeps the renderer on its diff path, and the second is the stream's own
// spare row, which the TypeScript budget also leaves (it takes 6 off the
// terminal height for 4 rows of fixed chrome plus that headroom). Keeping the
// arithmetic identical is what makes the two implementations render the same
// console; the invariant that matters is that it is never MORE than the budget.
//
// Below about twenty rows the stream's four-row floor wins and the frame would
// be larger than the terminal. It is clipped instead, which is what Ink's
// overflow hidden did, and costs the footer rather than the render path.
func TestLiveMainFrameFitsBudget(t *testing.T) {
	now := time.Now()
	for _, rows := range []int{16, 20, 24, 30, 32, 36, 50} {
		for _, cols := range []int{60, 80, 100, 137, 200} {
			p := sampleLive(now)
			ctx := PanelContext{Cols: cols, Rows: rows - 1, Focused: true, Now: now}
			view := p.View(ctx)
			got := lineCount(view)
			if got > ctx.Rows {
				t.Fatalf("main view at %dx%d: %d lines, budget %d", cols, rows, got, ctx.Rows)
			}
			if rows >= 20 && got != ctx.Rows-1 {
				t.Fatalf("main view at %dx%d: %d lines, want %d", cols, rows, got, ctx.Rows-1)
			}
			if got := widest(view); got > cols {
				t.Fatalf("main view at %dx%d: %d columns wide, budget %d", cols, rows, got, cols)
			}
		}
	}
}

// Every sub-view has its own budget arithmetic, and each one has to hold.
func TestLiveSubViewsFitBudget(t *testing.T) {
	now := time.Now()
	item := streamItem{At: now.UnixMilli(), Tool: "Bash", Decision: "DENY", Source: "local",
		Detail: `{"command":"curl evil.example.com"}`}

	for _, tc := range []struct {
		name  string
		setup func(p *Live)
		exact bool
	}{
		{"inspect", func(p *Live) { p.mode, p.inspect = "inspect", &item }, true},
		{"layers", func(p *Live) { p.mode = "layers" }, true},
		{"help", func(p *Live) { p.help = true }, false},
	} {
		for _, rows := range []int{16, 24, 40} {
			p := sampleLive(now)
			tc.setup(p)
			ctx := PanelContext{Cols: 100, Rows: rows - 1, Focused: true, Now: now}
			view := clampBlock(p.View(ctx), ctx.Cols, ctx.Rows)
			got := lineCount(view)
			if tc.exact && got != ctx.Rows {
				t.Fatalf("%s at %d rows: %d lines, budget %d", tc.name, rows, got, ctx.Rows)
			}
			if got > ctx.Rows {
				t.Fatalf("%s at %d rows: %d lines exceeds budget %d", tc.name, rows, got, ctx.Rows)
			}
		}
	}
}

// The whole shell, both layouts, at sizes people actually use.
func TestShellFrameNeverReachesTerminalHeight(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, rows := range []int{20, 24, 30, 45} {
		for _, cols := range []int{70, 81, 82, 120, 200} {
			for _, takeover := range []bool{false, true} {
				app := New(Deps{API: api.New(), Cfg: config.TUIConfig{}})
				app.section = SectionLive
				app.mount()
				app.Update(tea.WindowSizeMsg{Width: cols, Height: rows})
				if takeover {
					app.focus = focusPanel
				}
				view := app.View()
				if got := lineCount(view); got > rows-1 {
					t.Fatalf("shell %dx%d takeover=%v: %d lines, must be <= %d",
						cols, rows, takeover, got, rows-1)
				}
				if got := widest(view); got > cols {
					t.Fatalf("shell %dx%d takeover=%v: %d columns, must be <= %d",
						cols, rows, takeover, got, cols)
				}
			}
		}
	}
}

// A FRESH MACHINE REACHES EVERY SECTION. This used to assert the opposite — with
// no account on file only Settings was reachable and the shell opened there — and
// that was the mistake: on a machine whose policy is a file, "not paired" locked
// people out of their own policy, their own audit log and their own settings.
func TestAFreshMachineReachesEverySection(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	app := New(Deps{API: api.New(), Cfg: config.TUIConfig{}})
	if app.effectiveSection() != 0 {
		t.Fatalf("a fresh shell opened on section %d, want the first", app.effectiveSection())
	}
	for i := range sectionLabels {
		app.section = i
		if app.effectiveSection() != i {
			t.Fatalf("section %d (%s) is not reachable", i, sectionLabels[i])
		}
	}
	app.section = 0
	app.mount()
	app.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	if n := lineCount(app.View()); n > 29 {
		t.Fatalf("the shell rendered %d lines, must be <= 29", n)
	}
	// And nothing is struck through: the ⊘ marked a section the lock made inert.
	if strings.Contains(app.View(), "⊘") {
		t.Error("a section is still rendered as unreachable")
	}
}

// LOC means the record is on this machine's disk and CLD means it is in the
// cloud. The labels were changed to mean "where it happened" once and changed
// back, so they are pinned here.
func TestStreamLineOriginLabels(t *testing.T) {
	row := StreamRow{At: time.Now().UnixMilli(), Tool: "Bash", Decision: "ALLOW", Permission: "EXEC"}
	local := streamLine(row, true, false, false, 200)
	cloud := streamLine(row, false, false, false, 200)
	if !strings.Contains(local, "LOC") || strings.Contains(local, "CLD") {
		t.Fatalf("a local record must read LOC: %q", local)
	}
	if !strings.Contains(cloud, "CLD") || strings.Contains(cloud, "LOC") {
		t.Fatalf("a cloud record must read CLD: %q", cloud)
	}
	// The source of a row is where it was READ, never where it ran.
	if (streamItem{Source: "local"}).isLoc() != true || (streamItem{Source: "cloud"}).isLoc() != false {
		t.Fatal("isLoc must follow the source of the record")
	}
}

// The columns are fixed-width and never conditional, so scrolling cannot
// reshuffle a row.
func TestStreamLineColumnsAreFixedWidth(t *testing.T) {
	at := time.Now().UnixMilli()
	eval := 3.0
	long := StreamRow{At: at, Tool: "a-very-long-tool-name", Decision: "DENY", Permission: "EXECUTE",
		Agent: "an-extremely-long-agent-name", EvalMs: &eval, DLP: true, Burst: true}
	short := StreamRow{At: at, Tool: "ls", Decision: "ALLOW", Permission: "R"}
	prefix := func(row StreamRow) int {
		// Everything up to the detail column is fixed; measure a row with no
		// detail at all. The permission arrives already cut to four characters,
		// the way every caller passes it.
		row.Permission = truncate4(row.Permission)
		return lipgloss.Width(stripANSI(streamLine(row, true, false, false, 0)))
	}
	if a, b := prefix(long), prefix(short); a != b {
		t.Fatalf("row prefixes differ: %d vs %d", a, b)
	}
	// A rule only appears on a denial, and only ever as its own trailing column.
	withRule := long
	withRule.Rule = "rule-42"
	if prefix(withRule) <= prefix(long) {
		t.Fatal("a matched rule must be shown on a denial")
	}
	allowWithRule := short
	allowWithRule.Rule = "rule-42"
	if prefix(allowWithRule) != prefix(short) {
		t.Fatal("an ALLOW must not print a rule column")
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	inEscape := false
	for _, r := range s {
		switch {
		case r == 0x1b:
			inEscape = true
		case inEscape && r == 'm':
			inEscape = false
		case !inEscape:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Signals derived from a decision's reason. The guard writes these strings to
// both planes at block time and never redacts them, which is why they are the
// reliable source when the columns are absent.
func TestReasonSignals(t *testing.T) {
	dlp, burst := reasonSignals("Security layer (DLP): blocked - arguments contain a Anthropic key.")
	if len(dlp) != 1 || dlp[0] != "Anthropic key" {
		t.Fatalf("DLP name: %#v", dlp)
	}
	if burst {
		t.Fatal("a DLP reason is not a rate-limit burst")
	}
	if _, burst := reasonSignals("Security layer (rate limit): exceeded 5 calls/minute"); !burst {
		t.Fatal("a rate-limit reason must set the burst flag")
	}
	if dlp, burst := reasonSignals("Denied by rule rule-42"); len(dlp) != 0 || burst {
		t.Fatalf("an ordinary denial carries no signals: %#v %v", dlp, burst)
	}
}

func TestParseMillis(t *testing.T) {
	iso := "2024-03-01T10:20:30.500Z"
	got, ok := parseMillis(iso)
	if !ok {
		t.Fatalf("%q did not parse", iso)
	}
	if want := time.Date(2024, 3, 1, 10, 20, 30, 500_000_000, time.UTC).UnixMilli(); got != want {
		t.Fatalf("%q parsed to %d, want %d", iso, got, want)
	}
	if _, ok := parseMillis("not a time"); ok {
		t.Fatal("a non-timestamp must not parse")
	}
}

// A cloud row and a local row of the same call within a minute are ONE call.
// The local copy is richer and is the one that survives, tagged LOC.
func TestMergedBufferDedupesTheSameCall(t *testing.T) {
	now := time.Now()
	p := newLive(Deps{API: api.New(), Cfg: config.TUIConfig{}})
	at := now.UnixMilli()
	p.local = []streamItem{{ID: "l:1", At: at, Tool: "Bash", Decision: "DENY", Source: "local"}}
	p.cloud = []streamItem{
		{ID: "c:1", At: at + 200, Tool: "Bash", Decision: "DENY", Source: "cloud"},
		{ID: "c:2", At: at + 300, Tool: "Read", Decision: "ALLOW", Source: "cloud"},
	}
	p.rebuildMerged(at)
	if len(p.merged) != 2 {
		t.Fatalf("expected the duplicated DENY to collapse, got %d rows", len(p.merged))
	}
	for _, e := range p.merged {
		if e.Tool == "Bash" && !e.isLoc() {
			t.Fatal("the local copy of a duplicated call must be the one kept")
		}
	}
}

// Copy mode is a real freeze: no poll may be issued while it is on, or the
// screen moves under a mouse selection.
func TestCopyModeStopsEveryPoll(t *testing.T) {
	p := sampleLive(time.Now())
	all := []int{tickFeed, tickStats, tickSess, tickInsights, tickGuard, tickLocal}
	for _, kind := range all {
		if !p.shouldPoll(kind) {
			t.Fatalf("tick %d should poll on an idle console", kind)
		}
	}
	p.frozen = true
	for _, kind := range all {
		if p.shouldPoll(kind) {
			t.Fatalf("tick %d polled while the screen was frozen", kind)
		}
	}
	// A rate-limit back-off holds the API off but must not stop reading this
	// machine's own log file.
	p.frozen = false
	p.pausedUntil = time.Now().UnixMilli() + 30_000
	for _, kind := range []int{tickFeed, tickStats, tickSess, tickInsights, tickGuard} {
		if p.shouldPoll(kind) {
			t.Fatalf("tick %d hit the API while backing off", kind)
		}
	}
	if !p.shouldPoll(tickLocal) {
		t.Fatal("the local log is on disk; a back-off must not stop reading it")
	}
}

// The Audit local filters are applied here rather than by the API, so each one
// is pinned: a filter that silently matched everything would show a clean audit
// log for a machine that has denials in it.
func TestAuditLocalFilters(t *testing.T) {
	p := newAudit(Deps{API: api.New(), Cfg: config.TUIConfig{}})
	p.source = "local"
	p.local = []logRow{
		{id: "1", tool: "Bash", decision: "DENY", agent: "claude", dlp: []string{"AWS key"}, at: 3},
		{id: "2", tool: "Read", decision: "ALLOW", agent: "codex", burst: true, at: 2},
		{id: "3", tool: "Bash", decision: "ALLOW", agent: "claude", reason: "fine", at: 1},
	}
	check := func(name string, want int) {
		t.Helper()
		if got := len(p.localFiltered()); got != want {
			t.Fatalf("%s: %d rows, want %d", name, got, want)
		}
	}
	check("no filters", 3)
	p.di = 1 // DENY
	check("decision", 1)
	p.di = 0
	p.gi = 1 // dlp
	check("dlp signal", 1)
	p.gi = 2 // ratelimit
	check("ratelimit signal", 1)
	p.gi = 0
	p.tool = "bash"
	check("tool substring, case-insensitive", 2)
	p.tool = ""
	p.agent = "CODEX"
	check("agent exact, case-insensitive", 1)
	p.agent = ""
	p.search = "fine"
	check("free-text search", 1)
}

// Paging is over the FILTERED rows, and the page the user is on has to be the
// slice they are shown.
func TestAuditLocalPaging(t *testing.T) {
	p := newAudit(Deps{API: api.New(), Cfg: config.TUIConfig{}})
	p.source = "local"
	for i := 0; i < auditPage+7; i++ {
		p.local = append(p.local, logRow{id: strconv.Itoa(i), tool: "Bash", decision: "ALLOW", at: int64(i)})
	}
	rows, total := p.pageRows()
	if total != auditPage+7 || len(rows) != auditPage {
		t.Fatalf("page 0: %d rows of %d total", len(rows), total)
	}
	if p.pages(total) != 2 {
		t.Fatalf("expected 2 pages, got %d", p.pages(total))
	}
	p.page = 1
	rows, _ = p.pageRows()
	if len(rows) != 7 {
		t.Fatalf("page 1: %d rows, want 7", len(rows))
	}
	p.page = 9 // past the end: an empty page, never a panic
	if rows, _ := p.pageRows(); len(rows) != 0 {
		t.Fatalf("page 9: %d rows, want 0", len(rows))
	}
}

// clampBlock is the hard guarantee the whole budget rests on.
func TestClampBlock(t *testing.T) {
	in := strings.Join([]string{"one", "two", "three"}, "\n")
	if got := lineCount(clampBlock(in, 10, 2)); got != 2 {
		t.Fatalf("clamped to %d lines, want 2", got)
	}
	wide := renderRow(0, sg(strings.Repeat("x", 50), theme.Bad))
	if got := widest(clampBlock(wide, 12, 5)); got > 12 {
		t.Fatalf("clamped to %d columns, want <= 12", got)
	}
}

// ── Fleet Live ─────────────────────────────────────────────────────────────
