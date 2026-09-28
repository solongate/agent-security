package panels

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/codeyevsky/solongate/proxy/internal/api"
	"github.com/codeyevsky/solongate/proxy/internal/commands"
	"github.com/codeyevsky/solongate/proxy/internal/config"
	"github.com/codeyevsky/solongate/proxy/internal/install"
	"github.com/codeyevsky/solongate/proxy/internal/tui"
)

func testDeps() tui.Deps { return tui.Deps{API: api.New()} }

func ctxOf(cols, rows int) tui.PanelContext {
	return tui.PanelContext{Deps: testDeps(), Cols: cols, Rows: rows, Focused: true}
}

// Every panel promises to render inside the box the shell gave it. This is the
// frame-height rule as a test rather than as a comment: one line too many and
// Bubble Tea abandons its diff and repaints the terminal on every keystroke.
// A panel that has loaded data still has to fit. The Rate Limit panel is the
// one whose budget arithmetic is hand-rolled per section, so it is the one worth
// filling up.
func TestRateLimitFitsWithData(t *testing.T) {
	p := NewRateLimit(testDeps())
	p.hasDraft, p.haveSrv = true, true
	p.draft.RateLimit.Mode = api.LayerBlock
	p.draft.RateLimit.PerMinute = 20
	for i := 0; i < 40; i++ {
		p.insights.Anomalies = append(p.insights.Anomalies, rlAnomaly{
			Agent: "claude-code-very-long-agent-name", Minute: "2026-08-01T10:0" + itoa(i%10) + ":00Z",
			Count: 30 + i, Limit: 20, Blocked: i%2 == 0,
		})
	}
	for _, rows := range []int{8, 12, 20, 30} {
		ctx := ctxOf(70, rows)
		lines := strings.Split(p.View(ctx), "\n")
		if len(lines) > rows {
			t.Fatalf("rate limit with data at %d rows: %d lines", rows, len(lines))
		}
	}
}

// Settings is the panel that grows: every account and workspace is a row, and
// the doctor result adds unselectable lines under one of them. It still has to
// fit, and the selected row still has to be inside the window.
func TestSettingsFitsWithData(t *testing.T) {
	p := NewSettings(testDeps())
	p.accounts = []config.SavedAccount{
		{APIKey: "sg_live_" + strings.Repeat("a", 32), Email: "someone@example.com", Project: "prod"},
		{APIKey: "sg_live_" + strings.Repeat("b", 32), Email: "other@example.com", Project: "staging"},
	}
	// The workspaces this account owns are rows too, and they are the newest
	// thing on the panel: a frame that outgrows its budget makes this TUI
	// repaint the whole terminal on every render.
	p.haveSpace = true
	p.spaces = []api.Workspace{{ID: "p1", Name: "prod"}, {ID: "p2", Name: "staging"}}
	p.spaceNow = "p1"
	p.haveLocal, p.local = true, api.LocalLogsConfig{Enabled: true, Path: "/var/log/solongate"}
	p.haveGuard, p.haveSelf = true, true
	p.diag = []commands.Check{{Name: "login", OK: commands.StateOK, Detail: "paired"}}
	// The repair result too: it adds a dozen rows under one row, and a frame
	// that outgrows its budget makes this TUI repaint the whole terminal on
	// every render. The height has to be checked with them present, not just
	// with the panel at rest.
	p.repairReport = &install.Report{
		OK: true, Message: "guard repaired.",
		Before: []install.ReportLine{
			{Label: "guard hook file", OK: true, Detail: "present"},
			{Label: "cloud credential", OK: true, Detail: "present"},
			{Label: "Claude hooks", OK: true, Detail: "guard registered"},
			{Label: "Antigravity hooks", OK: true, Detail: "guard registered"},
			{Label: "Codex hooks", OK: true, Detail: "guard registered"},
			{Label: "OpenCode hooks", OK: true, Detail: "guard registered"},
		},
		After: []install.ReportLine{
			{Label: "guard hook file", OK: true, Detail: "present (v80)"},
			{Label: "Claude hooks", OK: true, Detail: "guard registered"},
			{Label: "Antigravity hooks", OK: true, Detail: "guard registered"},
			{Label: "Codex hooks", OK: true, Detail: "guard registered"},
			{Label: "OpenCode hooks", OK: true, Detail: "guard registered"},
		},
		Notes: []string{"swept 2 stray scratch folders"},
	}

	for _, rows := range []int{8, 14, 24} {
		ctx := ctxOf(90, rows)
		p.sel = 0
		for i := 0; i < len(p.allRows()); i++ {
			p.sel = i
			lines := strings.Split(p.View(ctx), "\n")
			if len(lines) > rows {
				t.Fatalf("settings at %d rows with cursor %d: %d lines", rows, i, len(lines))
			}
		}
	}
}

// ── the rule model ─────────────────────────────────────────────────────────

// An untouched rule must go back to the API byte for byte. The wire rule
// carries fields this version does not model, and a policy edited from the
// terminal must not come back narrower than it went in.
func TestUneditedRuleKeepsItsBytes(t *testing.T) {
	raw := json.RawMessage(`{"id":"r1","effect":"DENY","priority":10,"toolPattern":"*","enabled":true,` +
		`"commandConstraints":{"denied":["rm*"]},"somethingNewer":{"x":1}}`)
	var rule api.PolicyRule
	if err := json.Unmarshal(raw, &rule); err != nil {
		t.Fatal(err)
	}
	got, err := ruleDoc{rule: rule, raw: raw}.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("unedited rule was rewritten:\n have %s\n want %s", got, raw)
	}
}

// An EDITED rule is merged into its original object rather than replacing it,
// so the same unknown field survives the edit.
func TestEditedRuleMergesIntoItsOriginal(t *testing.T) {
	raw := json.RawMessage(`{"id":"r1","effect":"DENY","priority":10,"toolPattern":"*","enabled":true,` +
		`"minimumTrustLevel":"UNTRUSTED","commandConstraints":{"denied":["rm*"]},"somethingNewer":{"x":1}}`)
	var rule api.PolicyRule
	if err := json.Unmarshal(raw, &rule); err != nil {
		t.Fatal(err)
	}
	rule.Description = "no destructive shell"
	got, err := ruleDoc{rule: rule, raw: raw, edited: true}.marshal()
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatal(err)
	}
	if obj["description"] != "no destructive shell" {
		t.Errorf("edit not applied: %v", obj["description"])
	}
	if _, ok := obj["somethingNewer"]; !ok {
		t.Errorf("unknown field dropped by the merge: %s", got)
	}
}

// "Any permission" is the ABSENCE of the field. Writing null there compiles to a
// rule that matches nothing, which is the opposite of what the four ticked
// boxes mean.
func TestAnyPermissionIsWrittenAsAbsent(t *testing.T) {
	r := api.PolicyRule{Effect: "DENY", Permission: json.RawMessage(`["READ"]`)}
	for _, p := range []string{"WRITE", "EXECUTE", "NETWORK"} {
		togglePerm(&r, p)
	}
	if r.Permission != nil {
		t.Fatalf("all four should collapse to no field, got %s", r.Permission)
	}
	doc := ruleDoc{rule: r, raw: json.RawMessage(`{"permission":["READ"]}`), edited: true}
	b, err := doc.marshal()
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatal(err)
	}
	if _, ok := obj["permission"]; ok {
		t.Fatalf("permission should be absent, got %s", b)
	}
}

// Unticking the last box cannot leave a rule with no permission: a rule that
// matches no permission at all matches nothing.
func TestPermissionListNeverEmpties(t *testing.T) {
	r := api.PolicyRule{Effect: "DENY", Permission: json.RawMessage(`["READ"]`)}
	togglePerm(&r, "READ")
	if got := permListOf(r); len(got) != 1 || got[0] != "READ" {
		t.Fatalf("expected READ to survive, got %v", got)
	}
}

// Flipping the effect moves the values to the other side, so an ALLOW rule
// turned into a DENY denies what it used to allow instead of silently becoming
// an empty rule.
func TestEffectFlipMovesTheValues(t *testing.T) {
	r := api.PolicyRule{Effect: "DENY", CommandConstraints: &api.Constraint{Denied: []string{"rm*", "curl*"}}}
	migrateEffect(&r, "ALLOW")
	if r.CommandConstraints == nil || len(r.CommandConstraints.Allowed) != 2 || len(r.CommandConstraints.Denied) != 0 {
		t.Fatalf("values did not move to allowed: %+v", r.CommandConstraints)
	}
	migrateEffect(&r, "DENY")
	if len(r.CommandConstraints.Denied) != 2 || len(r.CommandConstraints.Allowed) != 0 {
		t.Fatalf("values did not move back to denied: %+v", r.CommandConstraints)
	}
}

// Selecting a constraint type clears the others: a rule carries exactly one.
func TestOneConstraintTypeAtATime(t *testing.T) {
	r := api.PolicyRule{Effect: "DENY", CommandConstraints: &api.Constraint{Denied: []string{"rm*"}}}
	setCType(&r, cPath)
	if r.CommandConstraints != nil {
		t.Errorf("command constraint survived the switch")
	}
	if r.PathConstraints == nil {
		t.Errorf("path constraint not created")
	}
	if got := currentCType(r); got != cPath {
		t.Errorf("currentCType = %q", got)
	}
}

func TestFlipStar(t *testing.T) {
	cases := [][3]string{
		{"rm", "right", "rm*"},
		{"rm*", "right", "rm"},
		{"env", "left", "*env"},
		{"*env", "left", "env"},
	}
	for _, c := range cases {
		if got := flipStar(c[0], c[1]); got != c[2] {
			t.Errorf("flipStar(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}

// A rule with no values and every permission matches EVERY request. The
// dashboard refuses to save one and so does this.
func TestBlanketRuleIsRefusedOnSave(t *testing.T) {
	p := policiesWithRules(api.PolicyRule{ID: "r1", Effect: "DENY", Enabled: true,
		CommandConstraints: &api.Constraint{}})
	if cmd := p.save(); cmd != nil {
		t.Fatalf("save should not have been issued")
	}
	if !strings.HasPrefix(p.status, "✗ rule 1 matches EVERYTHING") {
		t.Fatalf("status was %q", p.status)
	}
}

// A rule that is narrow in EITHER direction is fine: a constraint value, or
// narrowed permissions.
func TestNarrowRuleSaves(t *testing.T) {
	p := policiesWithRules(api.PolicyRule{ID: "r1", Effect: "DENY", Enabled: true,
		CommandConstraints: &api.Constraint{Denied: []string{"rm*"}}})
	if cmd := p.save(); cmd == nil {
		t.Fatalf("save was refused: %q", p.status)
	}
	if p.status != "Saving…" {
		t.Fatalf("status was %q", p.status)
	}
}

// A policy carrying a rule this version cannot decode must not be written back:
// the rule is not in the draft, so saving would delete it while the dashboard
// still showed it as active.
func TestUnreadableRulesRefuseSave(t *testing.T) {
	p := policiesWithRules(api.PolicyRule{ID: "r1", Effect: "DENY", Enabled: true,
		CommandConstraints: &api.Constraint{Denied: []string{"rm*"}}})
	p.unreadable = 2
	if cmd := p.save(); cmd != nil {
		t.Fatalf("save should not have been issued")
	}
	if !strings.Contains(p.status, "cannot be read by this version") {
		t.Fatalf("status was %q", p.status)
	}
}

func policiesWithRules(rules ...api.PolicyRule) *Policies {
	p := NewPolicies(testDeps())
	p.policies = []api.PolicyListEntry{{ID: "pol1", Name: "test"}}
	p.detailID = "pol1"
	p.haveDetail = true
	p.detail.ID = "pol1"
	p.detail.Name = "test"
	for _, r := range rules {
		p.rules = append(p.rules, ruleDoc{rule: r, edited: true})
	}
	return p
}

// ── variants ───────────────────────────────────────────────────────────────

// A policy is a set of variants and the editor edits ONE of them at a time.
// Switching tabs has to carry the edit into the variant it was made in, or the
// second tab a person opens quietly discards the first one's work.
func TestSwitchingVariantsKeepsBothEdits(t *testing.T) {
	p := policiesWithVariants()

	p.rules[0].rule.Description = "edited base"
	p.rules[0].edited = true
	p.switchVariant(1)
	if len(p.rules) != 1 || p.rules[0].rule.ID != "c1" {
		t.Fatalf("second variant did not come out: %+v", p.rules)
	}
	p.rules[0].rule.Description = "edited contractor"
	p.rules[0].edited = true
	p.switchVariant(-1)

	if got := p.rules[0].rule.Description; got != "edited base" {
		t.Fatalf("base variant lost its edit: %q", got)
	}
	p.switchVariant(1)
	if got := p.rules[0].rule.Description; got != "edited contractor" {
		t.Fatalf("second variant lost its edit: %q", got)
	}
}

// The layers are per variant too, and they are the half that used to be a
// project-wide row: a DLP mode set on one variant must not follow the cursor to
// the next one.
func TestLayersBelongToTheirVariant(t *testing.T) {
	p := policiesWithVariants()
	p.sec.DLP.Mode = api.LayerBlock
	p.switchVariant(1)
	if p.sec.DLP.Mode == api.LayerBlock {
		t.Fatalf("the second variant inherited the first one's DLP mode")
	}
	p.switchVariant(-1)
	if p.sec.DLP.Mode != api.LayerBlock {
		t.Fatalf("the first variant lost its DLP mode: %q", p.sec.DLP.Mode)
	}
}

// Saving sends the whole bundle. A save that sent only the visible variant
// would delete every other one from the policy — and the top level has to carry
// the first variant's rules as well, because three readers in the field take
// only $.rules.
func TestSaveCarriesEveryVariant(t *testing.T) {
	p := policiesWithVariants()
	body, ok := p.saveBody()
	if !ok {
		t.Fatalf("save refused: %q", p.status)
	}
	if len(body.Variants) != 2 {
		t.Fatalf("sent %d variants, want 2", len(body.Variants))
	}
	if body.DefaultVariant != body.Variants[0].ID {
		t.Fatalf("defaultVariant %q is not the first variant %q", body.DefaultVariant, body.Variants[0].ID)
	}
	top, err := body.Rules.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	first, err := body.Variants[0].Rules.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(top) != string(first) {
		t.Fatalf("top-level rules are not the first variant's:\n%s\n%s", top, first)
	}
	if body.Variants[0].Security == nil || body.Variants[1].Security == nil {
		t.Fatal("a variant went out with no layers")
	}
}

// A blanket rule is refused wherever it is, not only on the tab being looked at.
func TestABlanketRuleInAnotherVariantIsRefused(t *testing.T) {
	p := policiesWithVariants()
	p.variants[1].rules = []ruleDoc{{rule: api.PolicyRule{
		ID: "c1", Effect: "DENY", Enabled: true, CommandConstraints: &api.Constraint{},
	}, edited: true}}
	if cmd := p.save(); cmd != nil {
		t.Fatal("save should not have been issued")
	}
	if !strings.Contains(p.status, "Contractors") {
		t.Fatalf("the refusal does not say which variant: %q", p.status)
	}
}

// A policy that predates variants opens as exactly one, holding the rules it
// had and the layers the project has been enforcing — so opening it and saving
// it back describes the same enforcement it described before.
func TestAnOldPolicyBecomesOneVariant(t *testing.T) {
	p := NewPolicies(testDeps())
	p.fallback.DLP.Mode = api.LayerBlock
	p.fallback.DLP.Patterns = []string{"aws"}
	p.adoptPolicy(api.PolicySet{
		ID: "pol1", Name: "old",
		Rules: api.Rules{Items: []api.PolicyRule{{ID: "r1", Effect: "DENY"}}},
	})
	if len(p.variants) != 1 {
		t.Fatalf("got %d variants, want 1", len(p.variants))
	}
	if p.variants[0].name != "Base" {
		t.Fatalf("the one variant is called %q", p.variants[0].name)
	}
	if len(p.rules) != 1 {
		t.Fatalf("the rules did not come through: %+v", p.rules)
	}
	if p.sec.DLP.Mode != api.LayerBlock || len(p.sec.DLP.Patterns) != 1 {
		t.Fatalf("the project's layers were not inherited: %+v", p.sec.DLP)
	}
}

// Adding a variant copies the one on screen, and the copy must not carry the
// original's BYTES: two variants handing the server the same rule object is how
// one edit lands in both.
func TestANewVariantIsACopyWithItsOwnRules(t *testing.T) {
	p := policiesWithVariants()
	p.variants[0].rules[0].raw = []byte(`{"id":"b1"}`)
	p.unfold()
	p.addVariant()
	if len(p.variants) != 3 {
		t.Fatalf("got %d variants, want 3", len(p.variants))
	}
	for i, d := range p.rules {
		if len(d.raw) != 0 {
			t.Fatalf("copied rule %d carried the original's bytes", i)
		}
	}
}

// The last variant cannot be removed. A policy with none is a policy with no
// rules.
func TestTheLastVariantStays(t *testing.T) {
	p := policiesWithVariants()
	p.dropVariant()
	p.dropVariant()
	if len(p.variants) != 1 {
		t.Fatalf("got %d variants, want 1", len(p.variants))
	}
	if !strings.HasPrefix(p.status, "✗") {
		t.Fatalf("removing the last one was not refused: %q", p.status)
	}
}

func policiesWithVariants() *Policies {
	p := policiesWithRules()
	p.rules = nil
	p.variants = []variantDraft{
		{id: "v1", name: "Base", sec: normaliseLayers(api.SecurityLayers{}),
			rules: []ruleDoc{{rule: api.PolicyRule{ID: "b1", Effect: "DENY", Enabled: true,
				CommandConstraints: &api.Constraint{Denied: []string{"rm"}}}, edited: true}}},
		{id: "v2", name: "Contractors", sec: normaliseLayers(api.SecurityLayers{}),
			rules: []ruleDoc{{rule: api.PolicyRule{ID: "c1", Effect: "DENY", Enabled: true,
				CommandConstraints: &api.Constraint{Denied: []string{"curl"}}}, edited: true}}},
	}
	p.vi = 0
	p.unfold()
	return p
}

// ── DLP ────────────────────────────────────────────────────────────────────

func TestWildcardParts(t *testing.T) {
	cases := []struct {
		in    string
		left  bool
		core  string
		right bool
	}{
		{"sk-*", false, "sk-", true},
		{"*PRIVATE KEY*", true, "PRIVATE KEY", true},
		{"*/.env", true, "/.env", false},
		{"*", true, "*", false}, // a lone star has no core to show
	}
	for _, c := range cases {
		l, core, r := wcParts(c.in)
		if l != c.left || core != c.core || r != c.right {
			t.Errorf("wcParts(%q) = %v %q %v, want %v %q %v", c.in, l, core, r, c.left, c.core, c.right)
		}
	}
}

// Toggling a built-in pattern keeps the order of the others: the list is saved
// as it is shown, and re-sorting it would rewrite the setting on every keypress.
func TestToggleStringKeepsOrder(t *testing.T) {
	got := toggleString([]string{"aws", "github", "slack"}, "github")
	if strings.Join(got, ",") != "aws,slack" {
		t.Fatalf("remove: %v", got)
	}
	got = toggleString(got, "github")
	if strings.Join(got, ",") != "aws,slack,github" {
		t.Fatalf("add: %v", got)
	}
}

// The rows a locked (unpaired) device shows: the accounts section and nothing
// else. Every cloud row would need a key that does not exist.
func TestLockedDeviceOnlyShowsAccounts(t *testing.T) {
	p := NewSettings(testDeps())
	p.accounts = nil
	rows := p.allRows()
	if len(rows) != 1 || rows[0].kind != "acct-add" {
		t.Fatalf("locked rows = %+v", rows)
	}
}

// ── kit ────────────────────────────────────────────────────────────────────

func TestWindowKeepsCursorInView(t *testing.T) {
	lines := make([]string, 50)
	for i := range lines {
		lines[i] = itoa(i)
	}
	win, above, below := window(lines, 40, 10)
	if len(win) != 10 {
		t.Fatalf("window returned %d lines", len(win))
	}
	found := false
	for _, l := range win {
		if l == "40" {
			found = true
		}
	}
	if !found {
		t.Errorf("cursor line not in the window: %v", win)
	}
	if above+len(win)+below != len(lines) {
		t.Errorf("above %d + %d + below %d != %d", above, len(win), below, len(lines))
	}
}

func TestClipCutsToTheBudget(t *testing.T) {
	body := strings.Repeat("0123456789\n", 20)
	got := clip(body, 5, 4)
	lines := strings.Split(got, "\n")
	if len(lines) > 4 {
		t.Fatalf("clip left %d lines", len(lines))
	}
	for _, l := range lines {
		if lipgloss.Width(l) > 5 {
			t.Fatalf("clip left a %d-wide line", lipgloss.Width(l))
		}
	}
}

func TestTruncateNeverExceeds(t *testing.T) {
	if got := truncate("abcdefgh", 4); len([]rune(got)) != 4 {
		t.Fatalf("truncate = %q", got)
	}
	if got := truncate("abc", 10); got != "abc" {
		t.Fatalf("truncate = %q", got)
	}
}

// Pressing repair in the dataroom has to SHOW what it did.
//
// `solongate repair` prints two lists — what it found and what it restored —
// and the panel ran the same install.Repair() and threw both away, keeping only
// the one-line summary. From the user's seat the button did nothing: the row
// looked identical before and after, and the only sign anything had happened
// was a sentence in the status bar that also appears when nothing needed fixing.
func TestRepairShowsWhatItDid(t *testing.T) {
	p := NewSettings(testDeps())
	p.haveGuard, p.haveSelf = true, true
	p.accounts = []config.SavedAccount{
		{APIKey: "sg_live_" + strings.Repeat("a", 32), Email: "someone@example.com", Project: "prod"},
	}
	p.repairReport = &install.Report{
		OK:      true,
		Message: "guard repaired.",
		Before: []install.ReportLine{
			{Label: "guard hook file", OK: true, Detail: "present"},
			{Label: "Codex hooks", OK: false, Detail: "guard NOT registered"},
		},
		After: []install.ReportLine{
			{Label: "guard hook file", OK: true, Detail: "present (v80)"},
			{Label: "Codex hooks", OK: true, Detail: "guard registered"},
		},
		Notes: []string{"swept 2 stray scratch folders"},
	}

	// A tall enough view to hold the whole section.
	view := p.View(ctxOf(100, 40))
	for _, want := range []string{
		"before:", "restored:",
		"guard hook file", "present (v80)",
		"Codex hooks", "guard NOT registered",
		"swept 2 stray scratch folders",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("the repair result does not show %q — the panel is dropping what install.Repair() reported, "+
				"which is what made the button look like it did nothing", want)
		}
	}
}

// And it must not show a stale one. A second press that is still running would
// otherwise leave the previous run's lists on screen, which reads as a result.
func TestANewRepairClearsTheOldResult(t *testing.T) {
	p := NewSettings(testDeps())
	p.haveGuard, p.haveSelf = true, true
	p.repairReport = &install.Report{OK: true, Before: []install.ReportLine{{Label: "guard hook file", Detail: "STALE"}}}
	p.activate(setRow{kind: "repair"})
	if p.repairReport != nil {
		t.Error("starting a repair left the previous run's result on screen")
	}
}

// A CLI THAT KNOWS WHAT A WORKSPACE IS.
//
// A machine pairs once and is handed a key for one project, so every screen in
// this dataroom belonged to whichever workspace the pairing landed on. Somebody
// with two of them had to remove the account and add it again to see the second
// - which also moved what the guard on that machine enforces, whether they
// meant it or not.
func TestTheSettingsPanelListsTheAccountsWorkspaces(t *testing.T) {
	p := NewSettings(testDeps())
	p.accounts = []config.SavedAccount{
		{APIKey: "sg_live_" + strings.Repeat("a", 32), Email: "ada@example.com", Project: "prod"},
	}
	p.haveGuard, p.haveSelf = true, true

	// ONE WORKSPACE IS NOT A SECTION. A list of the only project this account
	// has answers a question nobody asked and puts a row under the cursor that
	// cannot do anything.
	p.haveSpace, p.spaces = true, []api.Workspace{{ID: "p1", Name: "prod"}}
	for _, r := range p.allRows() {
		if r.kind == "ws" {
			t.Fatal("a single workspace is drawn as a section to choose from")
		}
	}

	p.spaces = []api.Workspace{{ID: "p1", Name: "prod"}, {ID: "p2", Name: "staging"}}
	var listed []string
	for _, r := range p.allRows() {
		if r.kind == "ws" {
			listed = append(listed, r.ws.ID)
			if sectionOf(r) != "WORKSPACES" {
				t.Errorf("a workspace row is filed under %q", sectionOf(r))
			}
		}
	}
	if strings.Join(listed, ",") != "p1,p2" {
		t.Fatalf("the workspaces read %v", listed)
	}

	// Which one this machine is in comes from the account row's project name,
	// because that is the only thing the pairing wrote down.
	p.spaceNow = ""
	p.Update(setSpacesMsg{data: p.spaces}, ctxOf(80, 24))
	if p.spaceNow != "p1" {
		t.Errorf("this machine is shown in %q, want the workspace its key is for", p.spaceNow)
	}

	// The one it is already in is not a move: doing the round trip anyway would
	// revoke and re-mint a working key to arrive where it started.
	if cmd := p.activate(setRow{kind: "ws", ws: api.Workspace{ID: "p1", Name: "prod"}}); cmd != nil {
		t.Error("selecting the workspace this machine is in asks the cloud for a key")
	}
}
