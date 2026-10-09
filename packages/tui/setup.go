// SPDX-License-Identifier: Apache-2.0

// The first run.
//
// A GATE, NOT A PANEL, and that is the whole design. A section in the nav can
// be navigated away from, and the state it would be warning about is the one
// state where leaving is the wrong move: a machine with no policy file allows
// every call. The guard loads nil, the evaluator returns the empty string, and
// the call falls through to allow. Everything is instrumented and nothing is
// enforced, which from the dataroom looks identical to a machine that is
// working. So this runs before the dataroom exists and the dataroom does not
// open until it is finished.
//
// THE LAST STEP WAITS FOR A REAL TOOL CALL and cannot be skipped forward. Every
// part of this product is a claim about what happens when an agent acts, and
// until one has acted the claim is untested on this machine. Three things can
// be wrong and none of them are visible from here: the client never wrote the
// registration, the launcher cannot find node, or the hook is registered
// against a build that is not the one installed. Each of those produces a
// perfectly healthy looking dataroom. One tool call settles all three, and it
// costs the user ten seconds.
package tui

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/solongate/agent-security/packages/core/api"
	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/core/install"
)

type setupStep int

const (
	stepGuard setupStep = iota
	stepPolicy
	stepFirstCall
	stepFinished
)

// How often the last step looks for evidence of a tool call. Fast enough that
// the user does not wonder whether it is working, slow enough that it is two
// stats and a directory listing per tick.
const setupPollEvery = 900 * time.Millisecond

// setupPosture is one of the starting points offered in step two.
//
// THREE, NOT A BLANK FORM. The policy editor has seven drill-down levels and a
// rule has six fields, which is the right amount of control for someone who
// knows what they want and the wrong first question entirely. Each of these
// writes a real policy through the same API the editor uses, so what the user
// gets on the second screen is something they can open and edit, not a mode
// they are stuck in.
type setupPosture struct {
	name  string
	title string
	blurb []string
	// build returns the policy to write. A nil rule list is a real answer: it
	// is the watch-only posture.
	build func(path string) api.PolicySet
}

// The destructive shell patterns the middle posture refuses.
//
// SHORT ON PURPOSE. A long list reads as thorough and behaves as noise: every
// false refusal teaches the person to stop reading them. These are the ones
// whose cost is unrecoverable, and the comment on the rule says so in the file
// the user will open next.
var setupDestructive = []string{
	"*rm -rf /*",
	"*rm -rf ~*",
	"*git push --force*",
	"*git reset --hard*",
	"*chmod -R 777*",
}

func setupPostures() []setupPosture {
	rule := func(id, desc, effect string, c *api.Constraint, p *api.PathConstraint) api.PolicyRule {
		return api.PolicyRule{
			ID: id, Description: desc, Effect: effect,
			Priority: 10, ToolPattern: "*", Enabled: true,
			MinimumTrustLevel:  "UNTRUSTED",
			CommandConstraints: c,
			PathConstraints:    p,
		}
	}
	return []setupPosture{
		{
			name:  "watch",
			title: "Watch everything, refuse nothing",
			blurb: []string{
				"Every tool call is recorded on this machine and none are blocked.",
				"Start here if you want to see what your agent actually does before",
				"you decide what it should not.",
			},
			build: func(string) api.PolicySet {
				return api.PolicySet{Name: "watch", Mode: api.ModeDenylist}
			},
		},
		{
			name:  "destructive",
			title: "Refuse the commands you cannot undo",
			blurb: []string{
				"Everything is allowed except five shell commands whose cost is",
				"permanent: recursive deletes of / and ~, force push, hard reset,",
				"and a recursive chmod 777. Everything else is recorded.",
			},
			build: func(string) api.PolicySet {
				return api.PolicySet{
					Name: "careful", Mode: api.ModeDenylist,
					Rules: api.Rules{Items: []api.PolicyRule{
						rule("no-unrecoverable-commands",
							"Commands whose cost cannot be undone. Written by the first run.",
							"DENY", &api.Constraint{Denied: setupDestructive}, nil),
					}},
				}
			},
		},
		{
			name:  "path",
			title: "Keep the agent out of one path",
			blurb: []string{
				"A file or directory the agent may not read or write. Everything",
				"else is allowed and recorded.",
				"",
				"Read the next screen before you trust this one: a policy rule is a",
				"string match, and there are ways around a string match.",
			},
			build: func(path string) api.PolicySet {
				return api.PolicySet{
					Name: "protected", Mode: api.ModeDenylist,
					Rules: api.Rules{Items: []api.PolicyRule{
						rule("protected-path",
							"The path named during the first run.",
							"DENY", nil, &api.PathConstraint{Denied: []string{path, path + "/*"}}),
					}},
				}
			},
		},
	}
}

// ── the model ──────────────────────────────────────────────────────────────

type setupModel struct {
	deps Deps

	step       setupStep
	cols, rows int
	tick       int

	// step one
	guardReady  bool
	guardDetail string

	// step two
	choice     int
	askingPath bool
	input      textinput.Model
	writing    bool
	wrote      string
	writeErr   string
	hadPolicy  bool

	// step three
	call *setupCall

	// Set when the user leaves without finishing. The dataroom does not open
	// and nothing is recorded, so the next run starts here again.
	abandoned bool
}

// setupCall is one record out of the guard's eval ring, which is the only
// artefact written on EVERY call rather than only on a denial.
type setupCall struct {
	Ms      float64 `json:"ms"`
	Ts      int64   `json:"ts"`
	Tool    string  `json:"tool"`
	Client  string  `json:"client"`
	Cwd     string  `json:"cwd"`
	Perm    string  `json:"perm"`
	Paths   int     `json:"paths"`
	Cmds    int     `json:"cmds"`
	URLs    int     `json:"urls"`
	Session string  `json:"session"`
}

type setupTickMsg struct{}
type setupProbeMsg struct {
	guardReady  bool
	guardDetail string
	hasPolicy   bool
	call        *setupCall
}
type setupWroteMsg struct {
	name string
	err  string
}

func newSetup(deps Deps) *setupModel {
	in := textinput.New()
	in.Prompt = ""
	in.Placeholder = "/home/you/game"
	in.CharLimit = 4096
	return &setupModel{deps: deps, cols: 100, rows: 30, input: in}
}

func (m *setupModel) Init() tea.Cmd { return tea.Batch(setupTick(), m.probe()) }

func setupTick() tea.Cmd {
	return tea.Tick(setupPollEvery, func(time.Time) tea.Msg { return setupTickMsg{} })
}

// probe asks the disk the three questions the steps are about. All of it is a
// handful of stats, so it runs on every tick rather than being cached and
// going stale behind a user who is fixing something in another terminal.
func (m *setupModel) probe() tea.Cmd {
	client := m.deps.API
	return func() tea.Msg {
		out := setupProbeMsg{}

		registered := install.ClaudeGuardInstalled() || install.CodexGuardInstalled() ||
			install.OpencodeGuardInstalled()
		out.guardReady = registered

		// The beat says the client actually RAN it, which is a different
		// question from whether a config file names it, and the only one of the
		// two that cannot be wrong.
		switch beat := install.GuardBeat(); {
		case !registered:
			// The headline already says it. A detail line here would be
			// describing a hook nothing has registered.
		case beat == nil:
			out.guardDetail = "registered, not fired yet"
		case beat.Node == "no-node":
			out.guardDetail = "fired " + install.Ago(beat.At) + ", but found no node to run with"
			out.guardReady = false
		default:
			out.guardDetail = "fired " + install.Ago(beat.At) + " · " + beat.Node
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if list, err := client.Policies.List(ctx); err == nil && len(list) > 0 {
			out.hasPolicy = true
		}

		out.call = newestEvalRecord()
		return out
	}
}

// newestEvalRecord returns the most recent call the guard judged, from ANY
// project.
//
// NOT config.ProjectFlagDir(). The record is filed under a hash of the
// directory the HOOK process was spawned in, and a client is free to spawn it
// anywhere; Antigravity does. Reading only this dataroom's own project would
// have the last step wait forever while the guard was working perfectly, three
// directories away. cli/trace.go reaches the same conclusion for the same
// reason.
func newestEvalRecord() *setupCall {
	root := filepath.Join(config.Dir(), "projects")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var best *setupCall
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		for _, line := range tailLines(filepath.Join(root, e.Name(), ".eval-ring.jsonl"), 8192) {
			var rec setupCall
			if json.Unmarshal([]byte(line), &rec) != nil || rec.Ts == 0 {
				continue
			}
			if best == nil || rec.Ts > best.Ts {
				c := rec
				best = &c
			}
		}
	}
	return best
}

func (m *setupModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.cols, m.rows = msg.Width, msg.Height
		return m, nil

	case setupTickMsg:
		m.tick++
		return m, tea.Batch(setupTick(), m.probe())

	case setupProbeMsg:
		m.guardReady, m.guardDetail = msg.guardReady, msg.guardDetail
		m.hadPolicy = msg.hasPolicy
		m.call = msg.call
		m.advance()
		return m, nil

	case setupWroteMsg:
		m.writing = false
		if msg.err != "" {
			m.writeErr = msg.err
			return m, nil
		}
		m.wrote = msg.name
		m.hadPolicy = true
		m.step = stepFirstCall
		return m, m.probe()

	case tea.KeyMsg:
		return m.onKey(msg)
	}
	return m, nil
}

// advance moves forward only. A step that has been satisfied stays satisfied
// for this run even if the evidence flickers (a client restarting, a policy
// file being edited in another window), because a wizard that walks backwards
// under someone is worse than one that is briefly optimistic.
func (m *setupModel) advance() {
	switch m.step {
	case stepGuard:
		if m.guardReady {
			if m.hadPolicy {
				m.step = stepFirstCall
			} else {
				m.step = stepPolicy
			}
		}
	case stepPolicy:
		if m.hadPolicy && !m.writing {
			m.step = stepFirstCall
		}
	case stepFirstCall:
		if m.call != nil {
			m.step = stepFinished
		}
	}
}

func (m *setupModel) onKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	// While a path is being typed, the keyboard belongs to the text box. The
	// same discipline the panels use: otherwise a `q` in a path quits.
	if m.askingPath {
		switch k.Type {
		case tea.KeyEsc:
			m.askingPath = false
			m.input.Blur()
			return m, nil
		case tea.KeyEnter:
			path := strings.TrimSpace(m.input.Value())
			if path == "" {
				return m, nil
			}
			m.askingPath = false
			m.input.Blur()
			return m, m.write(path)
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(k)
		return m, cmd
	}

	switch k.String() {
	case "ctrl+c", "q":
		m.abandoned = true
		return m, tea.Quit

	case "up", "k":
		if m.step == stepPolicy && m.choice > 0 {
			m.choice--
		}
	case "down", "j":
		if m.step == stepPolicy && m.choice < len(setupPostures())-1 {
			m.choice++
		}

	case "enter", " ":
		switch m.step {
		case stepPolicy:
			if m.writing {
				return m, nil
			}
			if setupPostures()[m.choice].name == "path" {
				m.askingPath = true
				m.input.SetValue("")
				m.input.Focus()
				return m, textinput.Blink
			}
			return m, m.write("")
		case stepFinished:
			config.MarkSetupDone()
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *setupModel) write(path string) tea.Cmd {
	m.writing = true
	m.writeErr = ""
	posture := setupPostures()[m.choice]
	client := m.deps.API
	return func() tea.Msg {
		set := posture.build(path)
		// The id is generated here for the same reason cli/policy.go generates
		// it: two clients with two id schemes is a machine whose policy file
		// cannot be read by half its own tooling.
		set.ID = "policy-" + strconv.FormatInt(time.Now().UnixMilli(), 10)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := client.Policies.Create(ctx, set); err != nil {
			return setupWroteMsg{err: err.Error()}
		}
		return setupWroteMsg{name: set.Name}
	}
}

// ── rendering ──────────────────────────────────────────────────────────────

func (m *setupModel) View() string {
	w := m.cols - 4
	if w < 40 {
		w = 40
	}
	if w > 96 {
		w = 96
	}

	var b []string
	push := func(s string) { b = append(b, "  "+s) }

	push("")
	push(renderRow(w, sgb("SolonGate", theme.AccentBright), plain("  "),
		sg("first run", theme.Dim)))
	push(renderRow(w, sg("Three things, and the last one needs your agent.", theme.Dim)))
	push("")
	b = append(b, m.rail(w)...)
	push("")

	switch m.step {
	case stepGuard:
		b = append(b, m.viewGuard(w)...)
	case stepPolicy:
		b = append(b, m.viewPolicy(w)...)
	case stepFirstCall:
		b = append(b, m.viewWaiting(w)...)
	case stepFinished:
		b = append(b, m.viewDone(w)...)
	}

	push("")
	push(m.footer(w))
	return clampBlock(strings.Join(b, "\n"), m.cols, m.rows)
}

// rail is the three-step progress list, in the grammar the doctor panel
// already uses: a tick for done, a spinner for the one in hand, dim for what
// has not been reached.
func (m *setupModel) rail(w int) []string {
	names := []string{
		"the guard is registered and firing",
		"this machine has a policy",
		"the guard has judged a real tool call",
	}
	out := make([]string, 0, len(names))
	for i, name := range names {
		var mark seg
		switch {
		case setupStep(i) < m.step:
			mark = sg("✓", theme.OK)
		case setupStep(i) == m.step:
			mark = sg(spinFrames[m.tick%len(spinFrames)], theme.Warn)
		default:
			mark = sg("·", theme.Dim)
		}
		fg := theme.Dim
		if setupStep(i) <= m.step {
			fg = theme.White
		}
		out = append(out, "  "+renderRow(w, mark, plain("  "), sg(name, fg)))
	}
	return out
}

func (m *setupModel) viewGuard(w int) []string {
	var out []string
	push := func(segs ...seg) { out = append(out, "  "+renderRow(w, segs...)) }

	if m.guardReady {
		push(sg("The guard is registered. "+m.guardDetail, theme.OK))
		return out
	}
	push(sgb("No client has the guard registered.", theme.Bad))
	push(plain(""))
	push(sg("Nothing is being checked on this machine. Run the installer from the", theme.Dim))
	push(sg("checkout, in your own terminal, and this screen will notice:", theme.Dim))
	push(plain(""))
	push(sg("    ./install.sh", theme.AccentBright))
	if m.guardDetail != "" {
		push(plain(""))
		push(sg("what this screen can see: "+m.guardDetail, theme.Dim))
	}
	return out
}

func (m *setupModel) viewPolicy(w int) []string {
	var out []string
	push := func(segs ...seg) { out = append(out, "  "+renderRow(w, segs...)) }

	push(sgb("This machine has no policy, so every tool call is allowed.", theme.Warn))
	push(sg("It is being recorded. It is not being refused. Pick a starting point:", theme.Dim))
	push(plain(""))

	postures := setupPostures()
	for i, p := range postures {
		marker, fg := "  ", theme.White
		if i == m.choice {
			marker, fg = "▸ ", theme.AccentBright
		}
		push(sg(marker, theme.AccentBright), sgb(p.title, fg))
		if i == m.choice {
			for _, line := range p.blurb {
				push(sg("    "+line, theme.Dim))
			}
		}
	}

	if m.askingPath {
		push(plain(""))
		out = append(out, "  "+sgb("the path: ", theme.Warn).render()+m.input.View())
		push(sg("enter writes it · esc goes back", theme.Dim))
	}
	if m.writing {
		push(plain(""))
		push(sg(spinFrames[m.tick%len(spinFrames)]+" writing "+config.PolicyFilePath(), theme.Warn))
	}
	if m.writeErr != "" {
		push(plain(""))
		push(sg("✗ "+m.writeErr, theme.Bad))
	}
	return out
}

func (m *setupModel) viewWaiting(w int) []string {
	var out []string
	push := func(segs ...seg) { out = append(out, "  "+renderRow(w, segs...)) }

	if m.wrote != "" {
		push(sg("✓ wrote "+m.wrote+" to "+config.PolicyFilePath(), theme.OK))
		push(plain(""))
	}
	push(sgb(spinFrames[m.tick%len(spinFrames)]+" Waiting for the first tool call.", theme.Warn))
	push(plain(""))
	push(sg("Everything above is a claim about what happens when your agent acts.", theme.Dim))
	push(sg("None of it is proven on this machine until one has. Leave this open,", theme.Dim))
	push(sg("and in another terminal:", theme.Dim))
	push(plain(""))
	push(sg("    1. ", theme.Dim), sg("start your agent", theme.White),
		sg("  (claude, codex, opencode, antigravity)", theme.Dim))
	push(sg("    2. ", theme.Dim), sg("ask it to read a file", theme.White),
		sg("  anything at all, a README will do", theme.Dim))
	push(plain(""))
	push(sg("This screen will say so within a second of the guard seeing it.", theme.Dim))
	return out
}

func (m *setupModel) viewDone(w int) []string {
	var out []string
	push := func(segs ...seg) { out = append(out, "  "+renderRow(w, segs...)) }
	c := m.call
	if c == nil {
		push(sg("done", theme.OK))
		return out
	}

	push(sgb("✓ The guard judged a real tool call.", theme.OK))
	push(plain(""))

	kv := func(k, v string) {
		push(sg("    "+padEnd(k, 10), theme.Dim), sg(v, theme.White))
	}
	kv("tool", orSetupDash(c.Tool))
	kv("client", orSetupDash(c.Client))
	kv("where", orSetupDash(c.Cwd))
	kv("asked for", setupSaw(c))
	kv("took", strconv.FormatFloat(c.Ms, 'f', 1, 64)+" ms")
	push(plain(""))
	push(sg("That is the whole product: a decision, on this machine, before the", theme.Dim))
	push(sg("call ran. Nothing left it.", theme.Dim))
	push(plain(""))
	push(sg("A policy rule matches STRINGS, which is worth knowing before you", theme.Dim))
	push(sg("rely on one. `solongate doctor` says what is actually in force.", theme.Dim))
	return out
}

// setupSaw describes, in one line, what the guard extracted from the call. It
// is counts rather than values on purpose: the ring never records argument
// values, and this screen is not the place to start.
func setupSaw(c *setupCall) string {
	var parts []string
	add := func(n int, one, many string) {
		switch {
		case n == 1:
			parts = append(parts, "1 "+one)
		case n > 1:
			parts = append(parts, strconv.Itoa(n)+" "+many)
		}
	}
	add(c.Paths, "path", "paths")
	add(c.Cmds, "command", "commands")
	add(c.URLs, "url", "urls")
	if len(parts) == 0 {
		return "no paths, commands or urls"
	}
	if c.Perm != "" {
		return strings.Join(parts, ", ") + "  (" + strings.ToLower(c.Perm) + ")"
	}
	return strings.Join(parts, ", ")
}

func orSetupDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func (m *setupModel) footer(w int) string {
	switch m.step {
	case stepPolicy:
		if m.askingPath {
			return renderRow(w, sg("enter", theme.AccentBright), sg(" write  ", theme.Dim),
				sg("esc", theme.AccentBright), sg(" back", theme.Dim))
		}
		return renderRow(w, sg("↑↓", theme.AccentBright), sg(" choose  ", theme.Dim),
			sg("enter", theme.AccentBright), sg(" write it  ", theme.Dim),
			sg("q", theme.AccentBright), sg(" leave", theme.Dim))
	case stepFinished:
		return renderRow(w, sg("enter", theme.AccentBright), sg(" open the dataroom", theme.Dim))
	default:
		return renderRow(w, sg("q", theme.AccentBright),
			sg(" leave  (the first run starts here again next time)", theme.Dim))
	}
}

// render turns a single seg into a styled string, for the one place a seg has
// to be concatenated with a widget that renders itself.
func (s seg) render() string {
	st := lipgloss.NewStyle()
	if s.fg != nil {
		st = st.Foreground(s.fg)
	}
	if s.bg != nil {
		st = st.Background(s.bg)
	}
	if s.bold {
		st = st.Bold(true)
	}
	return st.Render(s.text)
}

// ── the gate ───────────────────────────────────────────────────────────────

// needsSetup is the one question Run asks before opening anything.
//
// The timestamp is the record, not the policy file: a user who deliberately
// deleted their policy should land in the dataroom they know, not back at a
// wizard. The first run happened; what they do afterwards is theirs.
func needsSetup(cfg config.TUIConfig) bool { return strings.TrimSpace(cfg.SetupDoneAt) == "" }

// runSetup shows the first run and reports whether to carry on into the
// dataroom. An abandoned setup records nothing, so the next run starts here.
func runSetup(deps Deps, out io.Writer) (bool, error) {
	m := newSetup(deps)
	final, err := tea.NewProgram(m, tea.WithAltScreen(), tea.WithOutput(out)).Run()
	if err != nil {
		return false, err
	}
	if fm, ok := final.(*setupModel); ok && fm.abandoned {
		return false, nil
	}
	return true, nil
}
