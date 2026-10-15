// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

// The first run.
//
// A GATE, NOT A PANEL, and that is the whole design. A section in the nav can
// be navigated away from, and the state it would be warning about is the one
// state where leaving is the wrong move: a machine with no policy file allows
// every call. The guard loads nil, the evaluator returns the empty string, and
// the call falls through to allow. Everything is instrumented and nothing is
// enforced, which from the TUI looks identical to a machine that is
// working. So this runs before the TUI exists and the TUI does not
// open until it is finished.
//
// THE LAST STEP WAITS FOR A REAL TOOL CALL and cannot be skipped forward. Every
// part of this product is a claim about what happens when an agent acts, and
// until one has acted the claim is untested on this machine. Three things can
// be wrong and none of them are visible from here: the client never wrote the
// registration, the launcher cannot find node, or the hook is registered
// against a build that is not the one installed. Each of those produces a
// perfectly healthy looking TUI. One tool call settles all three, and it
// costs the user ten seconds.
package tui

import (
	"context"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/core/install"
)

// setupPrompt is what the first run tells somebody to type at their agent.
//
// A SPECIFIC COMMAND RATHER THAN "do something". The screen is waiting for a
// tool call and the person has to produce one, which means the instruction has
// to be something an agent will definitely answer by REACHING FOR A TOOL. "Ask
// it to read a file" is not that: half the time the model answers from what it
// already has in context and no tool runs, and then this screen sits there
// looking broken while the person did exactly what it said.
//
// `echo` with a word in it also makes the record unmistakably theirs when it
// arrives: one command, no paths, and a tool name they will recognise.
const setupPrompt = `run the command: echo solongate-works`

type setupStep int

const (
	stepGuard setupStep = iota
	stepPolicy
	stepFirstCall
	stepFinished
)

// TWO CLOCKS, because they answer to different things.
//
// The probe reads the disk: two stats and a directory listing, and 900ms is
// fast enough that nobody wonders whether it noticed. Running it at animation
// speed would be forty directory listings a second to move a dot.
//
// The frame clock is what the eye is on. Below about 100ms a sweep reads as a
// jump rather than a movement, and the whole point of the waiting screen is
// that it looks like it is listening rather than like it has hung.
const (
	setupPollEvery  = 900 * time.Millisecond
	setupFrameEvery = 80 * time.Millisecond
)

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
	build func(path string) client.PolicySet
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
	rule := func(id, desc, effect string, c *client.Constraint, p *client.PathConstraint) client.PolicyRule {
		return client.PolicyRule{
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
			build: func(string) client.PolicySet {
				return client.PolicySet{Name: "watch", Mode: client.ModeDenylist}
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
			build: func(string) client.PolicySet {
				return client.PolicySet{
					Name: "careful", Mode: client.ModeDenylist,
					Rules: client.Rules{Items: []client.PolicyRule{
						rule("no-unrecoverable-commands",
							"Commands whose cost cannot be undone. Written by the first run.",
							"DENY", &client.Constraint{Denied: setupDestructive}, nil),
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
			build: func(path string) client.PolicySet {
				return client.PolicySet{
					Name: "protected", Mode: client.ModeDenylist,
					Rules: client.Rules{Items: []client.PolicyRule{
						rule("protected-path",
							"The path named during the first run.",
							"DENY", nil, &client.PathConstraint{Denied: []string{path, path + "/*"}}),
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

	// frame drives everything that moves. started is when this screen opened,
	// and arrived is when the call landed, which is what the reveal counts from:
	// the payoff is worth a moment of staging and the rest of the screen is not.
	frame   int
	started time.Time
	arrived time.Time

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

	// Set when the user leaves without finishing. The TUI does not open
	// and nothing is recorded, so the next run starts here again.
	abandoned bool
}

// setupCall is one record out of the guard's eval ring. The reader lives in
// core/config because `doctor` needs the same answer, and two readers of one
// file is how two surfaces end up disagreeing about what happened.
type setupCall = config.EvalRecord

type setupTickMsg struct{}
type setupFrameMsg struct{}
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
	return &setupModel{deps: deps, cols: 100, rows: 30, input: in, started: time.Now()}
}

func (m *setupModel) Init() tea.Cmd {
	return tea.Batch(setupTick(), setupFrame(), m.probe())
}

func setupTick() tea.Cmd {
	return tea.Tick(setupPollEvery, func(time.Time) tea.Msg { return setupTickMsg{} })
}

func setupFrame() tea.Cmd {
	return tea.Tick(setupFrameEvery, func(time.Time) tea.Msg { return setupFrameMsg{} })
}

// probe asks the disk the three questions the steps are about. All of it is a
// handful of stats, so it runs on every tick rather than being cached and
// going stale behind a user who is fixing something in another terminal.
func (m *setupModel) probe() tea.Cmd {
	client := m.deps.Client
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

		out.call = config.NewestEvalRecord()
		return out
	}
}

func (m *setupModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.cols, m.rows = msg.Width, msg.Height
		return m, nil

	case setupTickMsg:
		m.tick++
		return m, tea.Batch(setupTick(), m.probe())

	case setupFrameMsg:
		m.frame++
		return m, setupFrame()

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
			m.arrived = time.Now()
		}
	}
}

func (m *setupModel) write(path string) tea.Cmd {
	m.writing = true
	m.writeErr = ""
	posture := setupPostures()[m.choice]
	client := m.deps.Client
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

// ── the gate ───────────────────────────────────────────────────────────────

// needsSetup is the one question Run asks before opening anything.
//
// The timestamp is the record, not the policy file: a user who deliberately
// deleted their policy should land in the TUI they know, not back at a
// wizard. The first run happened; what they do afterwards is theirs.
func needsSetup(cfg config.TUIConfig) bool { return strings.TrimSpace(cfg.SetupDoneAt) == "" }

// runSetup shows the first run and reports whether to carry on into the
// TUI. An abandoned setup records nothing, so the next run starts here.
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