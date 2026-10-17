// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

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

const setupPrompt = `run the command: echo solongate-works`

type setupStep int

const (
	stepGuard setupStep = iota
	stepPolicy
	stepFirstCall
	stepFinished
)

const (
	setupPollEvery  = 900 * time.Millisecond
	setupFrameEvery = 80 * time.Millisecond
)

type setupPosture struct {
	name  string
	title string
	blurb []string

	build func(path string) client.PolicySet
}

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

type setupModel struct {
	deps Deps

	step       setupStep
	cols, rows int
	tick       int

	frame   int
	started time.Time
	arrived time.Time

	guardReady  bool
	guardDetail string

	choice     int
	askingPath bool
	input      textinput.Model
	writing    bool
	wrote      string
	writeErr   string
	hadPolicy  bool

	call *setupCall

	abandoned bool
}

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

func (m *setupModel) probe() tea.Cmd {
	client := m.deps.Client
	return func() tea.Msg {
		out := setupProbeMsg{}

		registered := install.ClaudeGuardInstalled() || install.CodexGuardInstalled() ||
			install.OpencodeGuardInstalled()
		out.guardReady = registered

		switch beat := install.GuardBeat(); {
		case !registered:

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

		set.ID = "policy-" + strconv.FormatInt(time.Now().UnixMilli(), 10)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := client.Policies.Create(ctx, set); err != nil {
			return setupWroteMsg{err: err.Error()}
		}
		return setupWroteMsg{name: set.Name}
	}
}

func needsSetup(cfg config.TUIConfig) bool { return strings.TrimSpace(cfg.SetupDoneAt) == "" }

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