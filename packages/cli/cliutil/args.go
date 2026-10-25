// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cliutil

import (
	"math"
	"strconv"
	"strings"
)

type ParsedArgs struct {
	positionals []string
	flags       map[string]any
}

func Parse(argv []string) ParsedArgs {
	p := ParsedArgs{flags: map[string]any{}}
	for i := 0; i < len(argv); i++ {
		tok := argv[i]
		if !strings.HasPrefix(tok, "--") {
			p.positionals = append(p.positionals, tok)
			continue
		}
		body := tok[2:]
		if eq := strings.IndexByte(body, '='); eq != -1 {
			p.flags[body[:eq]] = body[eq+1:]
			continue
		}
		if i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "--") {
			p.flags[body] = argv[i+1]
			i++
			continue
		}
		p.flags[body] = true
	}
	return p
}

func (p ParsedArgs) FlagStr(name string) string {
	v, _ := p.FlagStrOK(name)
	return v
}

func (p ParsedArgs) FlagStrOK(name string) (string, bool) {
	v, ok := p.flags[name].(string)
	return v, ok
}

func (p ParsedArgs) FlagNum(name string) int {
	n, _ := p.FlagNumOK(name)
	return n
}

func (p ParsedArgs) FlagNumOK(name string) (int, bool) {
	s := p.FlagStr(name)
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsInf(n, 0) || math.IsNaN(n) {
		return 0, false
	}
	return int(n), true
}

func (p ParsedArgs) FlagBool(name string) bool {
	switch v := p.flags[name].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

func (p ParsedArgs) Positional(i int) string {
	if i < len(p.positionals) {
		return p.positionals[i]
	}
	return ""
}

func (p ParsedArgs) Rest(i int) string {
	if i >= len(p.positionals) {
		return ""
	}
	return strings.Join(p.positionals[i:], " ")
}

func (p ParsedArgs) Tail(i int) ParsedArgs {
	if i >= len(p.positionals) {
		return ParsedArgs{flags: p.flags}
	}
	return ParsedArgs{positionals: p.positionals[i:], flags: p.flags}
}
