// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

import (
	"math"
	"strconv"
	"strings"
)

type parsedArgs struct {
	positionals []string
	flags       map[string]any
}

func parse(argv []string) parsedArgs {
	p := parsedArgs{flags: map[string]any{}}
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

func (p parsedArgs) flagStr(name string) string {
	if v, ok := p.flags[name].(string); ok {
		return v
	}
	return ""
}

func (p parsedArgs) flagNum(name string) int {
	n, _ := p.flagNumOK(name)
	return n
}

func (p parsedArgs) flagNumOK(name string) (int, bool) {
	s := p.flagStr(name)
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsInf(n, 0) || math.IsNaN(n) {
		return 0, false
	}
	return int(n), true
}

func (p parsedArgs) flagBool(name string) bool {
	switch v := p.flags[name].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

func (p parsedArgs) positional(i int) string {
	if i < len(p.positionals) {
		return p.positionals[i]
	}
	return ""
}

func (p parsedArgs) rest(i int) string {
	if i >= len(p.positionals) {
		return ""
	}
	return strings.Join(p.positionals[i:], " ")
}