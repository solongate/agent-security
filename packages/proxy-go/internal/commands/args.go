package commands

import (
	"math"
	"strconv"
	"strings"
)

// The flag grammar of the scriptable commands, ported from
// packages/proxy/src/commands/args.ts:
//
//	--flag value      → flag = "value"
//	--flag=value      → flag = "value"
//	--flag            → flag = true, when the next token is another flag or absent
//
// Everything else is a positional, in order.
//
// Deliberately not Go's flag package. That one stops at the first positional,
// rejects unknown flags, and prints its own usage to stderr on a parse error —
// three behaviours that would each be a visible change to a CLI whose commands
// are `policy allow <id> --command curl` and whose usage text is hand-drawn.
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

// flagStr returns a flag's value only when one was given. A bare `--tool` is
// not the tool named "true": it has no value, and the caller has to see that as
// absent or it sends a filter the user never typed.
func (p parsedArgs) flagStr(name string) string {
	if v, ok := p.flags[name].(string); ok {
		return v
	}
	return ""
}

// flagNum returns 0 for an absent or unparseable number, matching the
// TypeScript, where every caller then falls back to a default.
func (p parsedArgs) flagNum(name string) int {
	n, _ := p.flagNumOK(name)
	return n
}

// flagNumOK separates "not given" from "given as zero".
//
// Callers that write a SETTING have to use this one. `ratelimit set --minute
// oops` parses to no number at all, and treating that as 0 would save a limit of
// zero calls a minute — every request blocked, from a typo. The TypeScript gets
// this from `undefined`; Go needs the second return value to say the same thing.
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

// flagBool accepts both the bare flag and an explicit --flag=true, because a
// script writing out its arguments programmatically tends to produce the
// second.
func (p parsedArgs) flagBool(name string) bool {
	switch v := p.flags[name].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

// positional returns the nth positional or "" — the CLI's arguments are almost
// all optional and every call site would otherwise repeat the same bounds check.
func (p parsedArgs) positional(i int) string {
	if i < len(p.positionals) {
		return p.positionals[i]
	}
	return ""
}

// rest joins the positionals from i on with a space, for the commands that take
// a value which may contain spaces (`policy create My Policy`).
func (p parsedArgs) rest(i int) string {
	if i >= len(p.positionals) {
		return ""
	}
	return strings.Join(p.positionals[i:], " ")
}
