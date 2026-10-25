// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package observability

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/shared"
)

func traceUsage() string {
	return cliutil.Usage("solongate trace", "what the guard saw here", []cliutil.UsageRow{
		cliutil.Row("trace", "the last evaluations in this directory"),
		cliutil.Row("trace --limit N", "how many to show (default 20)"),
		cliutil.Row("trace --json", "the raw records"),
	})
}

type traceRecord struct {
	TS      int64    `json:"ts"`
	Ms      float64  `json:"ms"`
	Tool    string   `json:"tool"`
	Session string   `json:"session"`
	Client  string   `json:"client"`
	Cwd     string   `json:"cwd"`
	Perm    string   `json:"perm"`
	Args    []string `json:"args"`
	Paths   *int     `json:"paths"`
	Cmds    *int     `json:"cmds"`
	URLs    *int     `json:"urls"`
}

func countCell(n *int) string {
	if n == nil {
		return cliutil.Dim("-")
	}
	if *n == 0 {

		return cliutil.Red("0")
	}
	return strconv.Itoa(*n)
}

func readTraceRing(dir string) ([]traceRecord, error) {
	f, err := os.Open(filepath.Join(dir, ".eval-ring.jsonl"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []traceRecord
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var r traceRecord
		if json.Unmarshal([]byte(line), &r) == nil {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS > out[j].TS })
	return out, nil
}

func readAllTraceRings() []traceRecord {
	root := filepath.Join(shared.SGDir(), "projects")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []traceRecord
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		rs, err := readTraceRing(filepath.Join(root, e.Name()))
		if err != nil {
			continue
		}
		out = append(out, rs...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS > out[j].TS })
	return out
}

func sameDir(a, b string) bool {
	clean := func(s string) string {
		s = strings.ReplaceAll(s, `\`, "/")
		if len(s) > 1 {
			s = strings.TrimRight(s, "/")
		}
		return s
	}
	return clean(a) != "" && clean(a) == clean(b)
}

func RunTrace(ctx context.Context, c *client.Client, p cliutil.ParsedArgs) (int, error) {
	sub := p.Positional(0)
	if sub == "help" {
		cliutil.Errln(traceUsage())
		return 0, nil
	}
	if sub != "" {
		return cliutil.UnknownSub("trace", sub, traceUsage())
	}

	limit := p.FlagNum("limit")
	if limit <= 0 {
		limit = 20
	}

	here, err := os.Getwd()
	if err != nil {
		here = "."
	}
	if abs, e := filepath.Abs(here); e == nil {
		here = abs
	}

	all := readAllTraceRings()
	records := make([]traceRecord, 0, len(all))
	for _, r := range all {
		if sameDir(r.Cwd, here) {
			records = append(records, r)
		}
	}

	if len(records) == 0 {
		cliutil.Errln("")
		cliutil.Errln("  No calls recorded for this directory.")
		cliutil.Errln(cliutil.Dim("  " + here))
		if len(all) > 0 {

			cliutil.Errln("")
			cliutil.Errln(cliutil.Dim("  The guard has recorded calls in:"))
			seen := map[string]bool{}
			shown := 0
			for _, r := range all {
				if r.Cwd == "" || seen[r.Cwd] || shown >= 8 {
					continue
				}
				seen[r.Cwd] = true
				shown++
				cliutil.Errln("    " + cliutil.Dim("•") + " " + r.Cwd)
			}

			if shown == 0 {
				cliutil.Errln(cliutil.Dim("    (older records carry no directory; make one more call and retry)"))
			}
		}
		return 1, nil
	}

	if len(records) > limit {
		records = records[:limit]
	}

	if p.FlagBool("json") {
		cliutil.PrintJSON(records)
		return 0, nil
	}

	cliutil.Errln("")
	cliutil.Errln("  " + strconv.Itoa(len(records)) + " local evaluation(s) · " + cliutil.Dim(here))

	rows := make([][]string, 0, len(records))
	for _, r := range records {
		when := ""
		if r.TS > 0 {
			when = time.UnixMilli(r.TS).Format("15:04:05")
		}
		args := cliutil.Dim("-")
		if len(r.Args) > 0 {
			args = strings.Join(r.Args, ",")
		} else if r.Args != nil {

			args = cliutil.Red("(none)")
		}
		rows = append(rows, []string{
			when,
			r.Client,
			r.Tool,
			cliutil.Dim(r.Perm),
			countCell(r.Paths),
			countCell(r.Cmds),
			countCell(r.URLs),
			args,
			cliutil.Dim(strconv.FormatFloat(r.Ms, 'f', 0, 64) + "ms"),
		})
	}
	cliutil.Table([]string{"WHEN", "CLIENT", "TOOL", "PERM", "PATHS", "CMDS", "URLS", "ARGS", "MS"}, rows)

	cliutil.Errln("")
	cliutil.Errln(cliutil.Dim("  PATHS/CMDS/URLS is what the guard extracted from the call. A path rule"))
	cliutil.Errln(cliutil.Dim("  cannot fire on a call whose PATHS is 0, whatever the rule says."))
	return 0, nil
}
