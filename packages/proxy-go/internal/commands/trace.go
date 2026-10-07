// SPDX-License-Identifier: Apache-2.0

package commands

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

	"github.com/codeyevsky/solongate/proxy/internal/api"
	"github.com/codeyevsky/solongate/sgshared"
)

// `solongate trace` — what the guard saw, locally, for THIS directory.
//
// It exists because the audit log cannot answer the question people actually
// ask, which is "my rule names that directory, why did nothing happen".
//
// The cloud audit records denials reliably and ALLOWs only when the client has
// a post-tool stage to report them from. Antigravity has none, so on that client
// a permitted call leaves no cloud row at all, and "allowed" and "the guard
// never ran" look identical from the outside. The guard writes a local record
// for EVERY evaluation either way, and this is that file.
//
// The interesting columns are PATHS/CMDS/URLS: they are what the guard managed
// to extract from the call, and they are what every path, command and url rule
// matches against. A path rule that never fires on a call showing `paths 0` is
// not a rule that lost, it is a call the guard saw nothing addressable in.
//
// ARGS is the argument KEY NAMES, never the values. Names are schema and are
// what shows you a client renamed a field between versions; values are the file
// contents and commands the guard exists to keep in place.

func traceUsage() string {
	return usage("solongate trace", "what the guard saw here", []usageRow{
		row("trace", "the last evaluations in this directory"),
		row("trace --limit N", "how many to show (default 20)"),
		row("trace --json", "the raw records"),
	})
}

// traceRecord is one line of the guard's ring. Every field is optional: records
// written by an older guard carry only the first four, and a missing count must
// read as "not recorded" rather than as zero.
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
		return dim("-")
	}
	if *n == 0 {
		// Zero is the answer that explains a rule doing nothing, so it is the one
		// value in this table worth making impossible to skim past.
		return red("0")
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

// readAllTraceRings collects every project's ring.
//
// The record is filed under a hash of the directory the GUARD PROCESS was
// spawned in, which is not always the directory the call was made in: a client
// launches its hooks from wherever it likes, and Antigravity does. Looking only
// under the hash of the current directory therefore finds nothing for exactly
// the client whose allowed calls are missing from the cloud audit too, which is
// the one case this command exists for.
//
// So every ring is read and the records are matched on the `cwd` they carry.
func readAllTraceRings() []traceRecord {
	root := filepath.Join(sgshared.SGDir(), "projects")
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

func runTrace(ctx context.Context, c *api.Client, p parsedArgs) (int, error) {
	sub := p.positional(0)
	if sub == "help" {
		errln(traceUsage())
		return 0, nil
	}
	if sub != "" {
		return unknownSub("trace", sub, traceUsage())
	}

	limit := p.flagNum("limit")
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
		errln("")
		errln("  No calls recorded for this directory.")
		errln(dim("  " + here))
		if len(all) > 0 {
			// Records exist, just not for here. Naming the directories they DO
			// belong to is the difference between "nothing ran" and "you are
			// standing in the wrong place", and those need different next steps.
			errln("")
			errln(dim("  The guard has recorded calls in:"))
			seen := map[string]bool{}
			shown := 0
			for _, r := range all {
				if r.Cwd == "" || seen[r.Cwd] || shown >= 8 {
					continue
				}
				seen[r.Cwd] = true
				shown++
				errln("    " + dim("•") + " " + r.Cwd)
			}
			// A record with no cwd predates it being written down.
			if shown == 0 {
				errln(dim("    (older records carry no directory; make one more call and retry)"))
			}
		}
		return 1, nil
	}

	if len(records) > limit {
		records = records[:limit]
	}

	if p.flagBool("json") {
		printJSON(records)
		return 0, nil
	}

	errln("")
	errln("  " + strconv.Itoa(len(records)) + " local evaluation(s) · " + dim(here))

	rows := make([][]string, 0, len(records))
	for _, r := range records {
		when := ""
		if r.TS > 0 {
			when = time.UnixMilli(r.TS).Format("15:04:05")
		}
		args := dim("-")
		if len(r.Args) > 0 {
			args = strings.Join(r.Args, ",")
		} else if r.Args != nil {
			// An empty list is not the same as an absent one: it means the guard
			// parsed the payload and found no arguments in it at all.
			args = red("(none)")
		}
		rows = append(rows, []string{
			when,
			r.Client,
			r.Tool,
			dim(r.Perm),
			countCell(r.Paths),
			countCell(r.Cmds),
			countCell(r.URLs),
			args,
			dim(strconv.FormatFloat(r.Ms, 'f', 0, 64) + "ms"),
		})
	}
	table([]string{"WHEN", "CLIENT", "TOOL", "PERM", "PATHS", "CMDS", "URLS", "ARGS", "MS"}, rows)

	errln("")
	errln(dim("  PATHS/CMDS/URLS is what the guard extracted from the call. A path rule"))
	errln(dim("  cannot fire on a call whose PATHS is 0, whatever the rule says."))
	return 0, nil
}
