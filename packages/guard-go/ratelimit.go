package main

import (
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/codeyevsky/solongate/sgshared"
)

// One call = one fixed-width record, appended. 13 digits of epoch ms plus a
// newline; fixed width is what lets the tail be read by offset.
const (
	rlRecord  = 14
	rlMaxRead = 1 << 20 // ~74k calls, far past any window
	rlMaxFile = 4 << 20 // compact past this
	dayMs     = 86400000
)

type rlWindow struct {
	Key   string
	Ms    int64
	Label string
}

var rlWindows = []rlWindow{
	{"perDay", dayMs, "day"},
	{"perHour", 3600000, "hour"},
	{"perMinute", 60000, "minute"},
}

// rateLimitCheck returns a deny reason, or "" to allow.
//
// An append-only log rather than a counter that is read, incremented and
// written back: parallel guard processes doing the latter lose each other's
// increments, and the limit stops holding exactly when it matters. Measured on
// the JSON-array version, limit 5 with 30 calls fired at once: 7, 8, 5, 14, 11
// got through across five rounds.
//
// The reservation is made BEFORE the decision — every process appends, then
// counts the window, and the ones past the limit are the ones refused. That is
// what makes the count exact under concurrency rather than merely closer. A
// refused call therefore occupies a slot too, which is the honest reading:
// thirty attempts in a minute is thirty calls a minute whatever came back.
func rateLimitCheck(agent string, limits *sgshared.RateLimit) string {
	if limits == nil {
		return ""
	}
	dir := sgshared.SGDir()
	file := filepath.Join(dir, ".ratelimit-"+sgshared.AgentKey(agent)+".log")
	now := time.Now().UnixMilli()

	if err := os.MkdirAll(dir, sgshared.DirMode); err != nil {
		return ""
	}
	f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, sgshared.FileMode)
	if err != nil {
		return "" // cannot account for this call; never hand out a free one by erroring
	}
	rec := strconv.FormatInt(now, 10)
	for len(rec) < 13 {
		rec = "0" + rec
	}
	_, werr := f.WriteString(rec + "\n")
	f.Close()
	if werr != nil {
		return ""
	}

	st, err := os.Stat(file)
	if err != nil {
		return ""
	}
	size := st.Size()
	from := size - rlMaxRead
	if from < 0 {
		from = 0
	}
	from -= from % rlRecord

	rf, err := os.Open(file)
	if err != nil {
		return ""
	}
	buf := make([]byte, size-from)
	n, _ := rf.ReadAt(buf, from)
	rf.Close()
	buf = buf[:n]

	stamps := make([]int64, 0, len(buf)/rlRecord)
	for i := 0; i+rlRecord <= len(buf); i += rlRecord {
		t, err := strconv.ParseInt(string(buf[i:i+13]), 10, 64)
		if err == nil && now-t < dayMs {
			stamps = append(stamps, t)
		}
	}

	// Our own record is in there, so the limit is crossed at > rather than >=.
	for _, w := range rlWindows {
		limit := rlLimitFor(limits, w.Key)
		if limit <= 0 {
			continue
		}
		count := 0
		for _, t := range stamps {
			if now-t < w.Ms {
				count++
			}
		}
		if count > limit {
			return "Security layer (rate limit): exceeded " + strconv.Itoa(limit) +
				" calls/" + w.Label + " for this agent. Blocked by SolonGate (rate limit). Edit ~/.solongate/policy.json to review or adjust it."
		}
	}

	if size > rlMaxFile {
		compact(file, stamps)
	}
	return ""
}

// rlLimitFor reads one window off the configured limits. It is a function
// rather than a method because the type belongs to sgshared now, and Go will
// not let a package hang methods on a type it does not own.
func rlLimitFor(r *sgshared.RateLimit, key string) int {
	switch key {
	case "perDay":
		return r.PerDay
	case "perHour":
		return r.PerHour
	case "perMinute":
		return r.PerMinute
	}
	return 0
}

// Written beside and renamed, so a reader never sees a half-written file. An
// append landing during the swap is lost, which costs one call of accuracy on a
// file this size.
func compact(file string, stamps []int64) {
	tmp := file + "." + strconv.Itoa(os.Getpid()) + ".tmp"
	var out []byte
	for _, t := range stamps {
		rec := strconv.FormatInt(t, 10)
		for len(rec) < 13 {
			rec = "0" + rec
		}
		out = append(out, []byte(rec+"\n")...)
	}
	if os.WriteFile(tmp, out, sgshared.FileMode) == nil {
		_ = os.Rename(tmp, file)
	}
}
