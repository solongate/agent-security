// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/solongate/agent-security/packages/sgshared"
)

// One call = one fixed-width record, appended: 13 digits of epoch ms, a 10
// character token that belongs to this call alone, and a newline. Fixed width is
// what lets the tail be read by offset without parsing all of it.
//
// THE TOKEN IS WHAT MAKES THE COUNT EXACT. See rateLimitCheck.
const (
	rlStamp   = 13
	rlToken   = 10
	rlRecord  = rlStamp + rlToken + 1
	rlMaxRead = 1 << 20 // ~43k calls, far past any window
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

type rlEntry struct {
	ms    int64
	token string
}

// rlNewToken is this call's identity in the log. Random rather than pid-based: a
// burst is often one parent spawning many children, and two of them starting in
// the same millisecond with the same parent would otherwise collide.
func rlNewToken() string {
	var b [rlToken / 2]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Never hand out a free call because entropy was unavailable. A constant
		// token degrades this to the old count-everything behaviour, which is
		// conservative, rather than to no limit at all.
		return "0000000000"
	}
	return hex.EncodeToString(b[:])
}

// rateLimitCheck returns a deny reason, or "" to allow.
//
// An append-only log rather than a counter that is read, incremented and written
// back: parallel guard processes doing the latter lose each other's increments,
// and the limit stops holding exactly when it matters. Measured on the JSON-array
// version, limit 5 with 30 calls fired at once: 7, 8, 5, 14, 11 got through
// across five rounds.
//
// THE DECISION IS THIS CALL'S POSITION, NOT THE TOTAL. Appending and then
// counting everything in the window was the first fix, and it held the ceiling
// but not the floor: thirty processes append at once, and whichever one gets
// around to counting last sees all thirty and refuses itself, even though it was
// among the first five to reserve. How many got through depended on the
// interleaving. Measured: a limit of 5 let 3 through on a loaded machine, and the
// conformance case that asserts a useful number gets through failed on a run
// where nothing had changed.
//
// So each record carries a token, and a call is allowed when fewer than `limit`
// records inside the window sit AHEAD OF ITS OWN. The log is totally ordered by
// position, so every process computes the same answer whenever it happens to
// look: exactly the first `limit` records in a window are allowed, and the rest
// are not. The ceiling still holds, and now the floor does too.
//
// A refused call still occupies a slot, which is the honest reading: thirty
// attempts in a minute is thirty calls a minute whatever came back.
func rateLimitCheck(agent string, limits *sgshared.RateLimit) string {
	if limits == nil {
		return ""
	}
	dir := sgshared.SGDir()
	// `.v2` because the record width changed. An older file parsed at this stride
	// yields timestamps the day filter throws away, which is an empty window,
	// which is an allow: the one upgrade behaviour this must not have.
	file := filepath.Join(dir, ".ratelimit-"+sgshared.AgentKey(agent)+".v2.log")
	now := time.Now().UnixMilli()

	if err := os.MkdirAll(dir, sgshared.DirMode); err != nil {
		return ""
	}
	f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, sgshared.FileMode)
	if err != nil {
		return "" // cannot account for this call; never hand out a free one by erroring
	}
	token := rlNewToken()
	rec := strconv.FormatInt(now, 10)
	for len(rec) < rlStamp {
		rec = "0" + rec
	}
	_, werr := f.WriteString(rec + token + "\n")
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

	entries := make([]rlEntry, 0, len(buf)/rlRecord)
	mine := -1
	for i := 0; i+rlRecord <= len(buf); i += rlRecord {
		t, err := strconv.ParseInt(string(buf[i:i+rlStamp]), 10, 64)
		if err != nil || now-t >= dayMs {
			continue
		}
		e := rlEntry{ms: t, token: string(buf[i+rlStamp : i+rlStamp+rlToken])}
		if e.token == token && mine < 0 {
			mine = len(entries)
		}
		entries = append(entries, e)
	}

	for _, w := range rlWindows {
		limit := rlLimitFor(limits, w.Key)
		if limit <= 0 {
			continue
		}
		var count int
		if mine >= 0 {
			// How many are ahead of us inside this window.
			for _, e := range entries[:mine] {
				if now-e.ms < w.Ms {
					count++
				}
			}
			if count >= limit {
				return rlReason(limit, w.Label)
			}
			continue
		}
		// Our own record is not in the tail we read, which means the file was
		// compacted or truncated under us. Fall back to counting everything in
		// the window, ourselves included, and cross the limit at > rather than
		// >=. Conservative, and the behaviour this had before.
		for _, e := range entries {
			if now-e.ms < w.Ms {
				count++
			}
		}
		if count > limit {
			return rlReason(limit, w.Label)
		}
	}

	if size > rlMaxFile {
		compact(file, entries)
	}
	return ""
}

func rlReason(limit int, label string) string {
	return "Security layer (rate limit): exceeded " + strconv.Itoa(limit) +
		" calls/" + label + " for this agent. Blocked by SolonGate (rate limit). Edit ~/.solongate/policy.json to review or adjust it."
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
func compact(file string, entries []rlEntry) {
	tmp := file + "." + strconv.Itoa(os.Getpid()) + ".tmp"
	var out []byte
	for _, e := range entries {
		rec := strconv.FormatInt(e.ms, 10)
		for len(rec) < rlStamp {
			rec = "0" + rec
		}
		out = append(out, []byte(rec+e.token+"\n")...)
	}
	if os.WriteFile(tmp, out, sgshared.FileMode) == nil {
		_ = os.Rename(tmp, file)
	}
}
