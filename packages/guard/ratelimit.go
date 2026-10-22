// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/solongate/agent-security/packages/shared"
)

const (
	rlStamp   = 13
	rlToken   = 10
	rlRecord  = rlStamp + rlToken + 1
	rlMaxRead = 1 << 20
	rlMaxFile = 4 << 20
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

func rlNewToken() string {
	var b [rlToken / 2]byte
	if _, err := rand.Read(b[:]); err != nil {

		return "0000000000"
	}
	return hex.EncodeToString(b[:])
}

func rateLimitCheck(agent string, limits *shared.RateLimit) string {
	if limits == nil {
		return ""
	}
	dir := shared.SGDir()

	file := filepath.Join(dir, ".ratelimit-"+shared.AgentKey(agent)+".v2.log")
	now := time.Now().UnixMilli()

	if err := os.MkdirAll(dir, shared.DirMode); err != nil {
		return ""
	}
	f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, shared.FileMode)
	if err != nil {
		return ""
	}
	token := rlNewToken()
	_, werr := f.WriteString(rlFormat(now, token))
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

	if reason := rlExceeded(entries, mine, now, limits); reason != "" {
		return reason
	}

	if size > rlMaxFile {
		compact(file, entries)
	}
	return ""
}

// rlFormat renders one log record: the millisecond stamp zero-padded to
// rlStamp digits, then the token, then a newline. The reader slices the file
// at fixed offsets, so a record of any other width would shift every record
// after it and corrupt the count.
func rlFormat(ms int64, token string) string {
	stamp := strconv.FormatInt(ms, 10)
	for len(stamp) < rlStamp {
		stamp = "0" + stamp
	}
	return stamp + token + "\n"
}

// rlExceeded returns the block reason for the first window, widest first, that
// this call would push over its limit, or "" if none. It does no I/O so the
// window arithmetic can be tested without a log file.
//
// mine is the index in entries of this call's own record, or -1 if it was not
// found in the part of the log that was read. When found, only the records
// before it count, so two calls racing at the limit cannot both see room;
// when not found, the call's own record is somewhere in entries, so the cap
// is exceeded one record sooner.
func rlExceeded(entries []rlEntry, mine int, now int64, limits *shared.RateLimit) string {
	for _, w := range rlWindows {
		limit := rlLimitFor(limits, w.Key)
		if limit <= 0 {
			continue
		}
		var count int
		if mine >= 0 {
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

		for _, e := range entries {
			if now-e.ms < w.Ms {
				count++
			}
		}
		if count > limit {
			return rlReason(limit, w.Label)
		}
	}
	return ""
}

func rlReason(limit int, label string) string {
	return "Security layer (rate limit): exceeded " + strconv.Itoa(limit) +
		" calls/" + label + " for this agent. Blocked by SolonGate (rate limit). Edit ~/.solongate/policy.json to review or adjust it."
}

func rlLimitFor(r *shared.RateLimit, key string) int {
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

func compact(file string, entries []rlEntry) {
	tmp := file + "." + strconv.Itoa(os.Getpid()) + ".tmp"
	var out []byte
	for _, e := range entries {
		out = append(out, rlFormat(e.ms, e.token)...)
	}
	if os.WriteFile(tmp, out, shared.FileMode) == nil {
		_ = os.Rename(tmp, file)
	}
}
