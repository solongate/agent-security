// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package ratelimit

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

func Check(agent string, limits *shared.RateLimit) string {
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

	if size > rlMaxFile {
		compact(file, entries)
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
		rec := strconv.FormatInt(e.ms, 10)
		for len(rec) < rlStamp {
			rec = "0" + rec
		}
		out = append(out, []byte(rec+e.token+"\n")...)
	}
	if os.WriteFile(tmp, out, shared.FileMode) == nil {
		_ = os.Rename(tmp, file)
	}
}