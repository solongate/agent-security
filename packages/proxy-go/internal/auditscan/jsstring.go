// SPDX-License-Identifier: Apache-2.0

package auditscan

import "unicode/utf16"

// Every length limit and slice offset in the audit tool came from JavaScript,
// where a string index is a UTF-16 code unit. Reimplementing them over Go bytes
// would truncate a transcript containing anything outside ASCII at a different
// point than the npm tool does — and, worse, could cut a UTF-8 sequence in half
// and put invalid text into an exported report.

func jsLen(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// jsSliceHead is `s.slice(0, n)`.
func jsSliceHead(s string, n int) string {
	if n <= 0 {
		return ""
	}
	units := 0
	for i, r := range s {
		w := 1
		if r > 0xFFFF {
			w = 2
		}
		if units+w > n {
			return s[:i]
		}
		units += w
	}
	return s
}

// jsSliceRange is `s.slice(start, end)`. A range that would land inside a
// surrogate pair stops at the character boundary instead of emitting the lone
// surrogate JavaScript would: Go strings cannot hold one, and the callers are
// all scanning for a substring, where a character less costs nothing.
func jsSliceRange(s string, start, end int) string {
	units := utf16.Encode([]rune(s))
	if start < 0 {
		start = 0
	}
	if end > len(units) {
		end = len(units)
	}
	if start >= end {
		return ""
	}
	return string(utf16.Decode(units[start:end]))
}
