// SPDX-License-Identifier: Apache-2.0

package auditscan

import (
	"strconv"
	"strings"
)

// toFixed is JavaScript's Number.prototype.toFixed. Report text quotes these
// numbers, so the rounding has to be the same one the npm tool prints or two
// runs of the same scan disagree about a z-score by a tenth.
func toFixed(f float64, digits int) string {
	return strconv.FormatFloat(f, 'f', digits, 64)
}

// toLocaleString is Number.prototype.toLocaleString for a whole number, which
// in every locale this report targets means groups of three separated by a
// comma.
func toLocaleString(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}
