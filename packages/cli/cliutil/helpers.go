// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cliutil

import "fmt"

func UsageErr(msg string) (int, error) {
	Errln("  " + msg)
	return 1, nil
}

func Okf(format string, a ...any) {
	Errln(Green("  ✓ " + fmt.Sprintf(format, a...)))
}
