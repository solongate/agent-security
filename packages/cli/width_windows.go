//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

import "os"

// terminalColumns has no probe here, and returns 0 so nothing is wrapped.
//
// The console API that answers this is GetConsoleScreenBufferInfo, reached
// through x/sys/windows, and taking a dependency for it would put a syscall
// package in the enforcement path's module graph to improve the layout of a
// note. 0 means "unmeasurable", which the caller already handles by printing
// the text whole, and COLUMNS is still read before this is reached, so a
// Windows user who sets it gets the wrapping anyway.
func terminalColumns(f *os.File) int { return 0 }