//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cliutil

import "os"

func TerminalColumns(f *os.File) int { return 0 }
