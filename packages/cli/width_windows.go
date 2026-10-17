//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

import "os"

func terminalColumns(f *os.File) int { return 0 }