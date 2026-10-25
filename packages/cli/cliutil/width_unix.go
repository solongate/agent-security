//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cliutil

import (
	"os"
	"syscall"
	"unsafe"
)

func TerminalColumns(f *os.File) int {
	var ws struct{ Row, Col, Xpixel, Ypixel uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(),
		syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws)))
	if errno != 0 {
		return 0
	}
	return int(ws.Col)
}
