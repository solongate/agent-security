//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

import (
	"os"
	"syscall"
	"unsafe"
)

// terminalColumns asks the kernel how wide the terminal is, through the ioctl
// that is the only thing that knows.
//
// SPLIT BY BUILD TAG BECAUSE THE CONSTANTS DO NOT EXIST EVERYWHERE. TIOCGWINSZ
// and SYS_IOCTL are Unix, and this package is cross-compiled for Windows in CI.
// A width probe that breaks the Windows build is a worse trade than a Windows
// build with no width probe, which is the file next to this one.
func terminalColumns(f *os.File) int {
	var ws struct{ Row, Col, Xpixel, Ypixel uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(),
		syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws)))
	if errno != 0 {
		return 0
	}
	return int(ws.Col)
}