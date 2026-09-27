package mcp

import "io"

// NewPipe connects two transports back to back, in memory.
//
// It is here rather than in a test file because the proxy's own tests live in
// another package and cannot reach an unexported helper. It uses the same
// newline-delimited framing as stdio, so a test that drives a proxy through it
// exercises the real encoder and the real reader rather than a stand-in that
// agrees with them by construction.
func NewPipe() (Transport, Transport) {
	// aToB carries what A sends; bToA carries what B sends.
	aToBRead, aToBWrite := io.Pipe()
	bToARead, bToAWrite := io.Pipe()

	a := newStreamTransport(bToARead, aToBWrite, func() error {
		_ = aToBWrite.Close()
		_ = bToARead.Close()
		return nil
	})
	b := newStreamTransport(aToBRead, bToAWrite, func() error {
		_ = bToAWrite.Close()
		_ = aToBRead.Close()
		return nil
	})
	return a, b
}
