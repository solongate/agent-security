package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
)

// Transport moves whole JSON-RPC frames between this process and one peer.
//
// Recv is a stream even for the HTTP transports, where a reply arrives as the
// body of the POST that carried the request. Those transports queue what they
// received and hand it back here, so the client and server above this line do
// not have to know which wire they are on.
type Transport interface {
	Send(ctx context.Context, frame json.RawMessage) error
	Recv(ctx context.Context) (json.RawMessage, error)
	Close() error
}

// ErrTransportClosed is what Recv returns once the peer is gone. It is distinct
// from io.EOF so a caller can tell "the other end hung up" from "this end was
// shut down", which is the difference between an upstream crash worth reporting
// and an ordinary exit.
var ErrTransportClosed = errors.New("mcp: transport closed")

// maxFrameBytes caps one stdio line. A tool result carrying a large file is
// legitimate, and the 1 MB argument ceiling only applies to what goes UP, so
// this is set well above anything the protocol needs rather than at the
// argument limit.
const maxFrameBytes = 32 << 20

// ── stdio ──────────────────────────────────────────────────────────────────

// streamTransport is newline-delimited JSON over a reader and a writer, which
// is the whole of the MCP stdio framing. Messages may not contain a raw
// newline, so a line IS a frame.
type streamTransport struct {
	r      *bufio.Reader
	w      io.Writer
	closer func() error

	writeMu sync.Mutex

	closeOnce sync.Once
	closed    chan struct{}
}

func newStreamTransport(r io.Reader, w io.Writer, closer func() error) *streamTransport {
	return &streamTransport{
		r:      bufio.NewReaderSize(r, 64*1024),
		w:      w,
		closer: closer,
		closed: make(chan struct{}),
	}
}

func (t *streamTransport) Send(_ context.Context, frame json.RawMessage) error {
	select {
	case <-t.closed:
		return ErrTransportClosed
	default:
	}
	// One write per frame, under a lock. Two goroutines writing concurrently
	// would interleave halves of two JSON objects on the same line and the peer
	// would see a parse error rather than either message — and the server above
	// answers requests concurrently on purpose.
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	line := make([]byte, 0, len(frame)+1)
	line = append(line, frame...)
	line = append(line, '\n')
	_, err := t.w.Write(line)
	return err
}

func (t *streamTransport) Recv(_ context.Context) (json.RawMessage, error) {
	for {
		line, err := t.readLine()
		if err != nil {
			return nil, err
		}
		line = trimSpace(line)
		if len(line) == 0 {
			// Blank lines are not frames. Some servers emit one on startup and
			// treating it as a message would answer it with a parse error.
			continue
		}
		return json.RawMessage(line), nil
	}
}

// readLine assembles one line without bufio.Scanner's silent truncation: a
// frame longer than the buffer would come back as two half-frames, each of
// which fails to parse, and the tool call it belonged to would look like a
// malformed response rather than a large one.
func (t *streamTransport) readLine() ([]byte, error) {
	var buf []byte
	for {
		chunk, err := t.r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			buf = append(buf, chunk...)
			if len(buf) > maxFrameBytes {
				return nil, errors.New("mcp: message exceeds the frame limit")
			}
			continue
		}
		if err != nil {
			if len(buf) == 0 && len(chunk) == 0 {
				return nil, err
			}
			buf = append(buf, chunk...)
			return buf, nil
		}
		buf = append(buf, chunk...)
		return buf, nil
	}
}

func (t *streamTransport) Close() error {
	var err error
	t.closeOnce.Do(func() {
		close(t.closed)
		if t.closer != nil {
			err = t.closer()
		}
	})
	return err
}

// NewStdioServerTransport serves the protocol on this process's own stdin and
// stdout.
//
// Nothing else may write to stdout once this is live. That is why every log
// line in this package and in the proxy goes to stderr: one stray Println on
// stdout lands in the middle of a JSON-RPC frame and the client drops the
// connection with a parse error that names neither the writer nor the line.
func NewStdioServerTransport() Transport {
	return newStreamTransport(os.Stdin, os.Stdout, nil)
}

// StdioClientOptions is a child process to spawn and talk to.
type StdioClientOptions struct {
	Command string
	Args    []string
	// Env REPLACES the environment rather than adding to it, matching the Node
	// SDK: a tool server should get what it needs to find binaries and a home
	// directory, not every secret this process happens to be carrying.
	Env map[string]string
	Cwd string
	// Stderr is where the child's own logging goes. It must be drained by
	// somebody: the Node SDK pipes it and never reads it, which stalls any
	// upstream chatty enough to fill the pipe buffer.
	Stderr io.Writer
}

type childTransport struct {
	*streamTransport
	cmd *exec.Cmd
}

// NewStdioClientTransport spawns the upstream server and connects to its stdio.
func NewStdioClientTransport(opts StdioClientOptions) (Transport, error) {
	cmd := exec.Command(opts.Command, opts.Args...)
	cmd.Dir = opts.Cwd
	if opts.Env != nil {
		env := make([]string, 0, len(opts.Env))
		for k, v := range opts.Env {
			// An empty value is dropped rather than exported as `NAME=`.
			// USERPROFILE is in the default set and does not exist on Unix, and
			// exporting it empty is not the same as not exporting it — some
			// programs test for presence.
			if v == "" {
				continue
			}
			env = append(env, k+"="+v)
		}
		cmd.Env = env
	}
	stderr := opts.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	cmd.Stderr = stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, err
	}

	t := &childTransport{cmd: cmd}
	t.streamTransport = newStreamTransport(stdout, stdin, func() error {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		// Reaped so the child does not linger as a zombie for the life of a
		// proxy that outlives many upstream restarts.
		_ = cmd.Wait()
		return nil
	})
	return t, nil
}
