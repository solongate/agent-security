// Package logsserver is `solongate logs-server`: the loopback HTTP service that
// lets the SolonGate dashboard read THIS machine's local audit log.
//
// When local-log storage is on, the guard hooks append solongate-audit.jsonl to
// a folder on this machine and nothing goes to the cloud. A hosted web page
// cannot read a path on the developer's disk, so this service reads that one
// file and serves it over 127.0.0.1 for the dashboard to poll.
//
// Everything about the exposure is deliberately narrow, because what it hands
// out is a security record taken off a developer's machine and nothing here is
// behind a credential. It binds to loopback only, it answers two routes, it
// serves exactly one file — the one the guard is currently writing, resolved by
// internal/config rather than taken from the request — and it never lists a
// directory. The allowed origins are an exact-match list with no wildcard. A
// wider bind or a wider origin than the list below is a vulnerability, not a
// convenience.
//
// Ported from packages/proxy/src/logs-server.ts. The state file and the port
// are shared with that implementation, so both can manage the same service; see
// daemon.go.
package logsserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// DefaultPort is fixed rather than negotiated: the dashboard has no way to
// discover a port, so it tries this one. config owns the number because the
// dataroom's Settings panel reports it too.
const DefaultPort = config.LogsServerPort

// The origins allowed to read from this service: LOOPBACK ONLY, plus anything
// SOLONGATE_DASHBOARD_ORIGIN names.
//
// Exact match, no pattern, no wildcard, and no Access-Control-Allow-Credentials
// anywhere in this file. Any page in any browser on this machine can reach
// 127.0.0.1, so the origin check is the ONLY thing standing between a random
// site the developer has open and this machine's audit trail.
//
// A HOSTED DOMAIN USED TO BE ON THIS LIST and should not have been. This service
// reads the complete local audit trail off disk and hands it to any origin named
// here; trusting a hostname nobody running this build controls means the trail is
// readable by whoever holds that domain, on every machine that starts the
// service. Loopback is the whole audience — an installation that reads it from
// somewhere else names that origin itself. The TypeScript twin already said so
// in the same words; this is the Go side catching up.
func allowedOrigins() map[string]bool {
	out := map[string]bool{
		"http://localhost:3000": true,
		"http://localhost:3005": true,
		"http://127.0.0.1:3000": true,
		"http://127.0.0.1:3005": true,
	}
	for _, extra := range strings.Split(os.Getenv("SOLONGATE_DASHBOARD_ORIGIN"), ",") {
		if e := strings.TrimSpace(extra); e != "" {
			out[e] = true
		}
	}
	return out
}

func setCORS(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && allowedOrigins()[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		// The response body differs by origin — an unlisted one gets no access
		// at all — so a shared cache must not serve one origin's answer to
		// another.
		w.Header().Set("Vary", "Origin")
	}
	// Chrome's Private Network Access: a public page calling loopback sends this
	// on the preflight and refuses to proceed without the matching allow. It is
	// answered only when asked, so the header never appears on a plain request.
	if r.Header.Get("Access-Control-Request-Private-Network") == "true" {
		w.Header().Set("Access-Control-Allow-Private-Network", "true")
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "If-Modified-Since, Content-Type")
}

// target is where this machine's audit entries are landing right now.
//
// It comes from config.LocalLogsSetting, which is the same answer `doctor`, the
// dataroom and `watch` give. That matters more than it looks: this service and
// those views disagreeing about where the log is would show a full log in one
// place and an empty one in the other, with nothing saying which was right.
type target struct {
	// The folder the project asked for, verbatim. Empty when nothing is set.
	configured string
	// The file entries actually land in here, after any fallback. Empty when
	// local logging is not configured on this device at all.
	file string
	// False when the configured folder cannot be used HERE, which is why file
	// may not be inside it.
	usableHere bool
}

func currentTarget() target {
	s := config.LocalLogsSetting()
	// Nothing configured and nothing enabled: there is no log to serve and the
	// dashboard is told so, rather than being handed an empty file that reads
	// as "local logging is on and quiet".
	if !s.Enabled && s.ConfiguredPath == "" {
		return target{}
	}
	return target{configured: s.ConfiguredPath, file: s.File, usableHere: s.UsableHere}
}

type logFileInfo struct {
	exists bool
	size   int64
	mtime  time.Time
}

func statLog(file string) logFileInfo {
	if file == "" {
		return logFileInfo{}
	}
	st, err := os.Stat(file)
	if err != nil {
		return logFileInfo{}
	}
	return logFileInfo{exists: true, size: st.Size(), mtime: st.ModTime()}
}

// health is the shape the dashboard reads to explain itself to the user: which
// folder was asked for, which one is in use, and whether anything is in it. The
// nullable fields are pointers because the dashboard distinguishes "not
// configured" from "configured and empty".
type health struct {
	OK             bool    `json:"ok"`
	Agent          string  `json:"agent"`
	ConfiguredPath *string `json:"configuredPath"`
	ResolvedDir    *string `json:"resolvedDir"`
	File           *string `json:"file"`
	Exists         bool    `json:"exists"`
	Size           int64   `json:"size"`
	MTime          *string `json:"mtime"`
}

func orNull(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func handler() http.Handler { return http.HandlerFunc(handle) }

func handle(w http.ResponseWriter, r *http.Request) {
	setCORS(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// EscapedPath, not Path: the route is matched as it arrived on the wire, so
	// a percent-encoded spelling cannot reach a handler the caller did not
	// literally name.
	switch r.URL.EscapedPath() {
	case "/health":
		serveHealth(w)
	case "/local-logs":
		serveLog(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "not found")
	}
}

func serveHealth(w http.ResponseWriter) {
	t := currentTarget()
	info := statLog(t.file)
	dir := ""
	if t.file != "" {
		dir = filepath.Dir(t.file)
	}
	body := health{
		OK:             true,
		Agent:          "solongate-logs-server",
		ConfiguredPath: orNull(t.configured),
		ResolvedDir:    orNull(dir),
		File:           orNull(t.file),
		Exists:         info.exists,
		Size:           info.size,
	}
	if info.exists {
		// The same spelling Date#toISOString produces, because the dashboard
		// parses this string and the Node implementation is what it was written
		// against.
		stamp := info.mtime.UTC().Format("2006-01-02T15:04:05.000Z")
		body.MTime = &stamp
	}
	b, err := json.Marshal(body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func serveLog(w http.ResponseWriter, r *http.Request) {
	t := currentTarget()

	// Both "nothing configured" and "configured but empty" answer 200 with an
	// empty body and differ only in the header. The dashboard polls this; an
	// error status for a machine that simply has local logging off would show
	// up as the link being broken.
	if t.file == "" {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Solongate-Configured", "0")
		w.WriteHeader(http.StatusOK)
		return
	}
	info := statLog(t.file)
	if !info.exists {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Solongate-Exists", "0")
		w.WriteHeader(http.StatusOK)
		return
	}

	lastMod := info.mtime.UTC().Format(http.TimeFormat)
	// Conditional GET. The dashboard polls, and this file grows for as long as
	// the machine is working, so re-sending it every few seconds is the whole
	// cost of the feature. Compared at one-second granularity because that is
	// all Last-Modified carries: a modification in the same second as the
	// stamp the client holds has to count as unchanged, or every poll is a
	// full transfer.
	if since := r.Header.Get("If-Modified-Since"); since != "" {
		if ts, err := http.ParseTime(since); err == nil && !ts.Before(info.mtime.Truncate(time.Second)) {
			w.Header().Set("Last-Modified", lastMod)
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	b, err := tailBytes(t.file, maxServedBytes)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "read error")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Last-Modified", lastMod)
	w.Header().Set("X-Solongate-Exists", "1")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// maxServedBytes bounds one response, and with it the memory this service can be
// made to allocate.
//
// The log is append-only with no rotation anywhere: it grows for as long as the
// machine works. Reading the whole file per request was fine on the first day and
// is not on the hundredth — and this endpoint is POLLED every few seconds, so the
// allocation is not once but continuous. Sixteen megabytes is the same bound the
// dataroom's own reader uses for the same file, so the two agree about how much
// history is on offer.
const maxServedBytes = 16 * 1024 * 1024

// tailBytes returns at most max bytes from the END of a file, starting at a line
// boundary.
//
// The END rather than the start, because this is a log and the recent entries are
// the ones a reader wants. The first line of a mid-file read is dropped: it is
// almost certainly a fragment, and a fragment that happens to parse as JSON is
// worse than one that does not — it would show up as a call that never occurred.
// Same rule, for the same reason, as the dataroom's tailLines.
func tailBytes(file string, max int64) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	start := info.Size() - max
	if start <= 0 {
		return io.ReadAll(f)
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[i+1:]
	}
	return b, nil
}

// serve runs the service in the foreground. This is what the detached daemon
// re-enters as, and what a user gets from a bare `solongate logs-server`.
func serve(port int) int {
	// "127.0.0.1" and not ":" or "localhost": an explicit IPv4 loopback literal
	// cannot resolve to a wildcard bind, and this machine's audit log must not
	// be reachable from the network the laptop is on.
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		if addrInUse(err) {
			fmt.Fprintf(os.Stderr, "[SolonGate] Port %d is already in use. Pass --port <n> or set SOLONGATE_LOGS_PORT.\n", port)
		} else {
			fmt.Fprintf(os.Stderr, "[SolonGate] Local logs agent error: %s\n", err)
		}
		return 1
	}

	// Any start is also an enable, and the pid recorded here is this process:
	// the state file is how the dataroom and the other implementation find the
	// running service, so it has to name whoever actually holds the port.
	recordStarted(port)
	printBanner(port)

	srv := &http.Server{
		Handler: handler(),
		// A loopback service still has to survive a browser tab that opens a
		// connection and never finishes a request; without a header deadline
		// those accumulate for as long as the daemon lives.
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "[SolonGate] Local logs agent error: %s\n", err)
		return 1
	}
	return 0
}

// printBanner goes to stdout, which for the daemon is ~/.solongate/logs-server.log.
// It is the only record of what a service that came up and served nothing was
// actually looking at.
func printBanner(port int) {
	fmt.Printf("[SolonGate] Local logs agent listening on http://127.0.0.1:%d\n", port)
	t := currentTarget()
	switch {
	case t.configured == "":
		fmt.Print("[SolonGate] Local log storage not configured yet (set it in dashboard Settings).\n")
	case !t.usableHere:
		// The folder is a PROJECT setting shared by every device on it, so it
		// can name a path that only exists on another machine. The hooks fall
		// back quietly; saying which folder is really being read is the
		// difference between "the dashboard link is broken" and "that path is
		// not here".
		trimmed := strings.TrimRight(strings.TrimSpace(t.configured), `/\`)
		fmt.Printf("[SolonGate] Configured path: %s\n", t.configured)
		if !filepath.IsAbs(trimmed) {
			fmt.Printf("[SolonGate] That path isn't absolute on this machine — reading from: %s\n", filepath.Dir(t.file))
		} else {
			fmt.Printf("[SolonGate] That folder isn't on this machine — reading from: %s\n", filepath.Dir(t.file))
		}
	default:
		fmt.Printf("[SolonGate] Configured path: %s\n", t.configured)
	}
	fmt.Print("[SolonGate] Keep this running; the dashboard reads your logs live from here. Ctrl+C to stop.\n")
}

// addrInUse names the one bind failure with a useful next step. The POSIX errno
// and the Windows one are different values and the Windows constant is not
// defined everywhere this builds, so the message is checked as well.
func addrInUse(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") ||
		strings.Contains(msg, "only one usage of each socket address")
}

// chosenPort resolves the port for a foreground run.
//
// The environment variable wins over --port outright rather than being one of
// two candidates: `SOLONGATE_LOGS_PORT=abc` selects the default and the --port
// flag is not consulted, matching the `Number(env || flag || default) ||
// default` chain the Node implementation resolves this with. Getting that
// backwards would mean the two implementations bound to different ports from
// the same environment.
func chosenPort(args []string) int {
	raw := os.Getenv("SOLONGATE_LOGS_PORT")
	if raw == "" {
		for i, a := range args {
			if a == "--port" {
				if i+1 < len(args) {
					raw = args[i+1]
				}
				break
			}
		}
	}
	if p, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && p > 0 && p <= 65535 {
		return p
	}
	return DefaultPort
}

// Run is `solongate logs-server` / `solongate local-logs`.
//
// A bare invocation serves in the foreground. The three verbs manage the
// service, and `stop` is the one worth reading twice: it disables as well as
// kills, because everything else about this design brings the service back.
func Run(args []string) int {
	verb := ""
	if len(args) > 0 {
		verb = args[0]
	}
	switch verb {
	case "start":
		Start()
		// The child has to reach its listen call before its state means
		// anything. Without this pause a start that worked reports itself as a
		// failure, and the user's next move is to start it again.
		time.Sleep(800 * time.Millisecond)
		st := CurrentStatus()
		if st.Running {
			fmt.Printf("[SolonGate] Local logs service running on http://127.0.0.1:%d — background service, survives closing this terminal. Disable: solongate logs-server stop\n", st.Port)
		} else {
			fmt.Printf("[SolonGate] Could not start the local logs service — see %s\n", config.LogsServerLogPath())
		}
		return 0
	case "stop":
		Stop()
		fmt.Print("[SolonGate] Local logs service stopped and disabled (re-enable from the dataroom Settings or with `solongate logs-server start`).\n")
		return 0
	case "status":
		st := CurrentStatus()
		state := "stopped"
		if st.Running {
			state = fmt.Sprintf("running on http://127.0.0.1:%d (pid %d)", st.Port, st.Pid)
		}
		fmt.Printf("[SolonGate] Local logs service: %s · desired %s\n", state, st.Desired)
		return 0
	}
	return serve(chosenPort(args))
}
