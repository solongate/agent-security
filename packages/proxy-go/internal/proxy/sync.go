package proxy

import (
	"context"
	"os"
	"strconv"
	"sync"
	"time"
)

// Watches the policy file and reloads the policy when it changes. Kept in step with
// packages/proxy/src/sync.ts.
//
//	the file changes → the running proxy enforces the new rules
//
// It WAS bidirectional — the file pushed up, the cloud written down, a version number
// deciding which was newer and the cloud winning ties — and most of the care in it
// went on the loop that arrangement creates: a write caused by a poll must not read
// as a person's edit and get pushed straight back. One direction remains, and it is
// the one that was always doing the work. The file is the source of truth; nothing
// here writes to it.

// SyncOptions configures one manager.
type SyncOptions struct {
	// LocalPath is the policy file to watch. It used to be allowed to be empty,
	// meaning "the policy lives in the cloud and is polled"; there is nowhere else a
	// policy can live now, so empty means no policy and the default applies.
	LocalPath string
	// WatchInterval is how often the local file is checked. It defaults to a
	// second, which is fast enough that an edit feels immediate and slow enough
	// to be free. Tests shorten it; nothing else should.
	WatchInterval time.Duration
	Initial       PolicyDoc
	// OnPolicyUpdate is called with every accepted policy, from either
	// direction. It runs on the sync's own goroutine, so a slow reload delays
	// the next poll rather than racing it.
	OnPolicyUpdate func(PolicyDoc)
	Log            func(string)
}

// SyncManager watches both ends.
type SyncManager struct {
	opts SyncOptions

	mu      sync.Mutex
	current PolicyDoc

	cancel context.CancelFunc
	done   sync.WaitGroup
}

// NewSyncManager builds a manager. Nothing runs until Start.
func NewSyncManager(opts SyncOptions) *SyncManager {
	if opts.WatchInterval <= 0 {
		opts.WatchInterval = time.Second
	}
	if opts.Log == nil {
		opts.Log = func(string) {}
	}
	return &SyncManager{opts: opts, current: opts.Initial}
}

// Start begins watching the file and polling the cloud.
func (m *SyncManager) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	if m.opts.LocalPath != "" {
		if _, err := os.Stat(m.opts.LocalPath); err == nil {
			m.done.Add(1)
			go func() {
				defer m.done.Done()
				m.watchFile(ctx)
			}()
			m.opts.Log("Watching " + m.opts.LocalPath + " for changes")
		}
	}

}

// Stop ends both loops and waits for them.
//
// Waiting matters: a poller still running after the proxy it belongs to has
// gone is what rewrites a policy file a minute after the process was supposed
// to have exited.
func (m *SyncManager) Stop() {
	if m.cancel == nil {
		return
	}
	m.cancel()
	m.done.Wait()
}

// ── the local file ─────────────────────────────────────────────────────────

// watchFile polls the file's modification time rather than subscribing to
// filesystem events.
//
// A one-second poll of one file costs nothing, and the alternative is a
// dependency: this module has no fsnotify, and adding one to notice an edit
// half a second sooner is not a trade worth making. The debounce the Node
// implementation needs — editors write a file two or three times — comes free,
// because a poll only ever sees the settled result.
func (m *SyncManager) watchFile(ctx context.Context) {
	ticker := time.NewTicker(m.opts.WatchInterval)
	defer ticker.Stop()

	var lastMod time.Time
	var lastSize int64
	if info, err := os.Stat(m.opts.LocalPath); err == nil {
		lastMod, lastSize = info.ModTime(), info.Size()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		info, err := os.Stat(m.opts.LocalPath)
		if err != nil {
			// A deleted policy file does NOT clear the policy. Enforcement
			// carries on with what is loaded: an editor's atomic save briefly
			// removes the file, and treating that as "no rules" would open a
			// window with nothing enforced every time somebody saves.
			if !lastMod.IsZero() {
				m.opts.Log("Policy file deleted — keeping current policy")
				lastMod, lastSize = time.Time{}, 0
			}
			continue
		}
		if info.ModTime().Equal(lastMod) && info.Size() == lastSize {
			continue
		}
		lastMod, lastSize = info.ModTime(), info.Size()
		m.onFileChange(ctx)
	}
}

// onFileChange reloads the policy from the file.
//
// IT NO LONGER WRITES TO THE FILE. Two things used to make it write, and both were
// about the far end of a sync:
//
// The version bump — an edit that did not raise the version got one raised for it
// and the file rewritten, "or the cloud will not accept it as newer and the edit
// silently does nothing". Nothing has to accept it now; the rules in the file are in
// force the moment they parse. Rewriting a file a person is editing to change a
// field they did not touch is a bad trade for a number only a status line reads, and
// it fights every editor that holds the buffer open.
//
// The self-write guard — a ModTime change caused by our own write had to be told
// apart from a person's, or the poll pushed back up the policy it had just pulled.
// With no write of our own, there is no ambiguity left to resolve.
func (m *SyncManager) onFileChange(ctx context.Context) {
	raw, err := os.ReadFile(m.opts.LocalPath)
	if err != nil {
		m.opts.Log("File read error: " + err.Error())
		return
	}
	doc, err := DecodePolicyDoc(raw)
	if err != nil {
		// A file that will not parse is NOT treated as an empty policy. The
		// loaded one stays in force until the file is valid again — half a
		// policy is worse than a stale one.
		m.opts.Log("File read error: " + err.Error())
		return
	}

	m.mu.Lock()
	current := m.current
	m.mu.Unlock()

	// RULES, not the version, decide whether this is a change: a person who edits a
	// rule and leaves the version alone has still changed the policy, and that is the
	// normal way to edit a file by hand.
	if RulesEqual(doc, current) {
		return
	}

	m.opts.Log("File changed: " + doc.Set.Name + " v" + strconv.Itoa(doc.Set.Version))
	m.mu.Lock()
	m.current = doc
	m.mu.Unlock()

	if m.opts.OnPolicyUpdate != nil {
		m.opts.OnPolicyUpdate(doc)
	}
}
