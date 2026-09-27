package proxy

import (
	"context"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/api"
	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// Bidirectional policy sync between the local JSON file and the SolonGate
// cloud, ported from packages/proxy/src/sync.ts.
//
//	local file changes  → pushed to the cloud
//	cloud changes       → written to the local file
//
// The version number decides which is newer, and the cloud wins a tie. The one
// thing that has to be got right is the loop: a write triggered by a poll must
// not read as a user edit and get pushed straight back up, which is how two
// ends of a sync spend an afternoon incrementing a version at each other.

// SyncOptions configures one manager.
type SyncOptions struct {
	// LocalPath is the policy file to watch, empty when the policy is
	// cloud-only.
	LocalPath string
	APIKey    string
	Client    *api.Client
	// PollInterval defaults to a minute.
	PollInterval time.Duration
	// WatchInterval is how often the local file is checked. It defaults to a
	// second, which is fast enough that an edit feels immediate and slow enough
	// to be free. Tests shorten it; nothing else should.
	WatchInterval time.Duration
	// PolicyID comes from --policy-id and is the ONLY source of truth for which
	// cloud policy this proxy pushes to. The id inside the local file is a
	// fallback for when the flag was not given.
	PolicyID string
	Initial  PolicyDoc
	// OnPolicyUpdate is called with every accepted policy, from either
	// direction. It runs on the sync's own goroutine, so a slow reload delays
	// the next poll rather than racing it.
	OnPolicyUpdate func(PolicyDoc)
	Log            func(string)
}

// SyncManager watches both ends.
type SyncManager struct {
	opts SyncOptions

	mu            sync.Mutex
	current       PolicyDoc
	localVersion  int
	cloudVersion  int
	lastWriteTime time.Time

	cancel context.CancelFunc
	done   sync.WaitGroup
	// isLiveKey gates everything that talks to the cloud. A test key syncs with
	// the local file and nothing else — it has no account to sync against, and
	// pushing under one would write into whatever project the key happens to
	// resolve to.
	isLiveKey bool
}

// NewSyncManager builds a manager. Nothing runs until Start.
func NewSyncManager(opts SyncOptions) *SyncManager {
	if opts.PollInterval <= 0 {
		opts.PollInterval = 60 * time.Second
	}
	if opts.WatchInterval <= 0 {
		opts.WatchInterval = time.Second
	}
	if opts.Log == nil {
		opts.Log = func(string) {}
	}
	return &SyncManager{
		opts:         opts,
		current:      opts.Initial,
		localVersion: opts.Initial.Set.Version,
		isLiveKey:    isLiveKey(opts.APIKey),
	}
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

	if m.isLiveKey {
		// The first push is fire and forget. It is how a machine that has only
		// ever had a local policy gets one into the dashboard, and a failure
		// there must not stop the proxy from starting.
		m.done.Add(1)
		go func() {
			defer m.done.Done()
			pushCtx, pushCancel := context.WithTimeout(ctx, 30*time.Second)
			defer pushCancel()
			m.mu.Lock()
			doc := m.current
			m.mu.Unlock()
			_, _ = pushPolicy(pushCtx, m.opts.Client, m.cloudID(doc), doc)
		}()

		m.done.Add(1)
		go func() {
			defer m.done.Done()
			m.pollCloud(ctx)
		}()
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

func (m *SyncManager) onFileChange(ctx context.Context) {
	m.mu.Lock()
	sinceOwnWrite := time.Since(m.lastWriteTime)
	m.mu.Unlock()
	// Our own write, coming back as a change. Without this the poll below
	// pushes the policy it just pulled.
	if sinceOwnWrite < time.Second {
		return
	}

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
	localVersion, cloudVersion, current := m.localVersion, m.cloudVersion, m.current
	m.mu.Unlock()

	// An edit that did not bump the version still has to become a new version,
	// or the cloud will not accept it as newer and the edit silently does
	// nothing.
	if doc.Set.Version <= localVersion {
		next := localVersion
		if cloudVersion > next {
			next = cloudVersion
		}
		doc.SetVersion(next + 1)
		m.writeToFile(doc)
	}

	if RulesEqual(doc, current) {
		return
	}

	m.opts.Log("File changed: " + doc.Set.Name + " v" + strconv.Itoa(doc.Set.Version))
	m.mu.Lock()
	m.localVersion = doc.Set.Version
	m.current = doc
	m.mu.Unlock()

	if m.opts.OnPolicyUpdate != nil {
		m.opts.OnPolicyUpdate(doc)
	}

	if !m.isLiveKey {
		return
	}
	pushCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	version, err := pushPolicy(pushCtx, m.opts.Client, m.cloudID(doc), doc)
	if err != nil {
		m.opts.Log("Cloud push failed: " + err.Error())
		return
	}
	m.mu.Lock()
	m.cloudVersion = version
	m.mu.Unlock()
	m.opts.Log("Pushed to cloud: v" + strconv.Itoa(version))
}

// writeToFile rewrites the local policy, remembering when so the watcher can
// tell its own write from a person's.
//
// It goes through config.WriteProtectedFile because the policy file may carry
// the self-protection OS lock. A plain write to a locked file fails with EPERM,
// and a sync that swallowed that would report a cloud update as applied while
// the file on disk still held the old rules.
func (m *SyncManager) writeToFile(doc PolicyDoc) {
	if m.opts.LocalPath == "" {
		return
	}
	body, err := EncodeIndented(doc.WithoutID())
	if err != nil {
		m.opts.Log("File write error: " + err.Error())
		return
	}
	m.mu.Lock()
	m.lastWriteTime = time.Now()
	m.mu.Unlock()
	if !config.WriteProtectedFile(m.opts.LocalPath, body) {
		m.opts.Log("File write error: could not write " + m.opts.LocalPath)
	}
}

// ── the cloud ──────────────────────────────────────────────────────────────

func (m *SyncManager) pollCloud(ctx context.Context) {
	ticker := time.NewTicker(m.opts.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		m.onPollTick(ctx)
	}
}

func (m *SyncManager) onPollTick(ctx context.Context) {
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	doc, err := fetchCloudPolicy(reqCtx, m.opts.Client, m.opts.PolicyID)
	if err != nil {
		// Silent. A poll that cannot reach the API is the ordinary state of a
		// laptop, and logging it every minute buries everything else in the
		// proxy's stderr.
		return
	}

	m.mu.Lock()
	localVersion, current := m.localVersion, m.current
	m.mu.Unlock()

	same := RulesEqual(doc, current)
	// Nothing new: the cloud is not ahead, and its rules are the loaded ones.
	if doc.Set.Version <= localVersion && same {
		return
	}
	if doc.Set.Version <= localVersion {
		// Not ahead, but different. The cloud wins a tie — without that rule
		// the two ends disagree and neither of them ever moves.
		m.opts.Log("Cloud differs at v" + strconv.Itoa(doc.Set.Version) + " — cloud wins")
	}

	m.opts.Log("Cloud update: " + doc.Set.Name + " v" + strconv.Itoa(doc.Set.Version) +
		" (was v" + strconv.Itoa(localVersion) + ")")

	m.mu.Lock()
	m.cloudVersion = doc.Set.Version
	m.localVersion = doc.Set.Version
	m.current = doc
	m.mu.Unlock()

	if m.opts.OnPolicyUpdate != nil {
		m.opts.OnPolicyUpdate(doc)
	}

	if m.opts.LocalPath != "" {
		m.writeToFile(doc)
		m.opts.Log("Updated local file: " + m.opts.LocalPath)
	}
}

// cloudID is which cloud policy this proxy writes to. The --policy-id flag
// beats the id inside the file, and "default" is the last resort.
func (m *SyncManager) cloudID(doc PolicyDoc) string {
	if m.opts.PolicyID != "" {
		return m.opts.PolicyID
	}
	if doc.Set.ID != "" {
		return doc.Set.ID
	}
	return "default"
}
