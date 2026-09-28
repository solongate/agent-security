package sgshared

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Whether this machine is under somebody else's policy.
//
// A guest is a developer whose key opens their HOST's project: the host writes
// one policy and every machine in the fleet enforces it. The API decides that
// and says so on every policy poll, but the guard has to know it BEFORE it
// decides which credential to trust, and by then it has not polled anything.
// So the last answer is kept here, in one file, and it is read first.
//
// One file and not a field on the policy cache, deliberately. The cache is
// per-agent and its filename comes from SOLONGATE_AGENT_ID, so a guest could
// name an agent nobody has ever used, get no cache, and be unmanaged by
// construction. This has no such handle: there is one path and it does not
// depend on anything the environment can say.
//
// It is tamper-protected, so an agent tool call naming it is denied: see the
// glob and the basename list in packages/guard-go/tamper.go. It is NOT
// OS-locked — an earlier version of this comment said it was, and that was
// never true. The lock list in packages/proxy-go/internal/install/paths.go
// holds the four hooks, the client config files and the guard binary, and this
// file is not among them. A program running as the user can therefore remove
// it, which reads as "not managed" until the next successful poll writes it
// back. Closing that gap means adding it to the lock list and teaching `repair`
// about it, which is a change to the install path rather than to this file.

// FleetState is the file.
type FleetState struct {
	// Managed is the whole point. False is also what an absent file means, so a
	// machine that has never polled, or whose file was removed, behaves exactly
	// as every machine did before fleets existed.
	Managed bool `json:"managed"`
	// ProjectID is the project this machine is bound to while managed. It is
	// recorded so a credential presented from the environment can be compared
	// against the one the machine was paired with rather than merely against
	// "some key".
	ProjectID string `json:"projectId,omitempty"`
	// TS is when this was last written, in milliseconds, matching the other
	// state files the Node hook writes.
	TS int64 `json:"_ts"`
}

// FleetStatePath is the one location.
func FleetStatePath() string { return filepath.Join(SGDir(), ".fleet.json") }

// LoadFleet reads it. Every failure is the zero value, which is "not managed":
// an unreadable file must not lock a machine that was never in a fleet, and a
// machine that IS in one gets its answer back on the next successful poll.
func LoadFleet() FleetState {
	b, err := os.ReadFile(FleetStatePath())
	if err != nil {
		return FleetState{}
	}
	var f FleetState
	if json.Unmarshal(b, &f) != nil {
		return FleetState{}
	}
	return f
}

// SaveFleet records what the last poll said.
//
// It writes only when something CHANGED. This runs on the guard's hot path,
// behind every tool call, and rewriting an identical file each time would be a
// disk write per call and — worse — a file whose mtime moves constantly, which
// is exactly what a tamper check is watching for.
func SaveFleet(f FleetState) error {
	prev := LoadFleet()
	if prev.Managed == f.Managed && prev.ProjectID == f.ProjectID {
		return nil
	}
	f.TS = time.Now().UnixMilli()
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if err := EnsureSGDir(); err != nil {
		return err
	}
	return os.WriteFile(FleetStatePath(), b, 0o644)
}
