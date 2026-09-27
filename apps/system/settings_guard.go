package main

// GET /v1/settings/guard-status: the port of
// src/app/api/v1/settings/guard-status/route.ts and the read half of
// src/lib/guard-version.ts.
//
// This is the answer both the dashboard and `solongate doctor` render as "is
// this device protected", in the same words, so the two must agree. They did
// not once before: `doctor` reads the machine's own files and answers "is the
// guard REGISTERED for this client", while this endpoint used to answer "which
// client last called in" — a client installed but not opened in a week showed
// as guarded in the terminal and unguarded in the dashboard. The fix is that
// the device reports its registration list on every policy poll and this reads
// that; `agents` survives only as the fallback for a device whose guard has not
// polled since.
//
// The write half — recording what a poll reports — belongs to
// /v1/policies/active and lives in policies_active.go. guardDeviceEntry is
// shared with it rather than redeclared, because a second reading of that map
// is a second answer to "is this project guarded".

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sort"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/hookbundle"
	"github.com/codeyevsky/solongate/system/internal/store"
)

func init() {
	Register("GET /api/v1/settings/guard-status", func(s *server) http.Handler {
		return s.auth.WithAuth(s.settingsGuardStatus)
	})
}

// guardedClients are the clients named in the UI, in the order the panel lists
// them. Anything else a device reports is stored and simply not surfaced, which
// is what lets a new client appear in the fleet before this list is updated.
var guardedClients = []string{"claude-code", "antigravity", "codex", "opencode"}

// guardClientLabels is src/lib/guard-version.ts's CLIENT_LABELS. The strings
// are what the dashboard prints; an unknown agent falls back to its own id.
var guardClientLabels = map[string]string{
	"claude-code": "Claude hooks",
	"antigravity": "Antigravity hooks",
	"codex":       "Codex hooks",
	"opencode":    "OpenCode hooks",
}

// guardStatusClient is one row of the response's `clients` array.
//
// last_seen is a POINTER because null is the answer for a client that has never
// called in, and the dashboard tests it for null to decide between "never" and
// a date. Zero would render as 1970.
type guardStatusClient struct {
	Agent      string `json:"agent"`
	Label      string `json:"label"`
	Registered bool   `json:"registered"`
	LastSeen   *int64 `json:"last_seen"`
}

type guardStatusResponse struct {
	Latest        int64               `json:"latest"`
	Installed     *int64              `json:"installed"`
	UpToDate      bool                `json:"up_to_date"`
	DeviceCount   int                 `json:"device_count"`
	OutdatedCount int                 `json:"outdated_count"`
	Clients       []guardStatusClient `json:"clients"`
}

func (s *server) settingsGuardStatus(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	latest := int64(0)
	if b, ok := hookbundle.Get("guard"); ok {
		latest = b.Version
	}

	devices := s.guardDevices(r.Context(), key.ProjectID, store.NowMS())

	// `installed` is the LOWEST version in the fleet, because the devices are
	// sorted ascending and the original takes the first. That is the useful
	// answer for a banner that says "update your guard": one stale laptop is
	// what the project needs to hear about, not the newest one.
	var installed *int64
	outdated := 0
	for _, d := range devices {
		if d.Version < latest {
			outdated++
		}
	}
	if len(devices) > 0 {
		v := devices[0].Version
		installed = &v
	}

	clients := make([]guardStatusClient, 0, len(guardedClients))
	for _, agent := range guardedClients {
		label, named := guardClientLabels[agent]
		if !named {
			label = agent
		}
		clients = append(clients, guardStatusClient{
			Agent:      agent,
			Label:      label,
			Registered: guardRegistered(devices, agent),
			LastSeen:   guardLastSeen(devices, agent),
		})
	}

	apiauth.JSON(w, http.StatusOK, guardStatusResponse{
		Latest:        latest,
		Installed:     installed,
		UpToDate:      installed != nil && *installed >= latest,
		DeviceCount:   len(devices),
		OutdatedCount: outdated,
		Clients:       clients,
	})
}

// guardRegistered answers the question `doctor` and `repair` answer: is the
// guard registered for this client anywhere in the project.
//
// A device that reports a client list is believed about its OWN files and
// nothing else — only the machine can see them. A device that reports none
// falls back to `agents`, the older "has called in" signal, so an un-updated
// machine degrades to a weaker answer rather than to "missing".
func guardRegistered(devices []guardDevice, agent string) bool {
	for _, d := range devices {
		if len(d.Clients) > 0 {
			for _, c := range d.Clients {
				if c == agent {
					return true
				}
			}
			continue
		}
		if _, seen := d.Agents[agent]; seen {
			return true
		}
	}
	return false
}

// guardLastSeen is the newest timestamp any device recorded for this client, in
// milliseconds, or nil when none did.
func guardLastSeen(devices []guardDevice, agent string) *int64 {
	var newest *int64
	for _, d := range devices {
		t, seen := d.Agents[agent]
		if !seen {
			continue
		}
		if newest == nil || t > *newest {
			v := t
			newest = &v
		}
	}
	return newest
}

// guardDevice is one live device, as the response needs it.
type guardDevice struct {
	ID       string
	Version  int64
	LastSeen int64
	Agents   map[string]int64
	Clients  []string
}

// guardDevices reads the per-device map and drops the rows that are no longer
// live, then writes the pruned map back.
//
// A device is identified by the API KEY it authenticated with, so a revoked key
// retires its device: that is what makes "device_count" the number of machines
// currently able to poll rather than the number that ever have. Losing the
// api_keys query keeps every device instead of pruning them all — a database
// blip must not report a project's whole fleet as retired, which is the shape
// of a "you are unprotected" banner shown to somebody who is not.
//
// Everything here is best-effort, as the original is: an unreadable row is an
// empty fleet and a failed write is dropped. This is a GET, and telemetry
// housekeeping must not be able to fail the answer.
func (s *server) guardDevices(ctx context.Context, projectID string, nowMS int64) []guardDevice {
	stored := map[string]guardDeviceEntry{}
	if raw, ok, err := s.store.SettingJSON(ctx, store.SettingGuardVersions, projectID); err == nil && ok && raw != "" {
		if json.Unmarshal([]byte(raw), &stored) != nil {
			stored = map[string]guardDeviceEntry{}
		}
	}
	if len(stored) == 0 {
		return nil
	}

	live, err := s.store.LiveKeyIDs(ctx, projectID)
	if err != nil {
		live = nil
	}

	kept := map[string]guardDeviceEntry{}
	out := make([]guardDevice, 0, len(stored))
	for id, d := range stored {
		if live != nil && !live[id] {
			continue
		}
		if nowMS-d.TS > guardActiveWindow.Milliseconds() {
			continue
		}
		kept[id] = d
		out = append(out, guardDevice{
			ID:       id,
			Version:  d.Version,
			LastSeen: d.TS,
			Agents:   d.Agents,
			Clients:  d.Clients,
		})
	}

	// Ascending by version, and by id within a version so the answer does not
	// depend on Go's map iteration order. The original sorts by version alone;
	// nothing in the response distinguishes two devices on the same version.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].ID < out[j].ID
	})

	if len(kept) != len(stored) {
		s.pruneGuardDevices(ctx, projectID, kept)
	}
	return out
}

// pruneGuardDevices writes back the map with the retired devices removed.
//
// A write from a GET looks wrong and is what the original does, for a reason
// that only shows up over months: the map has no other reader that could clean
// it, and a project that reimages laptops accumulates a row per machine per
// lifetime in a single settings value. Nothing depends on it succeeding.
//
// The failure is logged with the project id and not the device ids: a device id
// is an API key's row id, and a log listing them is a list of what to go
// looking for.
func (s *server) pruneGuardDevices(ctx context.Context, projectID string, kept map[string]guardDeviceEntry) {
	value, err := marshalNoEscape(kept)
	if err != nil {
		return
	}
	if err := s.store.SetSettingJSON(ctx, store.SettingGuardVersions, projectID, string(value),
		"Per-device guard hook versions"); err != nil {
		log.Printf("api: could not prune retired guard devices for project %s: %v", projectID, err)
	}
}
