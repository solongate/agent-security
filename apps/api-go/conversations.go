package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codeyevsky/solongate/api/internal/apiauth"
	"github.com/codeyevsky/solongate/api/internal/store"
)

// The conversation half of a fleet: what a person wrote to their agent and what
// it wrote back.
//
// Everything else this service ingests is a record of what a MACHINE did. This
// is a record of what a PERSON said, and it is gated harder than anything else
// here as a result. Three refusals, in the order they are cheapest to answer:
//
//	NOT IN A FLEET. A turn from an account with no accepted grant is dropped.
//	Installing the guard must not start collecting somebody's conversation; the
//	only thing that does is accepting an invitation, which says so on the
//	button. This is checked on the SERVER and not only in the hook, because a
//	hook is on the guest's machine and a check that lives there is a check the
//	guest can remove.
//
//	NOT A ROLE WE KNOW. A prompt filed as a reply is a host reading words the
//	agent never said, so an unrecognised role is refused rather than defaulted.
//
//	NOT ENDLESS. The body is clipped and the row says it was clipped.
//
// What this route does NOT do is redact. That happens on the machine, before
// the text is sent, and it has to: a guard that strips a secret out of a tool
// result and then ships the same secret because somebody pasted it into a
// prompt is a leak with the product's name on it. The `redacted` flag here
// records that the sender did it, so a host reading a masked line knows it was
// masked rather than typed that way.

// TurnRetention is how long a stored conversation is kept.
//
// Ninety days, and the number matters less than the fact that there IS one.
// audit_logs, sessions, agents and anomaly_events all grow forever in this
// schema, which has been survivable because a ledger row is small and boring.
// What is stored here is neither: it is the most sensitive thing this service
// holds, and keeping it after the arrangement that justified it has ended is a
// liability rather than a feature. A host who needs longer than a quarter is
// asking for something this table should not be the answer to.
const TurnRetention = 90 * 24 * time.Hour

// turnPurgeInterval is how often the sweep runs.
//
// Hourly rather than by the minute like the nonce purge: nonces expire in
// seconds and a stale one is a security question, while a turn a few hours past
// its ninetieth day is only a row.
const turnPurgeInterval = time.Hour

var turnPurgeOnce sync.Once

// startTurnPurge deletes conversations past the retention window.
//
// Best-effort, and its failure is logged rather than surfaced: a sweep that did
// not run leaves rows behind for an hour, and a sweep that refused a request
// would turn housekeeping into an outage. It is the same shape as the nonce
// purge in tokens.go, for the same reasons.
func startTurnPurge(s *server) {
	turnPurgeOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(turnPurgeInterval)
			defer ticker.Stop()
			for range ticker.C {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				cutoff := time.Now().Add(-TurnRetention).Unix()
				if n, err := s.store.PruneTurns(ctx, cutoff); err != nil {
					log.Printf("[API:conversations] retention sweep failed: %v", err)
				} else if n > 0 {
					log.Printf("[API:conversations] retention sweep removed %d turns", n)
				}
				cancel()
			}
		}()
	})
}

func init() {
	Register("POST /api/v1/conversations", buildConversationHandler((*server).createConversationTurn))
	Register("GET /api/v1/conversations", buildConversationHandler((*server).listConversationTurns))
}

func buildConversationHandler(fn func(*server, http.ResponseWriter, *http.Request, apiauth.KeyInfo)) func(*server) http.Handler {
	return func(s *server) http.Handler {
		return s.auth.WithAuth(func(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
			fn(s, w, r, key)
		})
	}
}

// turnRequest is one half of one exchange, as a hook sends it.
type turnRequest struct {
	SessionID string `json:"session_id"`
	Role      string `json:"role"`
	Body      string `json:"body"`
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	Source    string `json:"source"`
	Redacted  bool   `json:"redacted"`
}

func (s *server) createConversationTurn(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	ctx := r.Context()

	// The gate, and it is deliberately the first thing. A machine on a project
	// that runs no fleet has nobody to show this to, so there is no reason to
	// hold it — and 204 rather than 403, because a guard sending this to a
	// project that stopped being a fleet is not doing anything wrong and must
	// not start retrying.
	//
	// The turn is stored under the account the key acts as, on that key's own
	// project. There is no second party: the gate here used to ask whether the
	// caller was a guest on somebody else's fleet, and this build has no fleets.
	//
	// ActingUser rather than ActingUserID, because it falls back to the
	// project's owner — a key minted before the user_id column carries no user,
	// and on somebody's own project the owner is them.
	userID := key.ActingUser()

	var body turnRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body) != nil {
		apiauth.BadRequest(w, "Invalid JSON body")
		return
	}

	role, ok := store.NormaliseTurnRole(body.Role)
	if !ok {
		apiauth.BadRequest(w, "role must be prompt or reply")
		return
	}
	session := strings.TrimSpace(body.SessionID)
	if session == "" {
		apiauth.BadRequest(w, "session_id is required")
		return
	}
	text := strings.TrimSpace(body.Body)
	if text == "" {
		// An empty turn is not an error and not a row. A Stop hook fires at the
		// end of every turn including ones that produced no text at all.
		w.WriteHeader(http.StatusNoContent)
		return
	}

	clipped, truncated := store.ClipTurnBody(text)
	turn := store.ConversationTurn{
		ID:        "turn-" + strconv.FormatInt(time.Now().UnixNano(), 36),
		ProjectID: key.ProjectID,
		APIKeyID:  key.KeyID,
		UserID:    userID,
		SessionID: store.Clip(session, 128),
		AgentID:   store.Clip(strings.TrimSpace(body.AgentID), 256),
		AgentName: store.Clip(strings.TrimSpace(body.AgentName), 256),
		Source:    store.Clip(strings.TrimSpace(body.Source), 64),
		Role:      role,
		Body:      clipped,
		Redacted:  body.Redacted,
		Truncated: truncated,
		CreatedAt: time.Now().Unix(),
	}
	if err := s.store.InsertTurn(ctx, turn); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"stored": true, "truncated": truncated})
}

// listConversationTurns is the host's read, and it is the host's ONLY read.
//
// There is no route here that lets somebody read their own turns back, because
// nothing needs one: the person who wrote them has them on their own machine,
// in the agent's transcript. The one reason this data is in the cloud at all is
// that a host is answerable for a fleet, so a host asking about one member is
// the whole of the read surface.
func (s *server) listConversationTurns(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	ctx := r.Context()
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}

	// The caller's own turns on their own project. The subject used to be a
	// parameter a host could point at one member of their fleet; with no fleet
	// there is one subject and it is the caller.
	turns, err := s.store.TurnsFor(ctx, key.ProjectID, key.ActingUser(), limit)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	out := make([]map[string]any, 0, len(turns))
	for _, t := range turns {
		out = append(out, map[string]any{
			"id":         t.ID,
			"session_id": t.SessionID,
			"agent":      t.AgentName,
			"source":     t.Source,
			"role":       t.Role,
			"body":       t.Body,
			"redacted":   t.Redacted,
			"truncated":  t.Truncated,
			"created_at": store.ISO(t.CreatedAt),
		})
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"turns": out})
}
