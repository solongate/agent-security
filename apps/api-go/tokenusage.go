package main

// POST /api/v1/token-usage — what a turn cost.
//
// Nothing in this product recorded it until now, and the gap is worth naming: a
// host paying for a fleet's seats could see every call those machines made and
// had no way to see what any of it cost. Calls and tokens are not proportional
// — one Read is a hundred tokens and one long reasoning turn with no tools at
// all is fifty thousand — so a chart of calls is not a chart of spend.
//
// One row per TURN, keyed by something the CLIENT can compute the same way
// twice, because a hook that retries must not double a bill. See the note on
// tokenTurnKey.
//
// The four clients do not report the same number and this route does not
// pretend otherwise. `measure` rides with every row: three of them report what
// the provider bills, and Antigravity reports how much of the context window
// has been consumed. They are stored side by side and never summed together —
// a total mixing them would be a number with no unit.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/codeyevsky/solongate/api/internal/apiauth"
	"github.com/codeyevsky/solongate/api/internal/store"
)

func init() {
	Register("POST /api/v1/token-usage", func(s *server) http.Handler {
		return s.auth.WithAuth(s.createTokenUsage)
	})
}

// tokenUsageRequest is one turn's cost, as a hook sends it.
//
// Every count is optional and defaults to zero, because the clients report
// different subsets: Claude Code splits the prompt three ways, OpenCode reports
// reasoning separately, Antigravity has only a context figure. A field a client
// does not have is absent rather than invented.
type tokenUsageRequest struct {
	SessionID string `json:"session_id"`
	// TurnKey is the client's own identifier for this turn — an API request id,
	// a message id, a generation index. It is what makes a retry idempotent.
	TurnKey   string `json:"turn_key"`
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	Source    string `json:"source"`
	Measure   string `json:"measure"`

	Input      int64 `json:"input"`
	Output     int64 `json:"output"`
	CacheRead  int64 `json:"cache_read"`
	CacheWrite int64 `json:"cache_write"`
	Reasoning  int64 `json:"reasoning"`
	// Total is what the client says the turn cost. Absent means "add up the
	// parts", which is the right default for a client that reports the split
	// and the wrong one for a client that reports only a total.
	Total int64 `json:"total"`

	// At is when the turn happened, in milliseconds. Absent is now.
	At int64 `json:"at"`
}

// tokenMaxPerTurn is a sanity bound on one turn.
//
// Ten million. No model has a context window near it, so a number above it is a
// unit error, a cumulative counter sent as a delta, or a corrupted read — and
// one bad row on a spend chart is a bar that dwarfs a month of real ones. It is
// clamped rather than refused: the rest of the turn's numbers are still worth
// having, and a hook that cannot report gets no error to retry against.
const tokenMaxPerTurn = 10_000_000

// tokenUsageBatch is what a hook actually sends.
//
// A batch rather than one turn per request, and that choice is what makes the
// hooks stateless. Every client's record is a FILE it can re-read — a
// transcript, a rollout, a database — so the cheapest correct hook emits a row
// for every turn it can see with a key derived from the client's own
// identifiers, and lets the server ignore the ones it already has. One request
// per Stop, no byte offset to keep, and a re-run costs nothing.
type tokenUsageBatch struct {
	Turns []tokenUsageRequest `json:"turns"`
}

// tokenBatchMax is how many turns one request may carry.
//
// A tail of a transcript is a few dozen turns at most. The cap is what stops a
// client that decided to send its whole history from turning one POST into a
// migration.
const tokenBatchMax = 200

func (s *server) createTokenUsage(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	ctx := r.Context()

	// One turn or many. The single form is kept because it is what a client
	// with nothing to batch would naturally send, and refusing it would make
	// the simplest hook the one that has to know about envelopes.
	var raw map[string]any
	if !apiauth.DecodeJSON(w, r, &raw, true) {
		return
	}
	turns, err := tokenTurnsFrom(raw)
	if err != nil {
		apiauth.ValidationError(w, err.Error())
		return
	}
	if len(turns) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if len(turns) > tokenBatchMax {
		turns = turns[:tokenBatchMax]
	}

	stored := 0
	for _, body := range turns {
		if s.storeTokenTurn(ctx, w, key, body) {
			stored++
		}
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"ok": true, "stored": stored})
}

// tokenTurnsFrom reads either shape out of one body.
func tokenTurnsFrom(raw map[string]any) ([]tokenUsageRequest, error) {
	blob, err := marshalNoEscape(raw)
	if err != nil {
		return nil, errTokenBody
	}
	if _, batched := raw["turns"]; batched {
		var b tokenUsageBatch
		if json.Unmarshal(blob, &b) != nil {
			return nil, errTokenBody
		}
		return b.Turns, nil
	}
	var one tokenUsageRequest
	if json.Unmarshal(blob, &one) != nil {
		return nil, errTokenBody
	}
	return []tokenUsageRequest{one}, nil
}

var errTokenBody = errors.New("expected a turn, or {turns: [...]}")

// storeTokenTurn writes one turn and reports whether it wrote anything.
func (s *server) storeTokenTurn(ctx context.Context, w http.ResponseWriter, key apiauth.KeyInfo, body tokenUsageRequest) bool {
	body.SessionID = strings.TrimSpace(body.SessionID)
	body.TurnKey = strings.TrimSpace(body.TurnKey)
	if body.TurnKey == "" {
		// Without a key there is no way to tell a retry from a second turn, and
		// a spend figure that grows on every retry is worse than none. The turn
		// is dropped rather than refused: a hook sending this is not doing
		// anything wrong, and an error would have it retry what it cannot do.
		return false
	}

	measure := store.TokenMeasureBilled
	if strings.EqualFold(body.Measure, store.TokenMeasureContext) {
		measure = store.TokenMeasureContext
	}

	u := store.TokenUsage{
		ID:        tokenTurnKey(key.ProjectID, body.Source, body.TurnKey),
		ProjectID: key.ProjectID,
		APIKeyID:  key.KeyID,
		UserID:    key.ActingUser(),
		SessionID: store.Clip(body.SessionID, 128),
		AgentID:   store.Clip(strings.TrimSpace(body.AgentID), 128),
		AgentName: store.Clip(strings.TrimSpace(body.AgentName), 128),
		Source:    store.Clip(strings.TrimSpace(body.Source), 32),
		Measure:   measure,

		Input:      clampTokens(body.Input),
		Output:     clampTokens(body.Output),
		CacheRead:  clampTokens(body.CacheRead),
		CacheWrite: clampTokens(body.CacheWrite),
		Reasoning:  clampTokens(body.Reasoning),
		CreatedAt:  tokenStamp(body.At),
	}

	// The total is the client's when it sent one, and the sum of the parts when
	// it did not. The parts are DISJOINT for every client that reports them —
	// Claude Code's cache reads and cache writes are additional to
	// input_tokens, not included in it — so adding them is the whole prompt
	// plus the completion rather than double counting.
	//
	// Reasoning is NOT added: where a client reports it, it is a subset of the
	// output it also reported.
	u.Total = clampTokens(body.Total)
	if u.Total == 0 {
		u.Total = u.Input + u.Output + u.CacheRead + u.CacheWrite
	}
	if u.Total == 0 {
		// A turn that cost nothing measurable is not a turn worth a row. It is
		// also what an empty entry looks like.
		return false
	}

	if err := s.store.InsertTokenUsage(ctx, u); err != nil {
		// Logged rather than failed. One unwritable row must not lose the rest
		// of a batch, and the client cannot fix it by retrying.
		log.Printf("[API:tokens] %v", err)
		return false
	}
	return true
}

// tokenTurnKey is the primary key, and therefore the whole of the idempotency.
//
// The SESSION is deliberately not in it. Resuming or forking a conversation
// copies prior records into a file under a new session id, so the same API
// request appears in two transcripts — 1,460 of them on one developer's machine,
// carrying nearly two million output tokens. A session-scoped key makes every
// one of those a second row, and a bill that grows because somebody resumed.
//
// So the key is the CLIENT's own identifier for the turn, and it is the client's
// job to make that identifier unique. Two of them already are — Claude Code's
// requestId and OpenCode's message id are provider-issued — and the two whose
// identifier is POSITIONAL prefix it with the session or conversation it counts
// within, inside the reader, where the id is known.
//
// Hashed rather than concatenated so the key is a fixed size whatever a client
// puts in it, and scoped by PROJECT so two projects cannot collide at all.
func tokenTurnKey(projectID, source, turnKey string) string {
	sum := sha256.Sum256([]byte(projectID + "\x1e" + source + "\x1e" + turnKey))
	return "tk_" + hex.EncodeToString(sum[:16])
}

// clampTokens keeps one implausible number from owning a chart. Negative is
// zero: a count cannot be negative, and a client sending one has a bug this
// service should not store.
func clampTokens(n int64) int64 {
	switch {
	case n < 0:
		return 0
	case n > tokenMaxPerTurn:
		return tokenMaxPerTurn
	}
	return n
}

// tokenStamp is when the turn happened, in seconds.
//
// A stamp from the future or from before this product existed is replaced with
// now rather than stored: a clock-skewed machine would otherwise put a bar at
// the end of the chart forever, or a year before anything else on it.
func tokenStamp(ms int64) int64 {
	now := time.Now()
	if ms <= 0 {
		return now.Unix()
	}
	at := ms / 1000
	if at > now.Add(time.Hour).Unix() || at < now.AddDate(-2, 0, 0).Unix() {
		return now.Unix()
	}
	return at
}
