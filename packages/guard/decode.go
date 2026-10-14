// SPDX-License-Identifier: Apache-2.0

package main

// Split from main.go: the call type, and the translation of a client's
// payload (and its rewrite patches) into and out of the guard's neutral
// argument names.

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/solongate/agent-security/packages/policy"
)

type call struct {
	Tool      string
	Args      map[string]interface{}
	Command   string
	Cwd       string
	SessionID string
	CallID    string
}

// Argument KEYS are part of a client's dialect too. Translating only the
// envelope leaves vendor names sitting inside the arguments, and then every
// layer downstream is back to reasoning about client-specific shapes: a rule
// written against `file_path` would miss a Codex `target_file` or an
// Antigravity `absolutePath`, and `readReferencedFiles`, which looks the
// `command` field up by name, would never see a `commandLine`.
//
// Unrecognised keys pass through untouched: they may still carry a path or a
// secret, and the scanners have to keep seeing them.
var argAliases = map[string]string{
	"commandline":   "command",
	"cmd":           "command",
	"absolutepath":  "file_path",
	"targetfile":    "file_path",
	"filepath":      "file_path",
	"target_file":   "file_path",
	"notebook_path": "file_path",
}

// neutralizeArgs renames aliased keys, keeping the FIRST value for each neutral
// name. First means first in the payload, which is why the key order is read
// off the raw JSON rather than off a Go map: map iteration is randomised, so a
// payload carrying both `command` and `cmd` would otherwise resolve to a
// different one run to run.
// argOriginals maps a NEUTRAL argument name back to the name the client used,
// for the keys neutralizeArgs renamed. Package-level for the same reason
// activeClient is: one process handles one call.
var argOriginals = map[string]string{}

func neutralizeArgs(args map[string]interface{}, order []string) map[string]interface{} {
	if len(order) == 0 {
		order = policy.SortedKeys(args)
	}
	out := make(map[string]interface{}, len(args))
	for _, k := range order {
		v, ok := args[k]
		if !ok {
			continue
		}
		nk := k
		if alias, has := argAliases[strings.ToLower(k)]; has {
			nk = alias
		}
		if _, exists := out[nk]; !exists {
			out[nk] = v
			if nk != k {
				// First one wins here too: the winning value and the name it is
				// written back under have to be the same argument.
				argOriginals[nk] = k
			}
		}
	}
	return out
}

// decodeObject returns a JSON object both as a map and as its keys in source
// order, which json.Unmarshal alone throws away.
func decodeObject(raw json.RawMessage) (map[string]interface{}, []string) {
	m := map[string]interface{}{}
	if len(raw) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return map[string]interface{}{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return m, nil
	}
	var order []string
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			break
		}
		k, ok := kt.(string)
		if !ok {
			break
		}
		order = append(order, k)
		var skip interface{}
		if err := dec.Decode(&skip); err != nil {
			break
		}
	}
	return m, order
}

// Allow the call but REPLACE its input, so a read is pointed at a redacted copy
// before the tool runs. The rewritten call is what executes, so no block is
// needed, which is the whole point for DLP: the agent gets an answer, without
// the secret in it.
func rewriteCall(patch map[string]interface{}) {
	emit(decision{Type: "rewrite", Patch: clientArgNames(patch)})
}

// clientArgNames turns the guard's neutral argument names back into the ones the
// client actually sent.
//
// A rewrite is SHALLOW-MERGED into the call's own arguments by the client, so a
// patch keyed `file_path` adds a new argument beside the `AbsolutePath` the
// client is really going to read. The call then runs against the original file
// and the rewrite does nothing at all, silently, because from the guard's side
// it looks like it worked.
//
// For the DLP read-redaction path that is the worst failure this binary has: it
// only runs on clients that CANNOT mask tool output, so the rewrite is the only
// thing standing between the agent and the secret. Antigravity (AbsolutePath)
// and OpenCode (filePath) are both in that group. Only `command` was ever
// translated back, which is why a rewrite of that key worked and a rewrite of
// either of these did not.
func clientArgNames(patch map[string]interface{}) map[string]interface{} {
	if len(patch) == 0 || len(argOriginals) == 0 {
		return patch
	}
	out := make(map[string]interface{}, len(patch))
	for k, v := range patch {
		if orig, ok := argOriginals[k]; ok {
			out[orig] = v
			continue
		}
		out[k] = v
	}
	return out
}