// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

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

var argAliases = map[string]string{
	"commandline":   "command",
	"cmd":           "command",
	"absolutepath":  "file_path",
	"targetfile":    "file_path",
	"filepath":      "file_path",
	"target_file":   "file_path",
	"notebook_path": "file_path",
}

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

				argOriginals[nk] = k
			}
		}
	}
	return out
}

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

func rewriteCall(patch map[string]interface{}) {
	emit(decision{Type: "rewrite", Patch: clientArgNames(patch)})
}

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