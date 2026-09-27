package policycompile

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// The bundle guard.mjs expects: a gzipped tar with policy.wasm in it, at the
// entrypoint it evaluates. It gunzips the response and walks the tar looking
// for that exact member, so "a wasm file" is not good enough and neither is an
// uncompressed bundle.
func TestCompileProducesABundleTheInstalledGuardCanRead(t *testing.T) {
	policy := json.RawMessage(`{"id":"p","name":"P","rules":[
		{"id":"deny-curl","effect":"DENY","priority":10,"toolPattern":"*","enabled":true,
		 "commandConstraints":{"denied":["curl*"]}}]}`)

	res, ok := Compile(context.Background(), policy)
	if !ok {
		t.Fatal("a policy with a rules array must compile")
	}
	if !strings.Contains(res.RegoSource, "package solongate.policy") {
		t.Fatalf("rego source is not a policy module:\n%s", res.RegoSource)
	}
	if res.WasmUnavailable {
		t.Fatalf("WASM build failed; /policies/{id}/wasm would serve nothing")
	}

	raw, err := base64.StdEncoding.DecodeString(res.WasmBundleB64)
	if err != nil {
		t.Fatalf("bundle is not base64: %v", err)
	}
	gz, err := gzip.NewReader(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("bundle is not gzipped, which is the first thing the hook does to it: %v", err)
	}
	tr := tar.NewReader(gz)
	found := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("bundle is not a tar: %v", err)
		}
		// The hook accepts `policy.wasm`, `./policy.wasm` or anything ending
		// in `/policy.wasm`; OPA writes the third form.
		if h.Name == "policy.wasm" || h.Name == "./policy.wasm" || strings.HasSuffix(h.Name, "/policy.wasm") {
			found = true
		}
	}
	if !found {
		t.Error("no policy.wasm in the bundle; extractWasmFromBundle throws on this")
	}
}

func TestCompileRefusesAPolicyWithNoRulesArray(t *testing.T) {
	if _, ok := Compile(context.Background(), json.RawMessage(`{"id":"p","name":"P"}`)); ok {
		t.Error("a policy with no rules must compile to nothing, as compilePolicyToOpa returns null")
	}
}
