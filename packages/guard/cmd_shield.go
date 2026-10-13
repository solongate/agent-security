// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/solongate/agent-security/packages/shared"
)

// Ported from packages/hooks/shield.mjs — secret redaction on the LLM request
// path. Wraps a command (the real `claude`) with a local HTTP proxy that
// masks secrets in the request body before it reaches the model; the
// response streams back untouched. Lifecycle is tied to the wrapped process —
// no daemon. FAIL OPEN everywhere: any parse/redact/upstream error forwards
// the original bytes rather than breaking the model connection.
//
// There is no second implementation of this one: the rest of this binary
// covers the tool-call path, and the LLM path is this file alone.
//
// Like shield.mjs, there is no TLS termination here — the proxy is plain HTTP
// on loopback (the child is pointed at it via ANTHROPIC_BASE_URL) and makes a
// normal TLS connection to the real upstream itself, so there is no MITM
// certificate to generate or to have the child trust.

func shieldLog(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "[SolonGate shield] "+format+"\n", a...)
}

// runShield implements `solongate-guard shield -- <command> [args...]`.
func runShield(args []string) int {
	cmdArgs := shieldCommandArgs(args)
	if len(cmdArgs) == 0 {
		shieldLog("usage: solongate-guard shield -- <command> [args...]")
		return 1
	}

	upstream := shieldPickUpstream()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		// A shield that cannot start must never stop `claude` from running.
		shieldLog("failed to start local proxy, running unshielded: %v", err)
		return shieldRunChild(cmdArgs, "")
	}
	srv := &http.Server{Handler: shieldProxyHandler(upstream)}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	port := ln.Addr().(*net.TCPAddr).Port
	return shieldRunChild(cmdArgs, fmt.Sprintf("http://127.0.0.1:%d", port))
}

// shieldCommandArgs extracts the command to wrap: everything after the "--"
// separator, matching shield.mjs's `process.argv.indexOf('--')`.
func shieldCommandArgs(args []string) []string {
	for i, a := range args {
		if a == "--" {
			return args[i+1:]
		}
	}
	return nil
}

// shieldRunChild execs the wrapped command with stdio inherited, pointing it
// at the local proxy via ANTHROPIC_BASE_URL (left unset when baseURL is "",
// the unshielded fallback). SIGINT/SIGTERM are forwarded to the child so an
// interrupted `claude` still gets a clean chance to shut down.
func shieldRunChild(cmdArgs []string, baseURL string) int {
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	if baseURL != "" {
		cmd.Env = append(cmd.Env, "ANTHROPIC_BASE_URL="+baseURL)
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		for sig := range sigCh {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}()

	if err := cmd.Start(); err != nil {
		shieldLog("failed to launch command: %v", err)
		return 1
	}
	err := cmd.Wait()
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		// shield.mjs re-raises the exact signal on itself so the parent shell
		// observes the real cause of death. Go has no portable equivalent of
		// that self-signaling; 128+signal is the same number a POSIX shell
		// would report for it, so $? still reads the same at the call site.
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return exitErr.ExitCode()
	}
	shieldLog("failed to launch command: %v", err)
	return 1
}

// shieldPickUpstream mirrors shield.mjs's pickUpstream.
func shieldPickUpstream() *url.URL {
	raw := os.Getenv("SOLONGATE_SHIELD_UPSTREAM")
	if raw == "" {
		raw = os.Getenv("ANTHROPIC_BASE_URL")
	}
	if raw == "" {
		raw = "https://api.anthropic.com"
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u
	}
	u, _ := url.Parse("https://api.anthropic.com")
	return u
}

// shieldProxyHandler mirrors shield.mjs's startProxy request handler:
// re-read config per request, redact a JSON body, forward everything else
// unchanged, and pipe the response straight back.
func shieldProxyHandler(upstream *url.URL) http.HandlerFunc {
	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := shieldLoadDLPConfig()
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 && strings.Contains(r.Header.Get("Content-Type"), "json") {
			body = shieldRedactBody(body, cfg)
		}

		target := *upstream
		target.Path = r.URL.Path
		target.RawPath = r.URL.RawPath
		target.RawQuery = r.URL.RawQuery

		upReq, err := http.NewRequest(r.Method, target.String(), bytes.NewReader(body))
		if err != nil {
			shieldLog("upstream error: %v", err)
			http.Error(w, "shield upstream error", http.StatusBadGateway)
			return
		}
		upReq.Header = r.Header.Clone()
		upReq.Header.Del("Host")
		upReq.Header.Del("Content-Length")
		upReq.Header.Del("Accept-Encoding")
		upReq.ContentLength = int64(len(body))
		upReq.Host = upstream.Host

		upRes, err := client.Do(upReq)
		if err != nil {
			shieldLog("upstream error: %v", err)
			http.Error(w, "shield upstream error", http.StatusBadGateway)
			return
		}
		defer upRes.Body.Close()
		for k, vv := range upRes.Header {
			w.Header()[k] = vv
		}
		w.WriteHeader(upRes.StatusCode)
		_, _ = io.Copy(w, upRes.Body)
	}
}

// shieldLoadDLPConfig mirrors shield.mjs's loadCfg, reusing the existing
// policy reader instead of a second one. Returns nil when a policy explicitly
// configures only dlpObserve (DLP configured, in a mode that must not rewrite
// anything a human sees) — a different answer from "nothing configured",
// which falls through to every built-in pattern.
func shieldLoadDLPConfig() *shared.DLPConfig {
	defaults := func() *shared.DLPConfig { return &shared.DLPConfig{Patterns: shared.DLPPatternNames()} }
	cache := loadLocalPolicyFile("")
	if cache == nil || !cache.HasSecurity || cache.Security == nil {
		return defaults()
	}
	sec := cache.Security
	d := sec.DLPRedact
	if d == nil {
		d = sec.DLPBlock
	}
	if d == nil || d.Patterns == nil {
		if sec.DLPObserve != nil && sec.DLPObserve.Patterns != nil {
			return nil
		}
		return defaults()
	}
	return d
}

// shieldRedactBody mirrors shield.mjs's request-body redaction: scan the
// system prompt and every non-assistant message (Claude Code resends the
// full conversation history on every request, so this has to run on every
// call), or the whole payload if it is not the {messages: [...]} shape.
// Any parse error returns body unchanged — fail open.
func shieldRedactBody(body []byte, cfg *shared.DLPConfig) []byte {
	if cfg == nil {
		return body
	}
	var parsed interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body
	}
	obj, ok := parsed.(map[string]interface{})
	if !ok {
		out, err := json.Marshal(shieldRedactDeep(parsed, cfg))
		if err != nil {
			return body
		}
		return out
	}
	msgs, hasMessages := obj["messages"].([]interface{})
	if !hasMessages {
		out, err := json.Marshal(shieldRedactDeep(obj, cfg))
		if err != nil {
			return body
		}
		return out
	}
	if sys, exists := obj["system"]; exists {
		obj["system"] = shieldRedactDeep(sys, cfg)
	}
	for i, m := range msgs {
		mm, ok := m.(map[string]interface{})
		if !ok {
			continue
		}
		if role, _ := mm["role"].(string); role != "assistant" {
			msgs[i] = shieldRedactDeep(mm, cfg)
		}
	}
	obj["messages"] = msgs
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

// shieldRedactDeep walks a decoded JSON value, masking every string leaf via
// the same dlpRedactText the tool-output and read-redaction paths use —
// one redaction implementation, not a second one for the LLM path.
func shieldRedactDeep(v interface{}, cfg *shared.DLPConfig) interface{} {
	switch x := v.(type) {
	case string:
		return dlpRedactText(x, cfg)
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, e := range x {
			out[i] = shieldRedactDeep(e, cfg)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(x))
		for k, val := range x {
			out[k] = shieldRedactDeep(val, cfg)
		}
		return out
	default:
		return v
	}
}
