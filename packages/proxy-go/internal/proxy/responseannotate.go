package proxy

import (
	"bytes"
	"encoding/json"

	"github.com/codeyevsky/solongate/proxy/internal/sdk"
)

// Marking up what comes BACK from the upstream.
//
// Resources and prompts are the two places an agent is TOLD to go and read
// attacker-controlled text: a web page, a README, an issue comment. Text in
// there that reads as an instruction is indirect prompt injection, and by the
// time the model has seen it nothing downstream has a say.
//
// A flagged response is MARKED, NOT BLOCKED. The scanner reports suspicion, and
// a false positive that silently breaks a working tool teaches people to turn
// the proxy off. The marker is addressed to the model and says "data": the
// useful instruction to something about to read untrusted text is that the text
// is content to report on, not directions to follow.

// annotateResourceContents walks `contents[].text` of a resources/read result.
//
// The document is decoded, mutated and re-encoded ONLY when something was
// flagged. An untouched response is returned as the exact bytes the upstream
// sent, because a round trip through map[string]any reorders keys and rewrites
// numbers, and neither is a change this proxy has any business making.
func annotateResourceContents(raw json.RawMessage) (json.RawMessage, []string) {
	doc, ok := decodeDocument(raw)
	if !ok {
		return raw, nil
	}
	items, ok := doc["contents"].([]any)
	if !ok {
		return raw, nil
	}

	var threats []string
	changed := false
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if annotateTextField(entry, &threats) {
			changed = true
		}
	}
	return reencode(raw, doc, changed), threats
}

// annotatePromptMessages walks `messages[].content.text` of a prompts/get
// result.
func annotatePromptMessages(raw json.RawMessage) (json.RawMessage, []string) {
	doc, ok := decodeDocument(raw)
	if !ok {
		return raw, nil
	}
	messages, ok := doc["messages"].([]any)
	if !ok {
		return raw, nil
	}

	var threats []string
	changed := false
	for _, item := range messages {
		message, ok := item.(map[string]any)
		if !ok {
			continue
		}
		content, ok := message["content"].(map[string]any)
		if !ok {
			continue
		}
		if annotateTextField(content, &threats) {
			changed = true
		}
	}
	return reencode(raw, doc, changed), threats
}

// annotateTextField scans one object's `text` member and prefixes the marker if
// it is flagged. The map is mutated in place, which is what makes the nested
// walks above work without rebuilding the document.
func annotateTextField(holder map[string]any, threats *[]string) bool {
	text, ok := holder["text"].(string)
	if !ok || text == "" {
		return false
	}
	scan := sdk.ScanResponse(text, sdk.DefaultResponseScanConfig())
	if scan.Safe {
		return false
	}
	for _, t := range scan.Threats {
		*threats = append(*threats, string(t.Type))
	}
	holder["text"] = sdk.ResponseWarningMarker + "\n\n" + text
	return true
}

// decodeDocument reads a result into a generic document, keeping numbers as
// they were written.
//
// json.Number matters here: without it every number becomes a float64 and
// re-encoding turns an id of 10000000000000001 into 1.0000000000000002e+16.
// The proxy is annotating one string field, and it must not silently rewrite
// anything else on the way past.
func decodeDocument(raw json.RawMessage) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, false
	}
	return doc, true
}

func reencode(raw json.RawMessage, doc map[string]any, changed bool) json.RawMessage {
	if !changed {
		return raw
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// The default HTML escaping would rewrite < and & inside a resource's text
	// into < and &. Harmless to a JSON parser, but it changes the
	// bytes of content the proxy was only supposed to prefix.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return raw
	}
	return json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n"))
}
