// Package hookbundle holds the self-updating hook payloads: the port of
// src/generated/{guard,audit,shield}-bundle.ts.
//
// These three values are how every installed guard, audit hook and shield on
// every developer's laptop gets a fix. The hook asks GET /api/v1/hooks/<name>,
// compares the served version with the one baked into the file it is running
// from, base64-decodes the content, hashes the DECODED bytes with SHA-256, and
// refuses the download unless that hash matches the sha256 field. Only then
// does it write itself.
//
// That refusal is silent. There is no error, no log line and no telemetry — a
// hook whose checksum does not verify simply returns and runs the version it
// already had. So a wrong encoding here does not break loudly on the next
// deploy; it stops every machine in the fleet from ever updating again, and
// nobody finds out until a security fix fails to land.
//
// Three things follow from that and none of them is negotiable:
//
//   - The digest is over the RAW FILE, not over the base64 text. bundles_gen.go
//     is produced by a generator that hashes and encodes the same byte slice in
//     the same function, so the two cannot describe different bytes.
//   - The encoding is standard base64 WITH padding — encoding/base64's
//     StdEncoding, which is what Node's Buffer.toString('base64') produces and
//     what Buffer.from(s, 'base64') expects. URL-safe or unpadded base64 would
//     decode to different bytes or not at all.
//   - version is a JSON NUMBER. The hook tests `typeof data.version !== 'number'`
//     and gives up on anything else, so a version serialised as a string is a
//     fleet that never updates. Version is int64 for that reason and must not
//     become a string.
//
// The payload is served verbatim to any caller with a valid API key. There is
// nothing tenant-specific in it — every project gets the same three files, as
// in the live app — so no project id reaches this package.
package hookbundle

import "sort"

// Bundle is the response body of GET /api/v1/hooks/{name}.
//
// The field names and their JSON spellings are the contract: the hook reads
// data.version, data.content and data.sha256 and nothing else. Adding a field
// is safe; renaming one is a fleet that stops updating.
type Bundle struct {
	Version int64  `json:"version"`
	SHA256  string `json:"sha256"`
	Content string `json:"content"`
}

// Get returns the bundle for a hook name, or false when the name is not one of
// the three. The caller answers 404 rather than serving an empty bundle: a
// bundle with an empty content and checksum is one the hook rejects, which is
// the same silent dead end this package exists to avoid.
func Get(name string) (Bundle, bool) {
	b, ok := bundles[name]
	return b, ok
}

// Names lists the hooks this service serves, sorted. For tests and for the
// route registration, so a hook added to the generator cannot be one the router
// has no path for.
func Names() []string {
	out := make([]string, 0, len(bundles))
	for name := range bundles {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
