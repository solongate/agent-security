// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	"encoding/json"
)

// Every registration this package writes lands in a file the user (and the npm
// package) also owns, so the rewrite has to be a rewrite of one key and not a
// re-rendering of the whole document.
//
// encoding/json cannot do that on its own. Decoding an object into a map sorts
// the keys on the way out, so registering a hook in ~/.claude/settings.json
// would silently reorder every setting the user has — and then the npm package
// would put them back on its next install, leaving the two implementations
// rewriting each other's file forever. jsonObject keeps the order the file
// already had, replaces a key in place, and appends a new one at the end, which
// is exactly what `{...existing, hooks: …}` does in the TypeScript.
//
// Values are kept as raw bytes. A settings file may contain anything, and a
// round trip through map[string]any would rewrite numbers, reorder nested
// objects and lose nothing visible until someone diffed their own config.
type jsonObject struct {
	keys []string
	vals map[string]json.RawMessage
}

func newJSONObject() *jsonObject {
	return &jsonObject{vals: map[string]json.RawMessage{}}
}

// parseJSONObject decodes a top-level object, preserving key order. Anything
// that is not an object — a truncated file, an array, a stray string — decodes
// as "no object", and callers treat that the way the TypeScript's catch does:
// start from empty.
func parseJSONObject(b []byte) (*jsonObject, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	t, err := dec.Token()
	if err != nil {
		return nil, false
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, false
	}
	o := newJSONObject()
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, false
		}
		k, ok := kt.(string)
		if !ok {
			return nil, false
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, false
		}
		o.set(k, v)
	}
	if _, err := dec.Token(); err != nil {
		return nil, false
	}
	return o, true
}

func (o *jsonObject) has(key string) bool {
	_, ok := o.vals[key]
	return ok
}

func (o *jsonObject) get(key string) json.RawMessage { return o.vals[key] }

// set replaces a key IN PLACE when it is already there. A duplicate key in the
// source file collapses onto the first position with the last value, which is
// what JSON.parse does with one.
func (o *jsonObject) set(key string, v json.RawMessage) {
	if _, ok := o.vals[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = v
}

// setValue marshals a Go value into the object. The error is the caller's to
// handle: a value that will not encode must abort the install before anything is
// written, not produce a file with a key missing from it.
func (o *jsonObject) setValue(key string, v any) error {
	b, err := marshalJS(v)
	if err != nil {
		return err
	}
	o.set(key, b)
	return nil
}

func (o *jsonObject) delete(key string) {
	if _, ok := o.vals[key]; !ok {
		return
	}
	delete(o.vals, key)
	for i, k := range o.keys {
		if k == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

// encode renders the object as JSON.stringify(value, null, 2) does, so a file
// this writes is byte-identical to the one the npm package writes from the same
// state. json.MarshalIndent is not that function: it escapes <, > and & into
// unicode sequences, which would rewrite every URL with a query string in a
// user's settings file the first time a hook was registered.
func (o *jsonObject) encode() ([]byte, error) {
	if len(o.keys) == 0 {
		return []byte("{}"), nil
	}
	var b bytes.Buffer
	b.WriteString("{\n")
	for i, k := range o.keys {
		if i > 0 {
			b.WriteString(",\n")
		}
		key, err := marshalJS(k)
		if err != nil {
			return nil, err
		}
		b.WriteString("  ")
		b.Write(key)
		b.WriteString(": ")
		// A nested value is re-indented rather than decoded and re-encoded: two
		// spaces of prefix per level, which is what json.Indent produces for a
		// value sitting one level in, and it leaves the value's own bytes alone.
		var v bytes.Buffer
		if err := json.Indent(&v, o.vals[k], "  ", "  "); err != nil {
			return nil, err
		}
		b.Write(v.Bytes())
	}
	b.WriteString("\n}")
	return b.Bytes(), nil
}

// encodeFile is the whole file: the object plus the trailing newline every
// writer in the TypeScript appends.
func (o *jsonObject) encodeFile() ([]byte, error) {
	b, err := o.encode()
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// marshalJS encodes one value the way JSON.stringify does.
//
// HTML escaping off, because JSON.stringify does not do it and these files are
// read and rewritten by both implementations. Two differences remain and are
// left alone rather than hand-rolled: Go spells backspace and form feed as
// six-character unicode escapes where JavaScript spells each with one letter,
// and Go escapes U+2028/U+2029 where JavaScript leaves them literal. Both need
// one of those characters to appear inside a string in someone's settings file,
// and matching them would mean writing a JSON encoder to be faithful about
// whitespace nobody can see.
func marshalJS(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
