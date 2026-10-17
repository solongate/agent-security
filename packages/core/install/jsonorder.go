// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"bytes"
	"encoding/json"
)

type jsonObject struct {
	keys []string
	vals map[string]json.RawMessage
}

func newJSONObject() *jsonObject {
	return &jsonObject{vals: map[string]json.RawMessage{}}
}

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

func (o *jsonObject) set(key string, v json.RawMessage) {
	if _, ok := o.vals[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = v
}

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

		var v bytes.Buffer
		if err := json.Indent(&v, o.vals[k], "  ", "  "); err != nil {
			return nil, err
		}
		b.Write(v.Bytes())
	}
	b.WriteString("\n}")
	return b.Bytes(), nil
}

func (o *jsonObject) encodeFile() ([]byte, error) {
	b, err := o.encode()
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func marshalJS(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}