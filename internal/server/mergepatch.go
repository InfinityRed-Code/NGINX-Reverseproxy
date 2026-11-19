package server

import (
	"bytes"
	"encoding/json"
	"errors"
)

// mergePatch wendet einen JSON Merge Patch (RFC 7386) auf ein Objekt an.
func mergePatch(target, patch []byte) ([]byte, error) {
	var t, p any
	if err := json.Unmarshal(target, &t); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(patch, &p); err != nil {
		return nil, err
	}
	if _, ok := p.(map[string]any); !ok {
		return nil, errors.New("Merge Patch muss ein JSON-Objekt sein")
	}
	return json.Marshal(merge(t, p))
}

func merge(target, patch any) any {
	pm, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	tm, ok := target.(map[string]any)
	if !ok {
		tm = map[string]any{}
	}
	for k, v := range pm {
		if v == nil {
			delete(tm, k)
		} else {
			tm[k] = merge(tm[k], v)
		}
	}
	return tm
}

func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
