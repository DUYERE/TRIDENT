package tools

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

// [01] Arguments are flat, scalar-only objects. Reject containers immediately,
// rather than recursively decoding attacker-controlled nesting into Go values.
const MaxArgumentsBytes = 16 << 10

type argumentKind uint8

const (
	stringArgument argumentKind = iota
	integerArgument
)

type argumentSpec struct {
	kind     argumentKind
	required bool
}

func decodeArguments(raw json.RawMessage, fields map[string]argumentSpec) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > MaxArgumentsBytes || !utf8.Valid(raw) {
		return nil, fmt.Errorf("%w: empty, oversized or invalid UTF-8 JSON", ErrArguments)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("%w: expected an object", ErrArguments)
	}
	values := make(map[string]any, len(fields))
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: invalid object key", ErrArguments)
		}
		key, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("%w: expected a string key", ErrArguments)
		}
		spec, known := fields[key]
		if _, duplicate := values[key]; duplicate || !known {
			return nil, fmt.Errorf("%w: duplicate or unknown key %q", ErrArguments, key)
		}
		token, err = d.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: invalid value for %q", ErrArguments, key)
		}
		switch spec.kind {
		case stringArgument:
			value, ok := token.(string)
			if !ok {
				return nil, fmt.Errorf("%w: %q must be a string", ErrArguments, key)
			}
			values[key] = value
		case integerArgument:
			value, ok := token.(json.Number)
			if !ok {
				return nil, fmt.Errorf("%w: %q must be an integer", ErrArguments, key)
			}
			n, err := strconv.ParseInt(string(value), 10, strconv.IntSize)
			if err != nil {
				return nil, fmt.Errorf("%w: %q must be an in-range integer", ErrArguments, key)
			}
			values[key] = int(n)
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return nil, fmt.Errorf("%w: invalid object ending", ErrArguments)
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing JSON data", ErrArguments)
	}
	for key, spec := range fields {
		if _, present := values[key]; spec.required && !present {
			return nil, fmt.Errorf("%w: missing required key %q", ErrArguments, key)
		}
	}
	return values, nil
}

func stringValue(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return value
}

func integerValue(values map[string]any, key string) int {
	value, _ := values[key].(int)
	return value
}
