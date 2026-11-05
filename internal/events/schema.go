package events

import (
	"encoding/json"
	"reflect"
	"strings"
	"time"
)

// Schema returns the JSON Schema (draft 2020-12) for Event, generated from
// the struct tags so code and schema cannot drift. Fields without omitempty
// are required. Optional tags: enum:"a,b" and desc:"text".
func Schema() ([]byte, error) {
	root := schemaOf(reflect.TypeFor[Event]())
	root["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	root["title"] = "Sherlock security event v1"
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func schemaOf(t reflect.Type) map[string]any {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == reflect.TypeFor[time.Time]() {
		return map[string]any{"type": "string", "format": "date-time"}
	}
	switch t.Kind() {
	case reflect.Struct:
		props := map[string]any{}
		var required []string
		for f := range t.Fields() {
			name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" || name == "-" {
				continue
			}
			s := schemaOf(f.Type)
			if d := f.Tag.Get("desc"); d != "" {
				s["description"] = d
			}
			if e := f.Tag.Get("enum"); e != "" {
				s["enum"] = strings.Split(e, ",")
			}
			props[name] = s
			if !strings.Contains(opts, "omitempty") {
				required = append(required, name)
			}
		}
		out := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
		if len(required) > 0 {
			out["required"] = required
		}
		return out
	case reflect.Slice:
		return map[string]any{"type": "array", "items": schemaOf(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": schemaOf(t.Elem())}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Invalid, reflect.Uintptr, reflect.Complex64, reflect.Complex128, reflect.Array, reflect.Chan,
		reflect.Func, reflect.Interface, reflect.Pointer, reflect.UnsafePointer:
		return map[string]any{}
	}
	return map[string]any{}
}
