package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// maxFileBytes bounds what Load reads; a real config is a few KiB.
const maxFileBytes = 4 << 20

// Load reads, defaults and validates the YAML file at path.
func Load(path string) (*Root, error) {
	f, err := os.Open(path) //nolint:gosec // operator-supplied config path
	if err != nil {
		return nil, fmt.Errorf("opening config: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("config %s exceeds %d bytes", path, maxFileBytes)
	}
	return Parse(data)
}

// Parse decodes YAML, rejects unknown fields with JSON-pointer paths, applies
// defaults and validates. The returned error, if any, is an Errors.
func Parse(data []byte) (*Root, error) {
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, Errors{{Code: CodeSyntax, Message: "config is empty"}}
		}
		return nil, Errors{{Code: CodeSyntax, Message: err.Error()}}
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, Errors{{Code: CodeSyntax, Message: "multiple YAML documents are not allowed"}}
	}

	var errs Errors
	findUnknownFields(&doc, reflect.TypeFor[Root](), "", &errs)
	if len(errs) > 0 {
		return nil, errs
	}

	var root Root
	if err := doc.Decode(&root); err != nil {
		return nil, Errors{{Code: CodeSyntax, Message: err.Error()}}
	}
	root.ApplyDefaults()
	if errs := root.Validate(); len(errs) > 0 {
		return nil, errs
	}
	return &root, nil
}

// findUnknownFields walks the YAML tree against t and reports keys that map
// to no struct field, so typos are hard errors with precise paths.
func findUnknownFields(n *yaml.Node, t reflect.Type, ptr string, errs *Errors) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			findUnknownFields(c, t, ptr, errs)
		}
	case yaml.AliasNode:
		errs.add(ptr, CodeSyntax, "YAML aliases are not allowed")
	case yaml.MappingNode:
		if t.Kind() != reflect.Struct {
			return
		}
		fields := yamlFields(t)
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i], n.Content[i+1]
			ft, ok := fields[key.Value]
			if !ok {
				errs.add(ptr+"/"+escapePointer(key.Value), CodeUnknownField, "unknown field %q (line %d)", key.Value, key.Line)
				continue
			}
			findUnknownFields(val, ft, ptr+"/"+escapePointer(key.Value), errs)
		}
	case yaml.SequenceNode:
		if t.Kind() != reflect.Slice {
			return
		}
		for i, c := range n.Content {
			findUnknownFields(c, t.Elem(), ptr+"/"+strconv.Itoa(i), errs)
		}
	case yaml.ScalarNode:
	}
}

func yamlFields(t reflect.Type) map[string]reflect.Type {
	m := make(map[string]reflect.Type, t.NumField())
	for f := range t.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "" || name == "-" {
			continue
		}
		m[name] = f.Type
	}
	return m
}

func escapePointer(s string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(s)
}
