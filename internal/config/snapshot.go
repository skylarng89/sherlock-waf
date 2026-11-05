package config

import (
	"bytes"
	"encoding/json"
	"fmt"

	"go.yaml.in/yaml/v3"
)

// Snapshot returns the canonical JSON form of a configuration: the exact bytes
// stored as a config version and compared to detect no-op changes. The root is
// defaulted first so equal configurations always encode identically.
func Snapshot(r *Root) ([]byte, error) {
	cp := *r
	cp.ApplyDefaults()
	b, err := json.Marshal(&cp)
	if err != nil {
		return nil, fmt.Errorf("encoding config snapshot: %w", err)
	}
	return b, nil
}

// FromSnapshot decodes a stored snapshot. Unknown fields are an error (a
// snapshot from a newer build must not be half-understood), and a snapshot from
// another schema version is refused until a migration for it exists.
func FromSnapshot(b []byte) (*Root, error) {
	var probe struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("reading snapshot schema version: %w", err)
	}
	if probe.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("snapshot has schema_version %d but this build understands %d; it needs a migration", probe.SchemaVersion, SchemaVersion)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r Root
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("decoding config snapshot: %w", err)
	}
	r.ApplyDefaults()
	if errs := r.Validate(); len(errs) > 0 {
		return nil, errs
	}
	return &r, nil
}

// MarshalYAML renders root as the YAML form accepted by Load, for export.
func MarshalYAML(root *Root) ([]byte, error) {
	b, err := yaml.Marshal(root)
	if err != nil {
		return nil, fmt.Errorf("encoding config as yaml: %w", err)
	}
	return b, nil
}
