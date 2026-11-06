// Command refgen writes the configuration JSON Schema and the configuration
// reference from the Go types in internal/config, so the documentation cannot
// drift from what the loader accepts. Run it with `make gen`; CI fails if the
// committed files differ.
//
//	refgen <internal/config dir> <output dir>
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

const rootType = "Root"

// field is one documented configuration key.
type field struct {
	Key      string
	Type     ast.Expr
	Doc      string
	Required bool
}

type pkgInfo struct {
	structs map[string][]field // type name -> fields in source order
	docs    map[string]string  // type name -> doc comment
	enums   map[string][]string
	basics  map[string]string // named non-struct types -> underlying identifier
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: refgen <internal/config dir> <output dir>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "refgen:", err)
		os.Exit(1)
	}
}

func run(dir, out string) error {
	p, err := load(dir)
	if err != nil {
		return err
	}
	if _, ok := p.structs[rootType]; !ok {
		return fmt.Errorf("type %s not found in %s", rootType, dir)
	}
	schema := map[string]any{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"$id":         "https://sherlock-waf.dev/schema/config-v1.json",
		"title":       "Sherlock WAF configuration (schema_version 1)",
		"description": strings.TrimSpace(p.docs[rootType]),
		"$ref":        "#/$defs/" + rootType,
		"$defs":       map[string]any{},
	}
	defs := schema["$defs"].(map[string]any)
	seen := reachable(p)
	if missing := p.undocumented(seen); len(missing) > 0 {
		return fmt.Errorf("every configuration key needs a doc comment; missing:\n  %s", strings.Join(missing, "\n  "))
	}
	for _, name := range seen {
		defs[name] = p.structSchema(name)
	}
	b, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o755); err != nil { //nolint:gosec // generated public docs
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "config.schema.json"), append(b, '\n'), 0o644); err != nil { //nolint:gosec // generated public docs
		return err
	}
	return os.WriteFile(filepath.Join(out, "config-reference.md"), []byte(p.markdown(seen)), 0o644) //nolint:gosec // generated public docs
}

func load(dir string) (*pkgInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	p := &pkgInfo{structs: map[string][]field{}, docs: map[string]string{}, enums: map[string][]string{}, basics: map[string]string{}}
	found := false
	for _, e := range entries { // ReadDir sorts by name, so the output is stable
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		if f.Name.Name != "config" {
			continue
		}
		found = true
		for _, decl := range f.Decls {
			if gd, ok := decl.(*ast.GenDecl); ok {
				p.addDecl(gd)
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("package config not found in %s", dir)
	}
	return p, nil
}

func (p *pkgInfo) addDecl(gd *ast.GenDecl) {
	if gd.Tok == token.CONST {
		p.addConsts(gd)
		return
	}
	if gd.Tok != token.TYPE {
		return
	}
	for _, spec := range gd.Specs {
		ts := spec.(*ast.TypeSpec)
		if !ts.Name.IsExported() {
			continue
		}
		doc := ts.Doc
		if doc == nil {
			doc = gd.Doc
		}
		p.docs[ts.Name.Name] = commentText(doc)
		switch t := ts.Type.(type) {
		case *ast.StructType:
			p.structs[ts.Name.Name] = structFields(t)
		case *ast.Ident:
			p.basics[ts.Name.Name] = t.Name
		}
	}
}

// addConsts records the string values of typed constant groups, which are the
// accepted values of enumerated settings such as Mode.
func (p *pkgInfo) addConsts(gd *ast.GenDecl) {
	var last string
	for _, spec := range gd.Specs {
		vs := spec.(*ast.ValueSpec)
		if id, ok := vs.Type.(*ast.Ident); ok {
			last = id.Name
		} else if vs.Type != nil {
			last = ""
		}
		if last == "" {
			continue
		}
		for _, v := range vs.Values {
			lit, ok := v.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			if s, err := strconv.Unquote(lit.Value); err == nil {
				p.enums[last] = append(p.enums[last], s)
			}
		}
	}
}

func structFields(st *ast.StructType) []field {
	var out []field
	for _, f := range st.Fields.List {
		if f.Tag == nil || len(f.Names) == 0 || !f.Names[0].IsExported() {
			continue
		}
		tag, err := strconv.Unquote(f.Tag.Value)
		if err != nil {
			continue
		}
		y := reflect.StructTag(tag).Get("yaml")
		key, opts, _ := strings.Cut(y, ",")
		if key == "" || key == "-" {
			continue
		}
		doc := commentText(f.Doc)
		if doc == "" {
			doc = commentText(f.Comment)
		}
		out = append(out, field{Key: key, Type: f.Type, Doc: doc, Required: !strings.Contains(opts, "omitempty")})
	}
	return out
}

func commentText(g *ast.CommentGroup) string {
	if g == nil {
		return ""
	}
	return strings.Join(strings.Fields(g.Text()), " ")
}

// typeName returns the exported type a field refers to, looking through
// pointers and slices, or "" for a builtin.
func typeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return typeName(t.X)
	case *ast.ArrayType:
		return typeName(t.Elt)
	case *ast.MapType:
		return typeName(t.Value)
	}
	return ""
}

func reachable(p *pkgInfo) []string {
	var out []string
	seen := map[string]bool{}
	var visit func(string)
	visit = func(n string) {
		if seen[n] {
			return
		}
		fs, ok := p.structs[n]
		if !ok || n == "NameList" {
			return
		}
		seen[n] = true
		out = append(out, n)
		for _, f := range fs {
			visit(typeName(f.Type))
		}
	}
	visit(rootType)
	return out
}

// undocumented lists the Type.key of every field without a comment, so a new
// key cannot ship without its reference entry.
func (p *pkgInfo) undocumented(types []string) []string {
	var out []string
	for _, name := range types {
		for _, f := range p.structs[name] {
			if f.Doc == "" {
				out = append(out, name+"."+f.Key)
			}
		}
	}
	return out
}

func (p *pkgInfo) structSchema(name string) map[string]any {
	props := map[string]any{}
	var required []string
	for _, f := range p.structs[name] {
		s := p.typeSchema(f.Type)
		if f.Doc != "" {
			s["description"] = f.Doc
		}
		props[f.Key] = s
		if f.Required {
			required = append(required, f.Key)
		}
	}
	out := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if d := p.docs[name]; d != "" {
		out["description"] = d
	}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

func (p *pkgInfo) typeSchema(e ast.Expr) map[string]any {
	switch t := e.(type) {
	case *ast.StarExpr:
		return p.typeSchema(t.X)
	case *ast.ArrayType:
		return map[string]any{"type": "array", "items": p.typeSchema(t.Elt)}
	case *ast.MapType:
		return map[string]any{"type": "object", "additionalProperties": p.typeSchema(t.Value)}
	case *ast.StructType:
		props := map[string]any{}
		for _, f := range structFields(t) {
			props[f.Key] = p.typeSchema(f.Type)
		}
		return map[string]any{"type": "object", "properties": props}
	case *ast.InterfaceType:
		return map[string]any{}
	case *ast.SelectorExpr:
		return map[string]any{"type": "string"}
	case *ast.Ident:
		return p.identSchema(t.Name)
	}
	return map[string]any{}
}

func (p *pkgInfo) identSchema(n string) map[string]any {
	switch n {
	case "string":
		return map[string]any{"type": "string"}
	case "bool":
		return map[string]any{"type": "boolean"}
	case "int", "int32", "int64", "uint", "uint32", "uint64":
		return map[string]any{"type": "integer"}
	case "float32", "float64":
		return map[string]any{"type": "number"}
	case "Duration":
		return map[string]any{"type": "string", "description": "Go duration such as 30s, 10m or 24h."}
	case "NameList":
		return map[string]any{"oneOf": []any{
			map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Replaces the inherited list."},
			map[string]any{"type": "object", "additionalProperties": false, "description": "Edits the inherited list.", "properties": map[string]any{
				"add": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "remove": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			}},
		}}
	}
	if _, ok := p.structs[n]; ok {
		return map[string]any{"$ref": "#/$defs/" + n}
	}
	if vals, ok := p.enums[n]; ok {
		return map[string]any{"type": "string", "enum": vals}
	}
	if under, ok := p.basics[n]; ok {
		return p.identSchema(under)
	}
	return map[string]any{}
}

func (p *pkgInfo) typeLabel(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return p.typeLabel(t.X)
	case *ast.ArrayType:
		return "list of " + p.typeLabel(t.Elt)
	case *ast.MapType:
		return "map of " + p.typeLabel(t.Value)
	case *ast.StructType:
		return "object"
	case *ast.SelectorExpr:
		return "string"
	case *ast.Ident:
		switch t.Name {
		case "string":
			return "string"
		case "bool":
			return "boolean"
		case "int", "int32", "int64", "uint", "uint32", "uint64":
			return "integer"
		case "float32", "float64":
			return "number"
		case "Duration":
			return "duration"
		case "NameList":
			return "name list"
		}
		if _, ok := p.structs[t.Name]; ok {
			return "[" + t.Name + "](#" + strings.ToLower(t.Name) + ")"
		}
		if vals, ok := p.enums[t.Name]; ok {
			return "one of " + strings.Join(quoteAll(vals), ", ")
		}
		if under, ok := p.basics[t.Name]; ok {
			return p.typeLabel(&ast.Ident{Name: under})
		}
		return t.Name
	}
	return "any"
}

func quoteAll(v []string) []string {
	out := make([]string, len(v))
	for i, s := range v {
		out[i] = "`" + s + "`"
	}
	return out
}

func (p *pkgInfo) markdown(types []string) string {
	var b strings.Builder
	b.WriteString("# Configuration reference\n\n")
	b.WriteString("<!-- Generated by `make gen` from the Go types in internal/config. Do not edit. -->\n\n")
	b.WriteString("Every key the configuration file accepts, in the order the loader defines them. Keys marked *required* have no default. Unknown keys are rejected. The machine-readable form is [config.schema.json](config.schema.json). How policy blocks inherit (global, site, endpoint) is described in [the configuration model](../architecture/config-model.md).\n\n")
	for _, name := range types {
		fmt.Fprintf(&b, "## %s\n\n", name)
		if d := p.docs[name]; d != "" {
			b.WriteString(d + "\n\n")
		}
		b.WriteString("| Key | Type | Description |\n| --- | --- | --- |\n")
		for _, f := range p.structs[name] {
			desc := strings.ReplaceAll(f.Doc, "|", "\\|")
			if f.Required {
				desc = strings.TrimSpace("*Required.* " + desc)
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", f.Key, strings.ReplaceAll(p.typeLabel(f.Type), "|", "\\|"), desc)
		}
		b.WriteString("\n")
	}
	return b.String()
}
