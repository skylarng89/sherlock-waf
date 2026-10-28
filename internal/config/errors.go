package config

import (
	"fmt"
	"strings"
)

// Error codes returned in Error.Code.
const (
	CodeSyntax       = "syntax"
	CodeUnknownField = "unknown_field"
	CodeRequired     = "required"
	CodeInvalid      = "invalid"
	CodeDuplicate    = "duplicate"
	CodeOutOfRange   = "out_of_range"
	CodeUnsupported  = "unsupported"
	CodeAmbiguous    = "ambiguous"
)

// Error is one problem found in a configuration; Path is a JSON pointer.
type Error struct {
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Errors is a list of configuration problems and implements error.
type Errors []Error

func (e Errors) Error() string {
	parts := make([]string, len(e))
	for i, x := range e {
		parts[i] = fmt.Sprintf("%s: %s (%s)", pathOrRoot(x.Path), x.Message, x.Code)
	}
	return "invalid configuration: " + strings.Join(parts, "; ")
}

func pathOrRoot(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func (e *Errors) add(path, code, format string, args ...any) {
	*e = append(*e, Error{Path: path, Code: code, Message: fmt.Sprintf(format, args...)})
}
