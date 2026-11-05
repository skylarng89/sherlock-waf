package api

import (
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/oapi"
)

// newRequestValidator compiles the embedded document once. A document the
// router cannot serve is a start-up error, never a silently unchecked API.
func newRequestValidator(spec *openapi3.T) (*oapi.Validator, error) {
	v, err := oapi.NewValidator(spec)
	if err != nil {
		return nil, fmt.Errorf("compiling request validator: %w", err)
	}
	return v, nil
}

// validateRequest checks a request that has passed authentication and
// authorisation against the operation it matches. It runs after those checks so
// an anonymous caller learns nothing about the schema from the response.
// Parameters and bodies are validated against the document, and the body is
// restored for the strict decoder and the handler.
func (s *Server) validateRequest(r *http.Request) error {
	route, _, out := s.validator.Route(r)
	if out != oapi.Conforms {
		return errNotFound("this route")
	}
	if route.Operation.RequestBody != nil && hasBody(r) {
		if err := checkMediaType(r, route.Operation.RequestBody.Value); err != nil {
			return err
		}
	}
	out, vs, skipped := s.validator.Check(r, maxBodyBytes)
	if skipped {
		// A body over the cap is never validated: the document cannot describe
		// a partial body, and the handler could not read it in full either.
		return errBadRequest("The request body is larger than the 4 MiB limit.")
	}
	if out == oapi.Conforms {
		return nil
	}
	if out != oapi.Invalid {
		return errNotFound("this route")
	}
	errs := make([]config.Error, 0, len(vs))
	for _, v := range vs {
		if v.Malformed {
			return errBadRequest(fmt.Sprintf("The request is malformed at %s: %s.", v.Pointer, v.Message))
		}
		// Messages come from the schema reason, never the offending value, so
		// passwords and tokens do not reach the response.
		errs = append(errs, config.Error{Path: bodyRelative(v.Pointer), Code: "schema", Message: v.Message})
	}
	return &problem{
		Status: 422, Code: "invalid_request", Title: "Invalid request",
		Detail: "The request does not match the API description.", Errors: errs,
	}
}

// bodyRelative makes a body violation point into the request document
// (/name, /hosts/0) like the config validation errors do, which is the shape
// the dashboard maps onto form fields. Parameter pointers keep their prefix.
func bodyRelative(pointer string) string {
	if rest, ok := strings.CutPrefix(pointer, "/body"); ok && (rest == "" || rest[0] == '/') {
		if rest == "" {
			return "/"
		}
		return rest
	}
	return pointer
}

func hasBody(r *http.Request) bool {
	return r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
}

// checkMediaType refuses a body whose Content-Type the operation does not
// declare (closes S-14: JSON endpoints must not accept form or text bodies).
func checkMediaType(r *http.Request, body *openapi3.RequestBody) error {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err == nil {
		if _, ok := body.Content[mt]; ok {
			return nil
		}
	}
	return newProblem(http.StatusUnsupportedMediaType, "unsupported_media_type", "Unsupported media type",
		"The request body must use one of the media types the operation documents.")
}
