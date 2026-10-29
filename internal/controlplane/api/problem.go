package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/configsvc"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/auth"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

const problemBase = "urn:sherlock:problem:"

// problem is an error that renders as an RFC 9457 document. Handlers return
// it (or a sentinel it wraps) and never write an error response themselves.
type problem struct {
	Status     int
	Code       string
	Title      string
	Detail     string
	Errors     []config.Error
	RetryAfter time.Duration
}

func (p *problem) Error() string { return p.Code + ": " + p.Detail }

func newProblem(status int, code, title, detail string) *problem {
	return &problem{Status: status, Code: code, Title: title, Detail: detail}
}

var (
	errBadRequest   = func(detail string) *problem { return newProblem(400, "bad_request", "Bad request", detail) }
	errForbidden    = func(detail string) *problem { return newProblem(403, "forbidden", "Forbidden", detail) }
	errNotFound     = func(what string) *problem { return newProblem(404, "not_found", "Not found", what+" does not exist") }
	errConflict     = func(detail string) *problem { return newProblem(409, "conflict", "Conflict", detail) }
	errUnprocessed  = func(detail string) *problem { return newProblem(422, "unprocessable", "Unprocessable entity", detail) }
	errUnauthorised = newProblem(401, "unauthenticated", "Authentication required", "Sign in or present a valid API token.")
)

// toProblem maps domain errors to problems. Anything unrecognised becomes a
// generic 500 whose detail never leaks internals; the cause is logged with the
// request id by the caller.
func toProblem(err error) (p *problem, internal bool) {
	var (
		pr *problem
		ie *configsvc.InvalidError
		te *auth.ThrottledError
	)
	switch {
	case errors.As(err, &pr):
		return pr, false
	case errors.As(err, &ie):
		return &problem{Status: 422, Code: "invalid_config", Title: "Invalid configuration", Detail: "The configuration failed validation.", Errors: ie.Errors}, false
	case errors.As(err, &te):
		return &problem{Status: 429, Code: "throttled", Title: "Too many attempts", Detail: "Try again later.", RetryAfter: te.RetryAfter}, false
	case errors.Is(err, configsvc.ErrPreconditionFailed):
		return newProblem(412, "precondition_failed", "Precondition failed", "The configuration changed since you read it; fetch it again and retry."), false
	case errors.Is(err, configsvc.ErrPreconditionRequired):
		return newProblem(428, "precondition_required", "Precondition required", "Send If-Match with the ETag of the configuration you read."), false
	case errors.Is(err, configsvc.ErrActivation):
		return newProblem(422, "activation_failed", "Activation failed", "The data plane rejected the configuration; the previous configuration is still live."), false
	case errors.Is(err, configsvc.ErrNotFound), errors.Is(err, store.ErrNotFound):
		return errNotFound("the requested object"), false
	case errors.Is(err, store.ErrConflict):
		return errConflict("An object with that identifier already exists."), false
	case errors.Is(err, auth.ErrInvalidCredentials):
		return newProblem(401, "invalid_credentials", "Invalid credentials", "The username or password is incorrect."), false
	case errors.Is(err, auth.ErrInvalidCode):
		return newProblem(401, "invalid_code", "Invalid code", "The verification code is incorrect or already used."), false
	case errors.Is(err, auth.ErrUnauthenticated):
		return errUnauthorised, false
	case errors.Is(err, auth.ErrWrongStage):
		return newProblem(403, "wrong_stage", "Wrong sign-in step", "This step is not available for your session."), false
	case errors.Is(err, auth.ErrWeakPassword):
		return errBadRequest(err.Error()), false
	}
	return newProblem(500, "internal", "Internal error", "The request could not be completed."), true
}

func writeProblem(w http.ResponseWriter, p *problem, requestID string) {
	body := map[string]any{"type": problemBase + p.Code, "title": p.Title, "status": p.Status}
	if p.Detail != "" {
		body["detail"] = p.Detail
	}
	if len(p.Errors) > 0 {
		body["errors"] = p.Errors
	}
	if requestID != "" {
		body["request_id"] = requestID
	}
	h := w.Header()
	h.Set("Content-Type", "application/problem+json")
	h.Set("Cache-Control", "no-store")
	if p.RetryAfter > 0 {
		secs := int(p.RetryAfter.Seconds()) + 1
		h.Set("Retry-After", strconv.Itoa(secs))
		body["retry_after_seconds"] = secs
	}
	if p.Status == http.StatusUnauthorized {
		h.Set("WWW-Authenticate", `Bearer realm="sherlock"`)
	}
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(body)
}

// errorHandler is installed as both the request and response error handler of
// the strict server.
func (s *Server) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	p, internal := toProblem(err)
	id := requestIDFrom(r.Context())
	if internal {
		s.log.ErrorContext(r.Context(), "request failed", slog.String("request_id", id), slog.String("path", r.URL.Path), slog.Any("error", err))
	}
	writeProblem(w, p, id)
}

// badRequestHandler turns request decoding failures (malformed JSON, bad
// parameters) into 400s without echoing parser internals beyond their message.
func (s *Server) badRequestHandler(w http.ResponseWriter, r *http.Request, err error) {
	writeProblem(w, errBadRequest(err.Error()), requestIDFrom(r.Context()))
}
