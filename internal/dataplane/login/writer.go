package login

import "net/http"

// statusWriter records the status the upstream answered with and otherwise
// stays out of the way: it never buffers, so streaming responses and upgrades
// behave as without it.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	// 1xx interim responses precede the real one; 101 (an upgrade) is final.
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		s.ResponseWriter.WriteHeader(code)
		return
	}
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(p []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(p)
}

// FlushError lets http.ResponseController flush through to the real writer.
func (s *statusWriter) FlushError() error {
	return http.NewResponseController(s.ResponseWriter).Flush()
}

// Unwrap lets http.ResponseController reach the underlying writer (hijacking,
// deadlines).
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
