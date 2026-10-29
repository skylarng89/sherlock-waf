package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"syscall"
)

func tlsClient(skipVerify bool) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: skipVerify} //nolint:gosec // an operator-chosen, per-request diagnostic option mirroring the upstream setting
}

// classifyDialError reduces a transport error to a short class that is safe to
// show: it never contains addresses or response data.
func classifyDialError(err error) string {
	var dns *net.DNSError
	var cert x509.UnknownAuthorityError
	var host x509.HostnameError
	var inval x509.CertificateInvalidError
	switch {
	case errors.As(err, &dns):
		return "dns"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return "timeout"
	case errors.As(err, &cert), errors.As(err, &host), errors.As(err, &inval), strings.Contains(err.Error(), "tls:"):
		return "tls"
	}
	return "protocol"
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
