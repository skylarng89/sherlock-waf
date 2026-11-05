//go:build !unix

package ops

import "errors"

// ErrLocked means another process holds the data directory.
var ErrLocked = errors.New("the data directory is in use by a running sherlock server")

// Lock is unsupported off Unix; it fails closed rather than pretend to protect the node.
func Lock(string) (func(), error) {
	return nil, errors.New("data-directory locking is only supported on Unix systems")
}
