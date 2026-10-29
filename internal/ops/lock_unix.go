//go:build unix

package ops

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ErrLocked means another process holds the data directory.
var ErrLocked = errors.New("the data directory is in use by a running sherlock server")

// Lock takes the exclusive data-directory lock without waiting. The server
// holds it while it runs; commands that must not race a live node (offline
// configuration import, key rotation) take it too and so refuse to run beside one.
func Lock(dataDir string) (release func(), err error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating data dir: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dataDir, "sherlock.lock"), os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // operator data dir
	if err != nil {
		return nil, fmt.Errorf("opening lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // fd fits int
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("locking data dir: %w", err)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil //nolint:gosec // fd fits int
}
