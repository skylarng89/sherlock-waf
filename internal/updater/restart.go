package updater

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"time"
)

// UnitName is the systemd unit the packages install.
const UnitName = "sherlock.service"

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// InContainer reports whether the process runs in a container, where the image
// (not the binary inside it) is the unit of update.
func InContainer() bool {
	for _, p := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return os.Getenv("KUBERNETES_SERVICE_HOST") != ""
}

// UnderSystemd reports whether this host runs systemd and the Sherlock unit is active.
func UnderSystemd(ctx context.Context) bool {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return false
	}
	return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", UnitName).Run() == nil //nolint:gosec // fixed arguments
}

// RestartSystemd restarts the unit and waits until it reports active, up to wait.
func RestartSystemd(ctx context.Context, wait time.Duration) error {
	if err := exec.CommandContext(ctx, "systemctl", "restart", UnitName).Run(); err != nil { //nolint:gosec // fixed arguments
		return err
	}
	deadline := time.Now().Add(wait)
	for {
		if exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", UnitName).Run() == nil { //nolint:gosec // fixed arguments
			// A crash loop restarts quickly; require the unit to stay up briefly.
			select {
			case <-time.After(3 * time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
			if exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", UnitName).Run() == nil { //nolint:gosec // fixed arguments
				return nil
			}
		}
		if time.Now().After(deadline) {
			return context.DeadlineExceeded
		}
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
