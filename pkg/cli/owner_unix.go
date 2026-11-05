//go:build unix

package cli

import (
	"os"
	"syscall"
)

// matchOwner gives paths the owner of dir when running as root, so a backup or
// database file created by a root-run command does not lock the service user out.
func matchOwner(dir string, paths ...string) {
	if os.Geteuid() != 0 {
		return
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	for _, p := range paths {
		_ = os.Lchown(p, int(st.Uid), int(st.Gid))
	}
}
