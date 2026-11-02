// Package fsutil has file helpers for data shared between root and the daemon.
//
// The daemon runs under systemd's DynamicUser, but `sudo vmmon db sync` runs as
// root against the same directory. Files root creates there must end up owned
// by whoever owns the directory, or the daemon can no longer update them.
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// MatchDirOwner chowns path to the owner of its parent directory. It does
// nothing unless running as root.
func MatchDirOwner(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return os.Chown(path, int(st.Uid), int(st.Gid))
}

// WriteFileAtomic writes data to a temporary file beside path, syncs it and
// renames it into place, so a crash leaves either the old file or the new one.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmp.Name(), err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := MatchDirOwner(tmp.Name()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
