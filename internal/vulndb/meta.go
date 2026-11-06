package vulndb

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/vitalii-ye/vmmon/internal/fsutil"
)

const (
	metaFile     = "meta.json"
	metaLockFile = "meta.lock"
)

// ErrSyncInProgress is returned at once, without waiting, when another process
// or goroutine is already syncing this data directory.
var ErrSyncInProgress = errors.New("another sync is already running")

// ReadMeta returns the content of meta.json in dir. A missing file gives an
// empty Meta.
func ReadMeta(dir string) (Meta, error) {
	m := Meta{Ecosystems: map[string]EcosystemMeta{}}
	data, err := os.ReadFile(filepath.Join(dir, metaFile))
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return Meta{Ecosystems: map[string]EcosystemMeta{}}, fmt.Errorf("parse %s: %w", metaFile, err)
	}
	if m.Ecosystems == nil {
		m.Ecosystems = map[string]EcosystemMeta{}
	}
	return m, nil
}

// UpdateMeta applies fn to meta.json in dir under an exclusive lock, so the
// vulndb and enrich sections can be updated independently without losing each
// other's writes. A corrupt file is replaced; losing it only forces a full
// sync.
func UpdateMeta(dir string, fn func(*Meta)) error {
	if err := EnsureDir(dir); err != nil {
		return err
	}
	unlock, err := flock(filepath.Join(dir, metaLockFile), true)
	if err != nil {
		return err
	}
	defer unlock()
	RemoveTemps(dir, metaFile+".")

	m, err := ReadMeta(dir)
	if err != nil {
		slog.Warn("replacing unreadable metadata", "err", err)
	}
	fn(&m)
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, metaFile), append(data, '\n'), 0o644)
}

// EnsureDir creates a data directory owned like its parent.
func EnsureDir(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return fsutil.MatchDirOwner(dir)
}

// TryLock takes the exclusive advisory lock at path. It returns
// ErrSyncInProgress when another holder has it. The kernel releases the lock if
// the process dies, so a killed sync never blocks the next one.
func TryLock(path string) (unlock func(), err error) {
	return flock(path, false)
}

func flock(path string, wait bool) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err := fsutil.MatchDirOwner(path); err != nil {
		_ = f.Close()
		return nil, err
	}
	how := syscall.LOCK_EX
	if !wait {
		how |= syscall.LOCK_NB
	}
	for {
		err = syscall.Flock(int(f.Fd()), how)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrSyncInProgress
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() { _ = f.Close() }, nil
}

// RemoveTemps deletes temporary files in dir left by a killed run, for files
// whose names start with prefix. Call it only while holding the lock that
// guards those files.
func RemoveTemps(dir, prefix string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) && strings.Contains(e.Name(), ".tmp-") {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// Compact copies the finished bolt file at path to a new temp file beside it,
// and returns that file's name. Keys inserted out of order fragment the pages,
// so the copy is much smaller. The caller removes both files.
func Compact(path string) (string, error) {
	src, err := bolt.Open(path, 0o644, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return "", err
	}
	defer func() { _ = src.Close() }()
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".compact.tmp-*")
	if err != nil {
		return "", err
	}
	_ = tmp.Close()
	if err := compactTo(tmp.Name(), src); err != nil {
		_ = os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

func compactTo(path string, src *bolt.DB) error {
	dst, err := bolt.Open(path, 0o644, &bolt.Options{NoSync: true, NoFreelistSync: true, Timeout: time.Second})
	if err != nil {
		return err
	}
	defer func() { _ = dst.Close() }()
	if err := bolt.Compact(dst, src, 4<<20); err != nil {
		return err
	}
	// Bolt grows files in 16 MB steps; give back the unused tail.
	var used int64
	if err := dst.View(func(tx *bolt.Tx) error {
		used = tx.Size()
		return nil
	}); err != nil {
		return err
	}
	if err := dst.Sync(); err != nil {
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	return os.Truncate(path, used)
}

// syncDir makes a completed rename in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// PublishFile makes a finished temporary file world-readable, owned like its
// directory and durable, then renames it over dst.
func PublishFile(tmp, dst string) error {
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	if err := fsutil.MatchDirOwner(tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	return syncDir(filepath.Dir(dst))
}
