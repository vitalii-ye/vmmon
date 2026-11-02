package inventory

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// statusFile is the dpkg database, relative to the scanned root.
const statusFile = "var/lib/dpkg/status"

// StatusPath returns the dpkg status file under root, for mtime checks.
func StatusPath(root string) string {
	if root == "" {
		root = "/"
	}
	return filepath.Join(root, statusFile)
}

// liveHost answers what only the running system knows. It is nil when
// scanning an offline root.
type liveHost struct {
	uname    func() (string, error)
	hostname func() (string, error)
}

// Collect inventories the host mounted at root; "" and "/" mean the running
// system. It fails rather than returning an empty inventory: an unsupported
// release gives an error matching ErrUnsupportedRelease, and a dpkg database
// that is missing or lists no installed packages is also an error.
func Collect(ctx context.Context, root string) (*Host, error) {
	if root == "" || filepath.Clean(root) == "/" {
		return collect(ctx, "/", &liveHost{uname: uname, hostname: os.Hostname})
	}
	return collect(ctx, root, nil)
}

func collect(ctx context.Context, rootPath string, live *liveHost) (*Host, error) {
	// os.Root keeps every read inside the scanned tree. Without it the absolute
	// symlink /var/run -> /run in an offline root would report the state of the
	// machine doing the scanning.
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open root: %w", err)
	}
	defer root.Close()

	release, err := readRelease(root)
	if err != nil {
		return nil, err
	}
	pkgs, err := readPackages(ctx, root, release.Distro)
	if err != nil {
		return nil, err
	}

	var hostname, running string
	if live != nil {
		if running, err = live.uname(); err != nil {
			return nil, fmt.Errorf("uname: %w", err)
		}
		if hostname, err = live.hostname(); err != nil {
			return nil, fmt.Errorf("hostname: %w", err)
		}
	} else {
		hostname = readHostname(root)
	}
	return &Host{
		Hostname: hostname,
		Release:  release,
		Kernel:   kernelState(root, pkgs, running),
		Packages: pkgs,
	}, nil
}

// readFirst returns the first of paths that can be read. On failure the error
// is that of the last path.
func readFirst(root *os.Root, paths ...string) (data []byte, err error) {
	for _, p := range paths {
		if data, err = root.ReadFile(p); err == nil {
			return data, nil
		}
	}
	return nil, err
}

// readHostname returns the name in etc/hostname, or "" without one.
func readHostname(root *os.Root) string {
	data, err := root.ReadFile("etc/hostname")
	if err != nil {
		return ""
	}
	for line := range strings.Lines(string(data)) {
		if line = strings.TrimSpace(line); line != "" && line[0] != '#' {
			return line
		}
	}
	return ""
}
