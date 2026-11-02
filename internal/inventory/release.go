package inventory

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// ErrUnsupportedRelease matches every UnsupportedReleaseError through errors.Is.
var ErrUnsupportedRelease = errors.New("unsupported release")

// supportedReleases lists every release vmmon can match, keyed by distro and
// VERSION_ID. Ubuntu interim releases are absent on purpose.
var supportedReleases = map[[2]string]Release{
	{"debian", "12"}:    {Ecosystem: "Debian:12", Root: "Debian"},
	{"debian", "13"}:    {Ecosystem: "Debian:13", Root: "Debian"},
	{"ubuntu", "22.04"}: {Ecosystem: "Ubuntu:22.04:LTS", Root: "Ubuntu"},
	{"ubuntu", "24.04"}: {Ecosystem: "Ubuntu:24.04:LTS", Root: "Ubuntu"},
}

// UnsupportedReleaseError names the release that was detected. Both fields are
// empty when the root has no os-release file at all.
type UnsupportedReleaseError struct {
	Distro  string
	Version string
}

func (e *UnsupportedReleaseError) Error() string {
	detected := strings.TrimSpace(e.Distro + " " + e.Version)
	if detected == "" {
		detected = "no os-release file"
	}
	return fmt.Sprintf("%v: found %s; vmmon supports Debian 12, 13 and Ubuntu 22.04, 24.04", ErrUnsupportedRelease, detected)
}

func (e *UnsupportedReleaseError) Unwrap() error { return ErrUnsupportedRelease }

// readRelease identifies the release from os-release(5).
func readRelease(root *os.Root) (Release, error) {
	data, err := readFirst(root, "etc/os-release", "usr/lib/os-release")
	if errors.Is(err, fs.ErrNotExist) {
		return Release{}, &UnsupportedReleaseError{}
	}
	if err != nil {
		return Release{}, fmt.Errorf("read os-release: %w", err)
	}
	vars := parseOSRelease(string(data))
	r, ok := supportedReleases[[2]string{vars["ID"], vars["VERSION_ID"]}]
	if !ok {
		return Release{}, &UnsupportedReleaseError{Distro: vars["ID"], Version: vars["VERSION_ID"]}
	}
	r.Distro, r.Version, r.Codename = vars["ID"], vars["VERSION_ID"], vars["VERSION_CODENAME"]
	return r, nil
}

// parseOSRelease reads shell-style KEY=value lines. Distro files only quote
// whole values, so full shell unquoting is not needed.
func parseOSRelease(data string) map[string]string {
	vars := map[string]string{}
	for line := range strings.Lines(data) {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		if n := len(value); n >= 2 && (value[0] == '"' || value[0] == '\'') && value[n-1] == value[0] {
			value = value[1 : n-1]
		}
		vars[key] = value
	}
	return vars
}
