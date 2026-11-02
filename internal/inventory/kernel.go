package inventory

import (
	"cmp"
	"os"
	"regexp"
	"slices"
	"strings"
)

// imageName matches a package holding a bootable kernel, capturing its
// `uname -r` release. The full x.y.z requirement is what separates
// linux-image-6.8.0-45-generic and linux-image-6.12.107+deb13-amd64 from
// Debian's metapackage linux-image-6.12-amd64. Variants are the Ubuntu unsigned-
// and uc- (Core) prefixes and Debian's -unsigned suffix.
var imageName = regexp.MustCompile(`^linux-image-(?:unsigned-|uc-)?(\d+\.\d+\.\d+.*?)(?:-unsigned)?$`)

// kernelRelease returns the kernel release of a versioned kernel image package,
// or "" for anything else: metapackages, debug symbols and signing templates.
func kernelRelease(name string) string {
	m := imageName.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	for _, suffix := range []string{"-dbg", "-dbgsym", "-signed-template"} {
		if strings.HasSuffix(m[1], suffix) {
			return ""
		}
	}
	return m[1]
}

// kernelState works out the kernel facts. running is `uname -r`, empty for an
// offline root.
//
// A running kernel with no matching package (removed since boot, or a custom
// build) falls back to the newest image for identity. It cannot be compared with
// the installed images, so only the marker file can then require a reboot.
func kernelState(root *os.Root, pkgs []Package, running string) Kernel {
	var current, newest *Package
	for i := range pkgs {
		p := &pkgs[i]
		if !p.IsKernelImage {
			continue
		}
		if current == nil && running != "" && kernelRelease(p.Name) == running {
			current = p
		}
		if newest == nil || compareVersions(p.Version, newest.Version) > 0 {
			newest = p
		}
	}

	k := Kernel{Release: running}
	_, markerErr := readFirst(root, "var/run/reboot-required", "run/reboot-required")
	k.RebootRequired = markerErr == nil
	if current != nil && newerImageInstalled(pkgs, current) {
		k.RebootRequired = true
	}
	if current == nil {
		current = newest
	}
	if current != nil {
		k.SourceName, k.Version = current.SourceName, current.SourceVersion
	}
	if data, err := readFirst(root, "var/run/reboot-required.pkgs", "run/reboot-required.pkgs"); err == nil {
		for line := range strings.Lines(string(data)) {
			// Each package post-install appends a line, so duplicates are normal.
			if line = strings.TrimSpace(line); line != "" && !slices.Contains(k.RebootPackages, line) {
				k.RebootPackages = append(k.RebootPackages, line)
			}
		}
	}
	return k
}

// newerImageInstalled reports whether an installed image is newer than the
// running one. Revisions only order within one source line: an aws 6.8.0-1016
// beside a running generic 6.8.0-100 is no newer, so across lines only the
// upstream version counts, which still catches HWE 6.8 beside a running GA 5.15.
func newerImageInstalled(pkgs []Package, current *Package) bool {
	_, running, _ := splitVersion(current.Version)
	for i := range pkgs {
		p := &pkgs[i]
		if !p.IsKernelImage {
			continue
		}
		if p.SourceName == current.SourceName {
			if compareVersions(p.Version, current.Version) > 0 {
				return true
			}
			continue
		}
		if _, upstream, _ := splitVersion(p.Version); compareFragment(upstream, running) > 0 {
			return true
		}
	}
	return false
}

// compareVersions orders dpkg versions: epoch, then upstream, then revision.
// It only ranks installed kernel images; internal/match owns version comparison
// for vulnerability matching.
func compareVersions(a, b string) int {
	aEpoch, aUpstream, aRevision := splitVersion(a)
	bEpoch, bUpstream, bRevision := splitVersion(b)
	return cmp.Or(
		compareDigits(aEpoch, bEpoch),
		compareFragment(aUpstream, bUpstream),
		compareFragment(aRevision, bRevision),
	)
}

func splitVersion(v string) (epoch, upstream, revision string) {
	if e, rest, ok := strings.Cut(v, ":"); ok {
		epoch, v = e, rest
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// compareFragment implements the deb-version(7) algorithm: alternate between
// comparing non-digit runs and digit runs.
func compareFragment(a, b string) int {
	for a != "" || b != "" {
		i := 0
		for nonDigitAt(a, i) || nonDigitAt(b, i) {
			if c := cmp.Compare(charOrder(a, i), charOrder(b, i)); c != 0 {
				return c
			}
			i++
		}
		a, b = a[i:], b[i:]

		aDigits, bDigits := digitPrefix(a), digitPrefix(b)
		if c := compareDigits(aDigits, bDigits); c != 0 {
			return c
		}
		a, b = a[len(aDigits):], b[len(bDigits):]
	}
	return 0
}

func digitAt(s string, i int) bool    { return i < len(s) && s[i] >= '0' && s[i] <= '9' }
func nonDigitAt(s string, i int) bool { return i < len(s) && !digitAt(s, i) }

// charOrder ranks ~ before the end of a run, and letters before other symbols.
func charOrder(s string, i int) int {
	if !nonDigitAt(s, i) {
		return 0
	}
	switch c := s[i]; {
	case c == '~':
		return -1
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return int(c)
	default:
		return int(c) + 256
	}
}

func digitPrefix(s string) string {
	i := 0
	for digitAt(s, i) {
		i++
	}
	return s[:i]
}

// compareDigits compares digit strings of any length; "" counts as zero.
func compareDigits(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	return cmp.Or(cmp.Compare(len(a), len(b)), cmp.Compare(a, b))
}
