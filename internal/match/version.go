// Package match evaluates OSV records against an inventory.
package match

import "strings"

// CompareVersions orders dpkg versions per deb-version(7), returning a negative
// number, zero or a positive number as a sorts before, with or after b.
//
// It is total and never panics. Malformed input, which dpkg would reject, is
// compared on a best-effort basis: an epoch that is not all digits is taken as
// part of the upstream version, the same reading dpkg gives a colon after the
// first one.
func CompareVersions(a, b string) int {
	aEpoch, aUpstream, aRevision := splitVersion(a)
	bEpoch, bUpstream, bRevision := splitVersion(b)
	if c := compareNumbers(aEpoch, bEpoch); c != 0 {
		return c
	}
	if c := compareFragments(aUpstream, bUpstream); c != 0 {
		return c
	}
	return compareFragments(aRevision, bRevision)
}

// splitVersion cuts [epoch:]upstream[-revision]: the epoch ends at the first
// colon and the revision starts after the last hyphen.
func splitVersion(v string) (epoch, upstream, revision string) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i > 0 && isNumber(v[:i]) {
		epoch, v = v[:i], v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

func isNumber(s string) bool {
	for i := range len(s) {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// compareFragments is dpkg's verrevcmp: alternate between non-digit runs,
// compared by order, and digit runs, compared numerically. The end of a string
// counts as an empty run, so "1.0" equals "1.0-0".
func compareFragments(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			if ac, bc := order(a, i), order(b, j); ac != bc {
				return ac - bc
			}
			i++
			j++
		}
		iStart, jStart := i, j
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		if c := compareNumbers(a[iStart:i], b[jStart:j]); c != 0 {
			return c
		}
	}
	return 0
}

// order ranks the byte at s[i], whatever the kind of the other string's byte: ~
// sorts before everything including the end of the string, then the end and
// digits, then letters, then everything else.
func order(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	switch c := s[i]; {
	case isDigit(c):
		return 0
	case c == '~':
		return -1
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return int(c)
	default:
		return int(c) + 256
	}
}

// compareNumbers compares digit strings of any length; "" counts as zero.
func compareNumbers(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return len(a) - len(b)
	}
	return strings.Compare(a, b)
}
