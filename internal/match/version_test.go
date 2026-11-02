package match

import (
	"strings"
	"testing"
)

// dpkgVectors is the __DATA__ table of dpkg's scripts/t/Dpkg_Version.t.
const dpkgVectors = `1.0-1 2.0-2 -1
2.2~rc-4 2.2-1 -1
2.2-1 2.2~rc-4 1
1.0000-1 1.0-1 0
1 0:1 0
0 0:0-0 0
2:2.5 1:7.5 1
1:0foo 0foo 1
0:0foo 0foo 0
0foo 0foo 0
0foo-0 0foo 0
0foo 0foo-0 0
0foo 0fo 1
0foo-0 0foo+ -1
0foo~1 0foo -1
0foo~foo+Bar 0foo~foo+bar -1
0foo~~ 0foo~ -1
1~ 1 -1
12345+that-really-is-some-ver-0 12345+that-really-is-some-ver-10 -1
0foo-0 0foo-01 -1
0foo.bar 0foobar 1
0foo.bar 0foo1bar 1
0foo.bar 0foo0bar 1
0foo1bar-1 0foobar-1 -1
0foo2.0 0foo2 1
0foo2.0.0 0foo2.10.0 -1
0foo2.0 0foo2.0.0 -1
0foo2.0 0foo2.10 -1
0foo2.1 0foo2.10 -1
1.09 1.9 0
1.0.8+nmu1 1.0.8 1
3.11 3.10+nmu1 1
0.9j-20080306-4 0.9i-20070324-2 1
1.2.0~b7-1 1.2.0~b6-1 1
1.011-1 1.06-2 1
0.0.9+dfsg1-1 0.0.8+dfsg1-3 1
4.6.99+svn6582-1 4.6.99+svn6496-1 1
53 52 1
0.9.9~pre122-1 0.9.9~pre111-1 1
2:2.3.2-2+lenny2 2:2.3.2-2 1
1:3.8.1-1 3.8.GA-1 1
1.0.1+gpl-1 1.0.1-2 1
1a 1000a -1`

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

func checkCompare(t *testing.T, a, b string, want int) {
	t.Helper()
	if got := sign(CompareVersions(a, b)); got != want {
		t.Errorf("CompareVersions(%q, %q) = %d, want %d", a, b, got, want)
	}
	if got := sign(CompareVersions(b, a)); got != -want {
		t.Errorf("CompareVersions(%q, %q) = %d, want %d", b, a, got, -want)
	}
}

func TestCompareVersionsDpkgTable(t *testing.T) {
	for line := range strings.Lines(dpkgVectors) {
		f := strings.Fields(line)
		want := map[string]int{"-1": -1, "0": 0, "1": 1}[f[2]]
		checkCompare(t, f[0], f[1], want)
	}
}

// The structured cases of dpkg's lib/dpkg/t/t-version.c: the string on the left
// parses into the object spelled out on the right, written back as a version.
func TestCompareVersionsTVersion(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"0-0", "0-0", 0},
		{"0-00", "00-0", 0},
		{"1:2-3", "1:2-3", 0},
		{"0:0-0", "1:0-0", -1},
		{"a-0", "b-0", -1},
		{"0-a", "0-b", -1},
		{"0:1-1", "0:2-1", -1},
		{"0:1-1", "0:1-2", -1},
		{"0", "0:0", 0},
		{"0:0-0", "0-0", 0},
		{"0:0.0-0.0", "0.0-0.0", 0},
		{"1:0", "1:0-", 0},
		{"5:1", "5:1-", 0},
		// Multiple hyphens: the last one starts the revision.
		{"0:0-0-0", "0-0-0", 0},
		{"0:0-0-0", "0-1-0", -1},
		{"0:0-0-0-0", "0-0-0-0", 0},
		// Multiple colons: the first one ends the epoch.
		{"0:0:0-0", "0:0:0-0", 0},
		{"0:0:0:0-0", "0:0:0:0-0", 0},
		{"0:0:0-0-0", "0:0:0-0-0", 0},
		{"0:0-0:0-0", "0:0-0:0-0", 0},
		// Every allowed character.
		{"0:09azAZ.-+~:-0", "09azAZ.-+~:-0", 0},
		{"0:0-azAZ09.+~", "0-azAZ09.+~", 0},
		// Surrounding blanks.
		{"  \t0:0-1", "0-1", 0},
		{"0:0-1\t  ", "0-1", 0},
		{"\t  0:0-1  \t", "0-1", 0},
	} {
		checkCompare(t, tc.a, tc.b, tc.want)
	}
}

func TestCompareVersionsDebianPractice(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		// binNMU, stable and backport suffixes.
		{"5.2.15-2+b13", "5.2.15-2", 1},
		{"5.2.15-2+b2", "5.2.15-2+b13", -1},
		{"5.2.15-2+b13", "5.2.15-3", -1},
		{"3.0.11-1~deb12u2", "3.0.11-1", -1},
		{"3.0.11-1~deb12u2", "3.0.11-1~deb12u10", -1},
		{"7.88.1-10+deb12u1~bpo11+1", "7.88.1-10+deb12u1", -1},
		// Ubuntu.
		{"3.0.13-0ubuntu3.1", "3.0.13-0ubuntu3", 1},
		{"2.39-0ubuntu8.1", "2.39-0ubuntu8.10", -1},
		{"6.8.0-45.45", "6.8.0-100.100", -1},
		// Revisions: empty equals zero, and native packages have none.
		{"1.0", "1.0-0", 0},
		{"1.0", "1.0-1", -1},
		{"1.0-1", "1.0", 1},
		// Epochs beat everything, and numbers can be any length.
		{"1:1.0", "2.0", 1},
		{"0:9", "1:0", -1},
		{"1.99999999999999999999999", "1.99999999999999999999998", 1},
		// Letters sort before other symbols, and ~ before the end of the string.
		{"1.0a", "1.0+", -1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~~", "1.0~", -1},
		{"1.0~", "1.0~a", -1},
	} {
		checkCompare(t, tc.a, tc.b, tc.want)
	}
}

// Strings dpkg's parser rejects (t-version.c's failure cases, plus noise) still
// compare consistently, without panicking.
func TestCompareVersionsMalformed(t *testing.T) {
	bad := []string{
		"", " ", "0:", ":1.0", "1.0-", "0:0 0-1", "-1:0-1", "999999999999999999999999:0-1",
		"a:0-0", "A:0-0", "-0", "0:-0", "0:abc3-0", "0:0-0:0", "1:2:3", "::", "--", "\x00", "\xff\xfe", "~",
		"1.0!", "1.0-!", "0:0~", "日本語",
	}
	for _, a := range bad {
		if c := CompareVersions(a, a); c != 0 {
			t.Errorf("CompareVersions(%q, %q) = %d, want 0", a, a, c)
		}
		for _, b := range bad {
			if ab, ba := sign(CompareVersions(a, b)), sign(CompareVersions(b, a)); ab != -ba {
				t.Errorf("not antisymmetric on %q, %q: %d and %d", a, b, ab, ba)
			}
		}
	}
	// A large epoch that dpkg rejects still outranks a small one, without overflow.
	checkCompare(t, "999999999999999999999999:0-1", "1:0-1", 1)
	// An epoch that is not a number is upstream text.
	checkCompare(t, "a:0-0", "0:a:0-0", 0)
}

func FuzzCompareVersions(f *testing.F) {
	for line := range strings.Lines(dpkgVectors) {
		fields := strings.Fields(line)
		f.Add(fields[0], fields[1])
	}
	f.Add("", ":")
	f.Add("\xff:-~", "0:~-")
	f.Fuzz(func(t *testing.T, a, b string) {
		if ab, ba := sign(CompareVersions(a, b)), sign(CompareVersions(b, a)); ab != -ba {
			t.Errorf("not antisymmetric on %q, %q: %d and %d", a, b, ab, ba)
		}
	})
}

func BenchmarkCompareVersions(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		CompareVersions("1:6.1.112-1+deb12u1~bpo11+1", "1:6.1.112-1+deb12u1~bpo11+2")
	}
}
