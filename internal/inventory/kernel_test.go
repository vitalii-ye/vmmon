package inventory

import (
	"os"
	"testing"
)

func TestKernelRelease(t *testing.T) {
	for name, want := range map[string]string{
		// Debian images.
		"linux-image-6.1.0-26-amd64":               "6.1.0-26-amd64",
		"linux-image-6.1.0-26-cloud-amd64":         "6.1.0-26-cloud-amd64",
		"linux-image-6.12.107+deb13-amd64":         "6.12.107+deb13-amd64",
		"linux-image-6.12.113+deb12-rt-amd64":      "6.12.113+deb12-rt-amd64",
		"linux-image-6.1.0-54-amd64-unsigned":      "6.1.0-54-amd64",
		"linux-image-6.12.94+deb13-amd64-unsigned": "6.12.94+deb13-amd64",
		// Ubuntu images.
		"linux-image-6.8.0-45-generic":          "6.8.0-45-generic",
		"linux-image-6.8.0-1016-aws":            "6.8.0-1016-aws",
		"linux-image-unsigned-7.0.0-42-generic": "7.0.0-42-generic",
		"linux-image-uc-6.14.0-1018-aws":        "6.14.0-1018-aws",
		// Debian metapackages, including a version-looking one.
		"linux-image-amd64":            "",
		"linux-image-cloud-amd64":      "",
		"linux-image-6.12-amd64":       "",
		"linux-image-6.12-cloud-amd64": "",
		// Ubuntu metapackages.
		"linux-image-generic":           "",
		"linux-image-virtual":           "",
		"linux-image-generic-hwe-24.04": "",
		"linux-image-aws-6.8":           "",
		"linux-image-extra-virtual-6.8": "",
		// Not bootable.
		"linux-image-6.1.0-54-amd64-dbg":               "",
		"linux-image-amd64-dbg":                        "",
		"linux-image-6.12-amd64-signed-template":       "",
		"linux-image-6.1.0-54-amd64-signed-template":   "",
		"linux-image-unsigned-6.8.0-45-generic-dbgsym": "",
		// Not images.
		"linux-headers-6.1.0-26-amd64":   "",
		"linux-modules-6.8.0-45-generic": "",
		"linux-libc-dev":                 "",
	} {
		if got := kernelRelease(name); got != want {
			t.Errorf("kernelRelease(%q) = %q, want %q", name, got, want)
		}
	}
}

// Shapes taken from the bookworm-security, trixie, jammy-updates and
// noble-updates Packages indexes. The chosen source names were checked against
// the package names in OSV's all.zip for each ecosystem.
func TestNewPackage(t *testing.T) {
	for name, tc := range []struct {
		distro, pkg, version, srcName, srcVersion string
		wantName, wantVersion                     string
		wantImage                                 bool
	}{
		// Plain source handling.
		0: {"debian", "base-files", "12.4", "", "", "base-files", "12.4", false},
		1: {"debian", "libc6", "2.36-9", "glibc", "", "glibc", "2.36-9", false},
		2: {"debian", "foo", "1.2-3+b1", "foo", "1.2-3", "foo", "1.2-3", false},
		// Debian signed.
		3: {"debian", "linux-image-6.1.0-26-amd64", "6.1.112-1", "linux-signed-amd64", "6.1.112+1", "linux", "6.1.112-1", true},
		4: {"debian", "linux-image-6.1.0-26-arm64", "6.1.112-1", "linux-signed-arm64", "6.1.112+1", "linux", "6.1.112-1", true},
		5: {"debian", "linux-image-6.12.113+deb12-amd64", "6.12.113-1~deb12u1", "linux-signed-6.12-amd64", "6.12.113+1~deb12u1", "linux-6.12", "6.12.113-1~deb12u1", true},
		// Debian unsigned: already correct.
		6: {"debian", "linux-image-6.1.0-54-amd64-unsigned", "6.1.190-1", "linux", "", "linux", "6.1.190-1", true},
		// Debian metapackages keep the literal signed source and its version.
		7: {"debian", "linux-image-amd64", "6.1.190-1", "linux-signed-amd64", "6.1.190+1", "linux-signed-amd64", "6.1.190+1", false},
		8: {"debian", "linux-image-6.12-amd64", "6.12.113-1~deb12u1", "linux-signed-6.12-amd64", "6.12.113+1~deb12u1", "linux-signed-6.12-amd64", "6.12.113+1~deb12u1", false},
		// Ubuntu signed: bare Source as in the archive, and parenthesised.
		9:  {"ubuntu", "linux-image-6.8.0-45-generic", "6.8.0-45.45", "linux-signed", "", "linux", "6.8.0-45.45", true},
		10: {"ubuntu", "linux-image-6.8.0-45-generic", "6.8.0-45.45", "linux-signed", "6.8.0-45.45", "linux", "6.8.0-45.45", true},
		11: {"ubuntu", "linux-image-6.8.0-45-generic", "6.8.0-45.45~22.04.1", "linux-signed-hwe-6.8", "", "linux-hwe-6.8", "6.8.0-45.45~22.04.1", true},
		12: {"ubuntu", "linux-image-6.8.0-1016-aws", "6.8.0-1016.17", "linux-signed-aws", "", "linux-aws", "6.8.0-1016.17", true},
		13: {"ubuntu", "linux-image-6.8.0-1012-aws", "6.8.0-1012.13~22.04.1", "linux-signed-aws-6.8", "", "linux-aws-6.8", "6.8.0-1012.13~22.04.1", true},
		14: {"ubuntu", "linux-image-unsigned-6.8.0-45-generic", "6.8.0-45.45", "linux", "", "linux", "6.8.0-45.45", true},
		// Ubuntu metapackages keep linux-meta*.
		15: {"ubuntu", "linux-image-generic", "6.8.0.45.45", "linux-meta", "", "linux-meta", "6.8.0.45.45", false},
		// A package merely named like the prefix is left alone.
		16: {"debian", "linux-image-6.1.0-1-amd64", "6.1.1-1", "linux-signedish", "", "linux-signedish", "6.1.1-1", true},
	} {
		got := newPackage(tc.distro, tc.pkg, tc.version, "amd64", tc.srcName, tc.srcVersion)
		if got.SourceName != tc.wantName || got.SourceVersion != tc.wantVersion || got.IsKernelImage != tc.wantImage {
			t.Errorf("case %d %s: got source %s %s image=%v, want %s %s image=%v",
				name, tc.pkg, got.SourceName, got.SourceVersion, got.IsKernelImage, tc.wantName, tc.wantVersion, tc.wantImage)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0-1", "1.0-01", 0},
		{"0:1.0", "1.0", 0},
		{"1.0", "1.0-0", 0},
		{"1.0", "2.0", -1},
		{"1:0.1", "9.9", 1},
		{"1.9", "1.10", -1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~~", "1.0~", -1},
		{"1.0", "1.0a", -1},
		{"1.0a", "1.0+", -1},
		{"1.2-3", "1.2-3+b1", -1},
		{"1.2-3", "1.2-10", -1},
		{"1.0-1", "1", 1},
		{"1", "1.", -1},
		{"99999999999999999999999.1", "99999999999999999999999.2", -1},
		// Kernels.
		{"6.1.112-1", "6.1.119-1", -1},
		{"6.12.94-1", "6.12.107-1", -1},
		{"6.8.0-45.45", "6.8.0-100.100", -1},
		{"6.8.0-45.45~22.04.1", "6.8.0-45.45", -1},
		{"5.15.0-122.132", "6.8.0-45.45~22.04.1", -1},
		{"6.12.100-1~deb12u1", "6.12.100-1", -1},
	} {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := compareVersions(tc.b, tc.a); got != -tc.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tc.b, tc.a, got, -tc.want)
		}
	}
}

func TestKernelStateRebootOnlyWithinSourceLine(t *testing.T) {
	image := func(name, source, version string) Package {
		return Package{Name: name, Version: version, SourceName: source, SourceVersion: version, IsKernelImage: true}
	}
	generic := image("linux-image-6.8.0-100-generic", "linux", "6.8.0-100.100")
	aws := image("linux-image-6.8.0-1016-aws", "linux-aws", "6.8.0-1016.17")
	newer := image("linux-image-6.8.0-101-generic", "linux", "6.8.0-101.101")

	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	if k := kernelState(root, []Package{generic, aws}, "6.8.0-100-generic"); k.RebootRequired {
		t.Error("another flavour's higher version must not require a reboot")
	}
	if k := kernelState(root, []Package{generic, aws, newer}, "6.8.0-100-generic"); !k.RebootRequired {
		t.Error("a newer image of the running flavour must require a reboot")
	}
}
