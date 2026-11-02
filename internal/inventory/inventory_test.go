package inventory

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeRoot creates a fake root from path -> content.
func writeRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, data := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func fakeLive(release string) *liveHost {
	return &liveHost{
		uname:    func() (string, error) { return release, nil },
		hostname: func() (string, error) { return "live-host", nil },
	}
}

const (
	debian12Release = "ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n"
	oneInstalled    = "Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.2.15-2+b13\nSource: bash (5.2.15-2)\n"
)

// signedImage returns an installed stanza for a Debian signed kernel image.
func signedImage(release, version string) string {
	return "Package: linux-image-" + release + "\nStatus: install ok installed\nArchitecture: amd64\nVersion: " + version + "\nSource: linux-signed-amd64 (" + strings.Replace(version, "-", "+", 1) + ")\n\n"
}

func TestCollectFixtures(t *testing.T) {
	for _, tc := range []struct {
		root string
		want Host
	}{
		{
			root: "debian12",
			want: Host{
				Hostname: "deb12-host",
				Release:  Release{Distro: "debian", Version: "12", Codename: "bookworm", Ecosystem: "Debian:12", Root: "Debian"},
				Kernel:   Kernel{SourceName: "linux", Version: "6.1.119-1"},
				Packages: []Package{
					// No Source field: source is the binary itself.
					{"base-files", "12.4+deb12u15", "amd64", "base-files", "12.4+deb12u15", false},
					// binNMU: source version has no +b13.
					{"bash", "5.2.15-2+b13", "amd64", "bash", "5.2.15-2", false},
					// Binary carries an epoch its source does not.
					{"bsdutils", "1:2.38.1-5+deb12u3", "amd64", "util-linux", "2.38.1-5+deb12u3", false},
					// Multi-arch pair, Source without a version.
					{"libc6", "2.36-9+deb12u14", "amd64", "glibc", "2.36-9+deb12u14", false},
					{"libc6", "2.36-9+deb12u14", "i386", "glibc", "2.36-9+deb12u14", false},
					{"linux-headers-6.1.0-28-amd64", "6.1.119-1", "amd64", "linux", "6.1.119-1", false},
					{"linux-image-6.1.0-26-amd64", "6.1.112-1", "amd64", "linux", "6.1.112-1", true},
					{"linux-image-6.1.0-28-amd64", "6.1.119-1", "amd64", "linux", "6.1.119-1", true},
					// Metapackage: literal source, not linux.
					{"linux-image-amd64", "6.1.119-1", "amd64", "linux-signed-amd64", "6.1.119+1", false},
					{"sudo", "1.9.13p3-1+deb12u4", "amd64", "sudo", "1.9.13p3-1+deb12u4", false},
					{"tzdata", "2026b-0+deb12u1", "all", "tzdata", "2026b-0+deb12u1", false},
				},
			},
		},
		{
			root: "debian13",
			want: Host{
				Hostname: "deb13-host",
				Release:  Release{Distro: "debian", Version: "13", Codename: "trixie", Ecosystem: "Debian:13", Root: "Debian"},
				Kernel:   Kernel{SourceName: "linux", Version: "6.12.107-1"},
				Packages: []Package{
					{"bash", "5.2.37-2+b10", "amd64", "bash", "5.2.37-2", false},
					{"libc6", "2.41-12+deb13u4", "amd64", "glibc", "2.41-12+deb13u4", false},
					{"libcurl4t64", "8.14.1-2+deb13u5", "amd64", "curl", "8.14.1-2+deb13u5", false},
					{"linux-image-6.12.107+deb13-amd64", "6.12.107-1", "amd64", "linux", "6.12.107-1", true},
					{"linux-image-6.12.107+deb13-amd64-dbg", "6.12.107-1", "amd64", "linux", "6.12.107-1", false},
					{"linux-image-6.12.94+deb13-amd64", "6.12.94-1", "amd64", "linux", "6.12.94-1", true},
					{"linux-image-amd64", "6.12.107-1", "amd64", "linux-signed-amd64", "6.12.107+1", false},
					// binNMU where the source also has an epoch.
					{"zlib1g", "1:1.3.dfsg+really1.3.1-1+b1", "amd64", "zlib", "1:1.3.dfsg+really1.3.1-1", false},
				},
			},
		},
		{
			root: "ubuntu2204",
			want: Host{
				Hostname: "u22-host",
				Release:  Release{Distro: "ubuntu", Version: "22.04", Codename: "jammy", Ecosystem: "Ubuntu:22.04:LTS", Root: "Ubuntu"},
				Kernel:   Kernel{SourceName: "linux-hwe-6.8", Version: "6.8.0-45.45~22.04.1"},
				Packages: []Package{
					{"bash", "5.1-6ubuntu1.1", "amd64", "bash", "5.1-6ubuntu1.1", false},
					{"comerr-dev", "2.1-1.46.5-2ubuntu1.2", "amd64", "e2fsprogs", "1.46.5-2ubuntu1.2", false},
					{"libc6", "2.35-0ubuntu3.15", "amd64", "glibc", "2.35-0ubuntu3.15", false},
					{"linux-image-5.15.0-122-generic", "5.15.0-122.132", "amd64", "linux", "5.15.0-122.132", true},
					{"linux-image-6.8.0-45-generic", "6.8.0-45.45~22.04.1", "amd64", "linux-hwe-6.8", "6.8.0-45.45~22.04.1", true},
					{"linux-image-generic", "5.15.0.122.122", "amd64", "linux-meta", "5.15.0.122.122", false},
					{"linux-image-generic-hwe-22.04", "6.8.0-45.45~22.04.1", "amd64", "linux-meta-hwe-6.8", "6.8.0-45.45~22.04.1", false},
					{"linux-modules-5.15.0-122-generic", "5.15.0-122.132", "amd64", "linux", "5.15.0-122.132", false},
					{"openssl", "3.0.2-0ubuntu1.30", "amd64", "openssl", "3.0.2-0ubuntu1.30", false},
					{"zlib1g", "1:1.2.11.dfsg-2ubuntu9.2", "amd64", "zlib", "1:1.2.11.dfsg-2ubuntu9.2", false},
				},
			},
		},
		{
			root: "ubuntu2404",
			want: Host{
				Hostname: "u24-host",
				Release:  Release{Distro: "ubuntu", Version: "24.04", Codename: "noble", Ecosystem: "Ubuntu:24.04:LTS", Root: "Ubuntu"},
				Kernel: Kernel{
					SourceName: "linux", Version: "6.8.0-100.100",
					RebootRequired: true, RebootPackages: []string{"linux-image-6.8.0-100-generic", "linux-base"},
				},
				Packages: []Package{
					{"bsdutils", "1:2.39.3-9ubuntu6.6", "amd64", "util-linux", "2.39.3-9ubuntu6.6", false},
					{"libc6", "2.39-0ubuntu8.9", "amd64", "glibc", "2.39-0ubuntu8.9", false},
					{"libssl3t64", "3.0.13-0ubuntu3.16", "amd64", "openssl", "3.0.13-0ubuntu3.16", false},
					{"linux-image-6.8.0-100-generic", "6.8.0-100.100", "amd64", "linux", "6.8.0-100.100", true},
					{"linux-image-6.8.0-45-generic", "6.8.0-45.45", "amd64", "linux", "6.8.0-45.45", true},
					{"linux-image-generic", "6.8.0-147.147", "amd64", "linux-meta", "6.8.0-147.147", false},
					{"tzdata", "2026e-0ubuntu0.24.04.1", "all", "tzdata", "2026e-0ubuntu0.24.04.1", false},
				},
			},
		},
	} {
		t.Run(tc.root, func(t *testing.T) {
			got, err := Collect(context.Background(), filepath.Join("testdata", tc.root))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Packages, tc.want.Packages) {
				t.Errorf("packages:\n got %+v\nwant %+v", got.Packages, tc.want.Packages)
			}
			got.Packages, tc.want.Packages = nil, nil
			if !reflect.DeepEqual(*got, tc.want) {
				t.Errorf("host:\n got %+v\nwant %+v", *got, tc.want)
			}
		})
	}
}

func TestRunningKernel(t *testing.T) {
	for name, tc := range map[string]struct {
		root, release string
		want          Kernel
	}{
		"debian running older": {
			root: "debian12", release: "6.1.0-26-amd64",
			want: Kernel{Release: "6.1.0-26-amd64", SourceName: "linux", Version: "6.1.112-1", RebootRequired: true},
		},
		"debian running newest": {
			root: "debian12", release: "6.1.0-28-amd64",
			want: Kernel{Release: "6.1.0-28-amd64", SourceName: "linux", Version: "6.1.119-1"},
		},
		"debian 13 numeric order, not lexical": {
			root: "debian13", release: "6.12.94+deb13-amd64",
			want: Kernel{Release: "6.12.94+deb13-amd64", SourceName: "linux", Version: "6.12.94-1", RebootRequired: true},
		},
		"ubuntu GA behind HWE": {
			root: "ubuntu2204", release: "5.15.0-122-generic",
			want: Kernel{Release: "5.15.0-122-generic", SourceName: "linux", Version: "5.15.0-122.132", RebootRequired: true},
		},
		"ubuntu HWE running": {
			root: "ubuntu2204", release: "6.8.0-45-generic",
			want: Kernel{Release: "6.8.0-45-generic", SourceName: "linux-hwe-6.8", Version: "6.8.0-45.45~22.04.1"},
		},
		"marker with newest running": {
			root: "ubuntu2404", release: "6.8.0-100-generic",
			want: Kernel{
				Release: "6.8.0-100-generic", SourceName: "linux", Version: "6.8.0-100.100",
				RebootRequired: true, RebootPackages: []string{"linux-image-6.8.0-100-generic", "linux-base"},
			},
		},
		"no package for running kernel falls back to newest": {
			root: "debian12", release: "6.9.0-custom",
			want: Kernel{Release: "6.9.0-custom", SourceName: "linux", Version: "6.1.119-1"},
		},
		"running release is a removed package": {
			root: "debian12", release: "6.1.0-20-amd64",
			want: Kernel{Release: "6.1.0-20-amd64", SourceName: "linux", Version: "6.1.119-1"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := collect(context.Background(), filepath.Join("testdata", tc.root), fakeLive(tc.release))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Kernel, tc.want) {
				t.Errorf("kernel:\n got %+v\nwant %+v", got.Kernel, tc.want)
			}
			if got.Hostname != "live-host" {
				t.Errorf("hostname = %q, want the live one", got.Hostname)
			}
		})
	}
}

func TestContainerHasNoKernel(t *testing.T) {
	root := writeRoot(t, map[string]string{"etc/os-release": debian12Release, statusFile: oneInstalled})
	got, err := collect(context.Background(), root, fakeLive("6.8.0-45-generic"))
	if err != nil {
		t.Fatal(err)
	}
	if want := (Kernel{Release: "6.8.0-45-generic"}); !reflect.DeepEqual(got.Kernel, want) {
		t.Fatalf("kernel = %+v, want %+v", got.Kernel, want)
	}
}

func TestRebootMarkerUnderRun(t *testing.T) {
	root := writeRoot(t, map[string]string{
		"etc/os-release":           debian12Release,
		statusFile:                 oneInstalled,
		"run/reboot-required":      "",
		"run/reboot-required.pkgs": "libc6\n",
	})
	got, err := Collect(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Kernel.RebootRequired || !reflect.DeepEqual(got.Kernel.RebootPackages, []string{"libc6"}) {
		t.Fatalf("kernel = %+v", got.Kernel)
	}
}

// A real offline root has var/run -> /run, which must not resolve to the
// scanning machine's own /run. Relative links stay inside and are followed.
func TestSymlinksStayInsideRoot(t *testing.T) {
	outside := writeRoot(t, map[string]string{"reboot-required": "", "os-release": "ID=evil\nVERSION_ID=1\n"})
	root := writeRoot(t, map[string]string{"usr/lib/os-release": debian12Release, statusFile: oneInstalled})
	for link, target := range map[string]string{
		"var/run":        outside,
		"etc/os-release": filepath.Join(outside, "os-release"),
	} {
		path := filepath.Join(root, link)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Collect(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Release.Ecosystem != "Debian:12" || got.Kernel.RebootRequired {
		t.Fatalf("read through an escaping symlink: %+v", got)
	}

	if err := os.Remove(filepath.Join(root, "etc/os-release")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../usr/lib/os-release", filepath.Join(root, "etc/os-release")); err != nil {
		t.Fatal(err)
	}
	if got, err = Collect(context.Background(), root); err != nil || got.Release.Codename != "bookworm" {
		t.Fatalf("relative link not followed: %+v, %v", got, err)
	}
}

func TestUnsupportedRelease(t *testing.T) {
	for name, tc := range map[string]struct {
		osRelease string
		wantInMsg string
	}{
		"debian 11":        {"ID=debian\nVERSION_ID=\"11\"\n", "debian 11"},
		"debian testing":   {"ID=debian\nPRETTY_NAME=\"Debian GNU/Linux forky/sid\"\n", "found debian;"},
		"ubuntu interim":   {"ID=ubuntu\nVERSION_ID=\"23.10\"\n", "ubuntu 23.10"},
		"ubuntu 20.04":     {"ID=ubuntu\nVERSION_ID=\"20.04\"\n", "ubuntu 20.04"},
		"derivative":       {"ID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_ID=\"22.04\"\n", "linuxmint 22.04"},
		"other family":     {"ID=fedora\nVERSION_ID=41\n", "fedora 41"},
		"empty os-release": {"", "vmmon supports"},
	} {
		t.Run(name, func(t *testing.T) {
			root := writeRoot(t, map[string]string{"etc/os-release": tc.osRelease, statusFile: oneInstalled})
			_, err := Collect(context.Background(), root)
			if !errors.Is(err, ErrUnsupportedRelease) {
				t.Fatalf("err = %v, want ErrUnsupportedRelease", err)
			}
			for _, want := range []string{tc.wantInMsg, "Debian 12, 13", "Ubuntu 22.04, 24.04"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("message %q does not contain %q", err, want)
				}
			}
		})
	}

	t.Run("no os-release", func(t *testing.T) {
		_, err := Collect(context.Background(), writeRoot(t, map[string]string{statusFile: oneInstalled}))
		var typed *UnsupportedReleaseError
		if !errors.Is(err, ErrUnsupportedRelease) || !errors.As(err, &typed) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("typed fields", func(t *testing.T) {
		_, err := Collect(context.Background(), writeRoot(t, map[string]string{"etc/os-release": "ID=fedora\nVERSION_ID='41'\n"}))
		var typed *UnsupportedReleaseError
		if !errors.As(err, &typed) || typed.Distro != "fedora" || typed.Version != "41" {
			t.Fatalf("err = %#v", err)
		}
	})
}

func TestBadDpkgDatabaseIsAnError(t *testing.T) {
	for name, status := range map[string]*string{
		"missing":        nil,
		"empty":          ptr(""),
		"none installed": ptr("Package: bash\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 5.2\n"),
		"bad status":     ptr("Package: bash\nStatus: installed\nVersion: 5.2\n"),
		"bad source":     ptr("Package: a\nStatus: install ok installed\nVersion: 1\nSource: b (1\n"),
	} {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{"etc/os-release": debian12Release}
			if status != nil {
				files[statusFile] = *status
			}
			if got, err := Collect(context.Background(), writeRoot(t, files)); err == nil {
				t.Fatalf("no error, got %+v", got)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

func TestCollectMissingRoot(t *testing.T) {
	if _, err := Collect(context.Background(), filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestCollectHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Collect(ctx, filepath.Join("testdata", "debian12")); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestStatusPath(t *testing.T) {
	for root, want := range map[string]string{
		"":          "/var/lib/dpkg/status",
		"/":         "/var/lib/dpkg/status",
		"/mnt/host": "/mnt/host/var/lib/dpkg/status",
	} {
		if got := StatusPath(root); got != want {
			t.Errorf("StatusPath(%q) = %q, want %q", root, got, want)
		}
	}
}

func TestOfflineHostnameMissing(t *testing.T) {
	root := writeRoot(t, map[string]string{"etc/os-release": debian12Release, statusFile: oneInstalled})
	got, err := Collect(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hostname != "" || got.Kernel.Release != "" {
		t.Fatalf("offline host = %+v", got)
	}
}

func TestSeveralImagesOfflineNewestWins(t *testing.T) {
	root := writeRoot(t, map[string]string{
		"etc/os-release": debian12Release,
		statusFile:       signedImage("6.1.0-9-amd64", "6.1.27-1") + signedImage("6.1.0-10-amd64", "6.1.38-1") + signedImage("6.1.0-8-amd64", "6.1.25-1"),
	})
	got, err := Collect(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kernel.Version != "6.1.38-1" {
		t.Fatalf("kernel = %+v", got.Kernel)
	}
}

// Scalibr logs through slog, never its default logger, and never to stdout.
func TestScalibrLogsGoToSlog(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)

	root := writeRoot(t, map[string]string{
		"etc/os-release": debian12Release,
		statusFile:       "Package: nostatus\nVersion: 1\n\n" + oneInstalled,
	})
	if _, err := Collect(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "component=scalibr") || !strings.Contains(buf.String(), "nostatus") {
		t.Fatalf("log output: %q", buf.String())
	}
}
