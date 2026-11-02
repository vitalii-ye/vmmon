package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vitalii-ye/vmmon/internal/config"
	"github.com/vitalii-ye/vmmon/internal/finding"
	"github.com/vitalii-ye/vmmon/internal/inventory"
	"github.com/vitalii-ye/vmmon/internal/scan/scantest"
	"github.com/vitalii-ye/vmmon/internal/vulndb"
)

var update = flag.Bool("update", false, "rewrite the golden files")

var (
	syncedAt = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	scanAt   = syncedAt.Add(3 * time.Hour)
)

func frozen() time.Time { return scanAt }

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.StateDir = t.TempDir()
	return cfg
}

func readFeeds(t *testing.T) scantest.Feeds {
	t.Helper()
	kev, err := os.ReadFile("testdata/kev.json")
	if err != nil {
		t.Fatal(err)
	}
	epss, err := os.ReadFile("testdata/epss.csv")
	if err != nil {
		t.Fatal(err)
	}
	return scantest.Feeds{KEV: kev, EPSS: epss}
}

func TestGolden(t *testing.T) {
	for _, tc := range []struct{ name, ecosystem, root string }{
		{"debian12", "Debian:12", "Debian"},
		{"ubuntu2404", "Ubuntu:24.04:LTS", "Ubuntu"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join("testdata", tc.name)
			cfg := testConfig(t)
			scantest.BuildDB(t, cfg.DBDir(), tc.ecosystem, tc.root, scantest.ReadRecords(t, filepath.Join(dir, "osv")), readFeeds(t), syncedAt)

			report, err := Run(context.Background(), cfg, Options{Root: filepath.Join(dir, "root"), Now: frozen})
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			path := filepath.Join(dir, "expected.json")
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("report differs from %s; rerun with -update and review the diff\n%s", path, firstDiff(got, want))
			}
		})
	}
}

// firstDiff shows the first line at which two outputs differ.
func firstDiff(got, want []byte) string {
	g, w := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
	for i := range min(len(g), len(w)) {
		if g[i] != w[i] {
			return fmt.Sprintf("line %d:\n got: %s\nwant: %s", i+1, g[i], w[i])
		}
	}
	return "one output is a prefix of the other"
}

// debianDB is a state directory holding one bash record, with both feeds.
func debianDB(t *testing.T, records map[string][]byte) *config.Config {
	t.Helper()
	cfg := testConfig(t)
	if records == nil {
		records = map[string][]byte{"a.json": scantest.Record("CVE-2026-1", "Debian:12", "bash", "9.9-1")}
	}
	scantest.BuildDB(t, cfg.DBDir(), "Debian:12", "Debian", records, readFeeds(t), syncedAt)
	return cfg
}

func debianHost(packages ...inventory.Package) *inventory.Host {
	return &inventory.Host{
		Hostname: "from-inventory",
		Release:  inventory.Release{Distro: "debian", Version: "12", Ecosystem: "Debian:12", Root: "Debian"},
		Packages: packages,
	}
}

func pkg(name, version string) inventory.Package {
	return inventory.Package{Name: name, Version: version, SourceName: name, SourceVersion: version}
}

func TestPreCollectedHost(t *testing.T) {
	cfg := debianDB(t, nil)
	report, err := Run(context.Background(), cfg, Options{
		Root: "/nonexistent, as Host wins",
		Host: debianHost(pkg("bash", "5.0-1"), pkg("curl", "7.0-1")),
		Now:  frozen,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Hostname != "from-inventory" || report.Ecosystem != "Debian:12" || report.PackagesCount != 2 || report.Partial {
		t.Errorf("unexpected report: %+v", report)
	}
	if !report.ScannedAt.Equal(scanAt) || !report.DBSyncedAt.Equal(syncedAt) || report.DBAgeSeconds != 3*3600 {
		t.Errorf("times: scanned %v, synced %v, age %d", report.ScannedAt, report.DBSyncedAt, report.DBAgeSeconds)
	}
	if report.Counts != (finding.Counts{Total: 1, FixAvailable: 1}) {
		t.Errorf("Counts = %+v", report.Counts)
	}
	if len(report.Warnings) != 0 {
		t.Errorf("Warnings = %v", report.Warnings)
	}

	cfg.Hostname = "from-config"
	report, err = Run(context.Background(), cfg, Options{Host: debianHost(pkg("bash", "5.0-1")), Now: frozen})
	if err != nil {
		t.Fatal(err)
	}
	if report.Hostname != "from-config" {
		t.Errorf("Hostname = %q", report.Hostname)
	}
}

func TestPartial(t *testing.T) {
	cfg := debianDB(t, map[string][]byte{
		"a.json": scantest.Record("CVE-2026-1", "Debian:12", "bash", ""),
		"b.json": scantest.Record("CVE-2026-2", "Debian:12", "curl", ""),
	})
	host := debianHost(pkg("bash", "5.0-1"), pkg("curl", "7.0-1"))
	report, err := Run(context.Background(), cfg, Options{Host: host, Only: map[string]bool{"curl": true}, Now: frozen})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Partial || len(report.Findings) != 1 || report.Findings[0].VulnID != "CVE-2026-2" || report.Counts.Total != 1 {
		t.Errorf("partial report: %+v", report)
	}

	// Findings from partial and full runs are the same, so they can be merged.
	full, err := Run(context.Background(), cfg, Options{Host: host, Now: frozen})
	if err != nil {
		t.Fatal(err)
	}
	if full.Partial || len(full.Findings) != 2 || !reflect.DeepEqual(full.Findings[1], report.Findings[0]) {
		t.Errorf("full report: %+v", full)
	}

	report, err = Run(context.Background(), cfg, Options{Host: host, Only: map[string]bool{}, Now: frozen})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Partial || report.Findings == nil || len(report.Findings) != 0 {
		t.Errorf("empty Only: %+v", report)
	}
}

func TestIgnoreFromConfig(t *testing.T) {
	cfg := debianDB(t, nil)
	cfg.Policy.Ignore.CVEs = []string{"CVE-2026-1"}
	report, err := Run(context.Background(), cfg, Options{Host: debianHost(pkg("bash", "5.0-1")), Now: frozen})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 0 {
		t.Errorf("Findings = %+v", report.Findings)
	}
}

func TestWarnings(t *testing.T) {
	host := debianHost(pkg("bash", "5.0-1"))
	warnings := func(t *testing.T, cfg *config.Config, h *inventory.Host, now time.Time) []string {
		t.Helper()
		report, err := Run(context.Background(), cfg, Options{Host: h, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		return report.Warnings
	}
	check := func(t *testing.T, got []string, want ...string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("Warnings = %q, want %d", got, len(want))
		}
		for i := range want {
			if !strings.Contains(got[i], want[i]) {
				t.Errorf("warning %q does not mention %q", got[i], want[i])
			}
		}
	}

	t.Run("stale database", func(t *testing.T) {
		cfg := debianDB(t, nil)
		check(t, warnings(t, cfg, host, syncedAt.Add(cfg.DB.StaleAfter)))
		check(t, warnings(t, cfg, host, syncedAt.Add(cfg.DB.StaleAfter+time.Minute)), "database is 48h1m0s old")
		cfg.DB.StaleAfter = time.Hour
		check(t, warnings(t, cfg, host, syncedAt.Add(2*time.Hour)), "database is 2h0m0s old")
	})
	t.Run("kernel source without records", func(t *testing.T) {
		cfg := debianDB(t, nil)
		h := debianHost(inventory.Package{Name: "linux-image-6.12.9-amd64", Version: "6.12.9-1", SourceName: "linux-6.12", SourceVersion: "6.12.9-1", IsKernelImage: true})
		h.Kernel = inventory.Kernel{SourceName: "linux-6.12", Version: "6.12.9-1"}
		check(t, warnings(t, cfg, h, scanAt), "kernel vulnerabilities could not be checked")
	})
	t.Run("no kernel image", func(t *testing.T) {
		check(t, warnings(t, debianDB(t, nil), host, scanAt))
	})
	t.Run("feeds never synced", func(t *testing.T) {
		cfg := testConfig(t)
		scantest.BuildDB(t, cfg.DBDir(), "Debian:12", "Debian", map[string][]byte{"a.json": scantest.Record("CVE-2026-1", "Debian:12", "bash", "")}, scantest.Feeds{}, syncedAt)
		check(t, warnings(t, cfg, host, scanAt), "KEV", "EPSS")
	})
}

func TestRebootRequired(t *testing.T) {
	cfg := debianDB(t, map[string][]byte{
		"a.json": scantest.Record("CVE-2026-1", "Debian:12", "linux", "6.1.115-1"),
	})
	image := func(name, version string) inventory.Package {
		return inventory.Package{Name: name, Version: version, SourceName: "linux", SourceVersion: version, IsKernelImage: true}
	}
	h := debianHost(image("linux-image-6.1.0-26-amd64", "6.1.112-1"), image("linux-image-6.1.0-27-amd64", "6.1.115-1"))
	h.Kernel = inventory.Kernel{Release: "6.1.0-26-amd64", SourceName: "linux", Version: "6.1.112-1", RebootRequired: true}
	report, err := Run(context.Background(), cfg, Options{Host: h, Now: frozen})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || !report.Findings[0].RebootRequired || !report.Findings[0].Kernel {
		t.Fatalf("Findings = %+v", report.Findings)
	}
	if !report.RebootRequired || report.RunningKernel != "6.1.0-26-amd64" {
		t.Errorf("report: %+v", report)
	}
}

func TestMissingDB(t *testing.T) {
	_, err := Run(context.Background(), testConfig(t), Options{Host: debianHost(pkg("bash", "5.0-1"))})
	if !errors.Is(err, vulndb.ErrNoDB) {
		t.Errorf("err = %v, want ErrNoDB", err)
	}
}

// The daemon's state directory is private when it runs with DynamicUser.
func TestPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	cfg := debianDB(t, nil)
	if err := os.Chmod(cfg.StateDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(cfg.StateDir, 0o755) })
	_, err := Run(context.Background(), cfg, Options{Host: debianHost(pkg("bash", "5.0-1"))})
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("err = %v, want ErrPermission", err)
	}
}

func TestUnsupportedRelease(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=arch\n"), 0o644)
	_, err := Run(context.Background(), testConfig(t), Options{Root: root})
	if !errors.Is(err, inventory.ErrUnsupportedRelease) {
		t.Errorf("err = %v", err)
	}
}

// Every URL the configuration knows points at a server that counts hits, so any
// attempt to refresh anything would show. vulndb and enrich build their clients
// from these URLs alone.
func TestOffline(t *testing.T) {
	cfg := debianDB(t, nil)

	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	cfg.DB.OSVBaseURL, cfg.DB.KEVURL, cfg.DB.EPSSURL = srv.URL, srv.URL, srv.URL

	report, err := Run(context.Background(), cfg, Options{Root: "testdata/debian12/root", Now: frozen})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 {
		t.Errorf("Findings = %+v", report.Findings)
	}
	if hits.Load() != 0 {
		t.Errorf("the scan made %d requests", hits.Load())
	}
}

func TestDeterministic(t *testing.T) {
	cfg := testConfig(t)
	scantest.BuildDB(t, cfg.DBDir(), "Debian:12", "Debian", scantest.ReadRecords(t, "testdata/debian12/osv"), readFeeds(t), syncedAt)
	var first []byte
	for i := range 3 {
		report, err := Run(context.Background(), cfg, Options{Root: "testdata/debian12/root", Now: frozen})
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = data
		} else if !bytes.Equal(first, data) {
			t.Fatal("reports differ between runs")
		}
	}
}
