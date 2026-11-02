package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vitalii-ye/vmmon/internal/finding"
	"github.com/vitalii-ye/vmmon/internal/scan/scantest"
)

const fixtureRoot = "../../internal/scan/testdata/debian12/root"

// runScan runs `vmmon scan` against stateDir, with no config file.
func runScan(t *testing.T, stateDir string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	t.Setenv("VMMON_CONFIG", filepath.Join(t.TempDir(), "absent.yaml"))
	t.Setenv("VMMON_STATE_DIR", stateDir)
	var out, errOut bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(append([]string{"scan"}, args...))
	err = cmd.Execute()
	return out.String(), errOut.String(), err
}

func syncedState(t *testing.T, records map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	feeds := scantest.Feeds{
		KEV:  []byte(`{"catalogVersion":"1","vulnerabilities":[{"cveID":"CVE-2026-2","dateAdded":"2026-01-02"}]}`),
		EPSS: []byte("cve,epss,percentile\nCVE-2026-1,0.5,0.9\n"),
	}
	scantest.BuildDB(t, filepath.Join(dir, "db"), "Debian:12", "Debian", records, feeds, time.Now())
	return dir
}

func TestScanJSON(t *testing.T) {
	dir := syncedState(t, map[string][]byte{
		"a.json": scantest.Record("CVE-2026-1", "Debian:12", "bash", "9.9-1"),
		"b.json": scantest.Record("CVE-2026-2", "Debian:12", "curl", ""),
	})
	stdout, _, err := runScan(t, dir, "--json", "--root", fixtureRoot)
	if err != nil {
		t.Fatal(err)
	}
	var report finding.Report
	dec := json.NewDecoder(strings.NewReader(stdout))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&report); err != nil {
		t.Fatalf("stdout is not a report: %v\n%s", err, stdout)
	}
	if dec.More() {
		t.Error("stdout has more than the JSON document")
	}
	if report.Counts != (finding.Counts{Total: 2, KEV: 1, FixAvailable: 1, NoFixYet: 1}) {
		t.Errorf("Counts = %+v", report.Counts)
	}
	if report.Hostname != "golden-debian" || report.DBSyncedAt.IsZero() {
		t.Errorf("report: %+v", report)
	}
}

// A clean host and a vulnerable one both exit 0, which Execute shows as no error.
func TestScanNoFindings(t *testing.T) {
	dir := syncedState(t, map[string][]byte{"a.json": scantest.Record("CVE-2026-1", "Debian:12", "not-installed", "")})
	stdout, _, err := runScan(t, dir, "--root", fixtureRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Database: synced", "0 findings"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, stdout)
		}
	}
	jsonOut, _, err := runScan(t, dir, "--json", "--root", fixtureRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jsonOut, `"findings": []`) {
		t.Errorf("findings should be an empty list, not null:\n%s", jsonOut)
	}
}

func TestScanMissingDB(t *testing.T) {
	_, _, err := runScan(t, t.TempDir(), "--root", fixtureRoot)
	if err == nil || !strings.Contains(err.Error(), "sudo vmmon db sync") {
		t.Errorf("err = %v", err)
	}
}

func TestScanPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	dir := syncedState(t, map[string][]byte{"a.json": scantest.Record("CVE-2026-1", "Debian:12", "bash", "")})
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	_, _, err := runScan(t, dir, "--root", fixtureRoot)
	if err == nil || !strings.Contains(err.Error(), "sudo vmmon scan") {
		t.Errorf("err = %v", err)
	}
}

func TestScanBadRoot(t *testing.T) {
	if _, _, err := runScan(t, t.TempDir(), "--root", filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("scanning a missing root succeeded")
	}
}

func TestPrintReportOrder(t *testing.T) {
	synced := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	fixable := func(pkg, vuln, version, fix string, score float64) finding.Finding {
		return finding.Finding{SourcePackage: pkg, VulnID: vuln, InstalledVersion: version, FixStatus: finding.FixAvailable, FixedVersion: fix, CVSSScore: score}
	}
	fs := []finding.Finding{
		fixable("low", "CVE-1", "1.0", "1.1", 2.0),
		fixable("worst", "CVE-2", "1.0", "1.1", 5.0),
		fixable("worst", "CVE-3", "1.0", "1.10", 9.8),
		fixable("worst", "CVE-4", "1.0", "1.2", 7.0),
		fixable("worst", "CVE-5", "1.0", "1.1", 4.0),
		fixable("worst", "CVE-6", "1.0", "1.1", 3.0),
		{SourcePackage: "unfixed", VulnID: "CVE-7", InstalledVersion: "1.0", FixStatus: finding.NoFixYet, CVSSScore: 10},
		{SourcePackage: "exploited", VulnID: "CVE-8", InstalledVersion: "1.0", FixStatus: finding.FixAvailable, FixedVersion: "1.1", KEV: true, CVSSScore: 1, EPSS: 0.42},
		{SourcePackage: "linux", VulnID: "CVE-9", InstalledVersion: "6.1", FixStatus: finding.FixAvailable, FixedVersion: "6.2", Kernel: true, RebootRequired: true, SeverityLabel: "high"},
	}
	var buf bytes.Buffer
	printReport(&buf, &finding.Report{
		Hostname: "web-01", Ecosystem: "Debian:12", PackagesCount: 12, DBSyncedAt: synced, DBAgeSeconds: 3700,
		RebootRequired: true, Warnings: []string{"kernel vulnerabilities could not be checked"},
		Counts: finding.Count(fs), Findings: fs,
	})
	want := `web-01 (Debian:12): 12 packages
Database: synced 1h1m ago (2026-11-02 12:00:00)
Reboot required.
Warning: kernel vulnerabilities could not be checked

Known exploited (1):
  CVE-8  exploited 1.0 -> 1.1  (1.0, EPSS 0.42)

Fix available (7):
  worst 1.0 -> 1.10  CVE-3 (9.8), CVE-4 (7.0), CVE-2 (5.0), +2 more
  linux 6.1 -> 6.2 (reboot required)  CVE-9 (high)
  low 1.0 -> 1.1  CVE-1 (2.0)

9 findings: 1 known exploited, 8 with a fix, 1 without a fix yet
Those without a fix are listed by ` + "`vmmon scan --json`" + `.
`
	if got := buf.String(); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestDBAgeWithoutSync(t *testing.T) {
	var buf bytes.Buffer
	printReport(&buf, &finding.Report{Ecosystem: "Debian:12", Warnings: []string{"x"}})
	if !strings.Contains(buf.String(), "Database: sync time unknown") {
		t.Errorf("output:\n%s", buf.String())
	}
}
