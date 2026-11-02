// Package integration builds the fixture databases for the CI job that runs the
// release binary inside real distro containers. Its directory is under testdata,
// so `go test ./...` skips it; run it by path with VMMON_IT_STATE set.
package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vitalii-ye/vmmon/internal/scan/scantest"
)

// Fixed versions far above and below anything a distro image ships, so results
// do not change when images are rebuilt. These packages are in every image.
const (
	alwaysFixedLater = "999:1-1"
	alreadyFixed     = "0~~"
)

// TestBuildFixtures writes $VMMON_IT_STATE/<ecosystem, with : as _>/db for each
// supported release. check.sh holds the findings these records must produce.
func TestBuildFixtures(t *testing.T) {
	out := os.Getenv("VMMON_IT_STATE")
	if out == "" {
		t.Skip("VMMON_IT_STATE is not set")
	}
	for _, ecosystem := range []string{"Debian:12", "Debian:13", "Ubuntu:22.04:LTS", "Ubuntu:24.04:LTS"} {
		root, _, _ := strings.Cut(ecosystem, ":")
		records := map[string][]byte{
			// Affected, with a fix. Binary and source names are the same.
			"bash.json": scantest.Record("CVE-2099-0001", ecosystem, "bash", alwaysFixedLater),
			// Affected, with no fix yet, and listed in KEV below.
			"coreutils.json": scantest.Record("CVE-2099-0002", ecosystem, "coreutils", ""),
			// Matches only if libc6 was mapped to its source package, glibc.
			"glibc.json": scantest.Record("CVE-2099-0003", ecosystem, "glibc", alwaysFixedLater),
			// Installed, but already past the fix.
			"dash.json": scantest.Record("CVE-2099-0004", ecosystem, "dash", alreadyFixed),
			// Not installed.
			"absent.json": scantest.Record("CVE-2099-0005", ecosystem, "vmmon-not-installed", ""),
		}
		feeds := scantest.Feeds{
			KEV:  []byte(`{"catalogVersion":"1","vulnerabilities":[{"cveID":"CVE-2099-0002","dateAdded":"2099-01-01"}]}`),
			EPSS: []byte("cve,epss,percentile\nCVE-2099-0001,0.5,0.9\n"),
		}
		dbDir := filepath.Join(out, strings.ReplaceAll(ecosystem, ":", "_"), "db")
		scantest.BuildDB(t, dbDir, ecosystem, root, records, feeds, time.Now())
	}
}
