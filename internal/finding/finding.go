// Package finding defines the finding model shared by matching, state, policy
// and notifications.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// FixStatus says whether the distro has published a fix.
type FixStatus string

// Fix statuses.
const (
	FixAvailable FixStatus = "fix-available"
	NoFixYet     FixStatus = "no-fix-yet"
)

// Finding is one vulnerability affecting one source package on this host.
type Finding struct {
	// ID is stable across rescans and DB updates. See NewID.
	ID        string `json:"id"`
	Ecosystem string `json:"ecosystem"`
	// SourcePackage is the name OSV keys records by, after kernel normalisation.
	SourcePackage string `json:"source_package"`
	// InstalledVersion is the source version that matched. For the kernel it
	// is the running kernel's version.
	InstalledVersion string `json:"installed_version"`
	// BinaryPackages are the installed packages built from this source.
	BinaryPackages []string `json:"binary_packages"`
	// VulnID is the CVE, or the OSV record ID when the record names no CVE.
	VulnID string `json:"vuln_id"`
	// AdvisoryIDs are the OSV records merged into this finding (DSA, USN, …).
	AdvisoryIDs []string `json:"advisory_ids"`
	Summary     string   `json:"summary,omitempty"`

	FixStatus    FixStatus `json:"fix_status"`
	FixedVersion string    `json:"fixed_version,omitempty"`

	CVSSScore  float64 `json:"cvss_score,omitempty"`
	CVSSVector string  `json:"cvss_vector,omitempty"`
	// SeverityLabel is the distro's own rating when it gives one (Ubuntu
	// priority, Debian urgency), lower-cased.
	SeverityLabel string `json:"severity_label,omitempty"`

	KEV            bool       `json:"kev"`
	KEVDateAdded   *time.Time `json:"kev_date_added,omitempty"`
	EPSS           float64    `json:"epss,omitempty"`
	EPSSPercentile float64    `json:"epss_percentile,omitempty"`

	// Kernel marks a finding against the running kernel.
	Kernel bool `json:"kernel,omitempty"`
	// RebootRequired means the fixed kernel is installed but not running.
	RebootRequired bool `json:"reboot_required,omitempty"`
}

// NewID computes the stable finding ID: sha256(ecosystem|source package|vuln).
func NewID(ecosystem, sourcePackage, vulnID string) string {
	sum := sha256.Sum256([]byte(ecosystem + "|" + sourcePackage + "|" + vulnID))
	return hex.EncodeToString(sum[:])
}

// Counts summarises a set of findings.
type Counts struct {
	Total        int `json:"total"`
	KEV          int `json:"kev"`
	FixAvailable int `json:"fix_available"`
	NoFixYet     int `json:"no_fix_yet"`
}

// Count tallies findings.
func Count(fs []Finding) Counts {
	var c Counts
	for i := range fs {
		c.Total++
		if fs[i].KEV {
			c.KEV++
		}
		if fs[i].FixStatus == FixAvailable {
			c.FixAvailable++
		} else {
			c.NoFixYet++
		}
	}
	return c
}

// Report is the result of one scan and the schema of `vmmon scan --json`.
type Report struct {
	Hostname  string    `json:"hostname"`
	Ecosystem string    `json:"ecosystem"`
	ScannedAt time.Time `json:"scanned_at"`
	// DBSyncedAt is when the vulnerability DB last synced; zero if it never did.
	DBSyncedAt     time.Time `json:"db_synced_at"`
	DBAgeSeconds   int64     `json:"db_age_seconds"`
	RunningKernel  string    `json:"running_kernel,omitempty"`
	RebootRequired bool      `json:"reboot_required"`
	PackagesCount  int       `json:"packages_count"`
	// Partial means only some source packages were matched, so a finding absent
	// here is not necessarily gone.
	Partial bool `json:"partial,omitempty"`
	// Warnings says what the scan could not vouch for: a kernel whose source has no
	// records, a stale database.
	Warnings []string  `json:"warnings,omitempty"`
	Counts   Counts    `json:"counts"`
	Findings []Finding `json:"findings"`
}
