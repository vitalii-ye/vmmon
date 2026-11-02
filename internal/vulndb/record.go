// Package vulndb maintains the local index of OSV records for this host's
// release.
package vulndb

import "time"

// Record is the subset of the OSV schema vmmon uses. Its Affected entries hold
// only the host's release once indexed.
//
// Debian and Ubuntu records link CVEs through Upstream and Related more often
// than through Aliases. A DSA or USN can list many CVEs. Severity vectors can
// be CVSS_V3 or CVSS_V4, and Ubuntu adds a "Ubuntu" type holding a priority
// word instead of a vector.
type Record struct {
	ID        string     `json:"id"`
	Modified  time.Time  `json:"modified"`
	Withdrawn *time.Time `json:"withdrawn,omitempty"`
	Summary   string     `json:"summary,omitempty"`
	Aliases   []string   `json:"aliases,omitempty"`
	Upstream  []string   `json:"upstream,omitempty"`
	Related   []string   `json:"related,omitempty"`
	Severity  []Severity `json:"severity,omitempty"`
	Affected  []Affected `json:"affected,omitempty"`
}

// Severity is one OSV severity entry.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Affected is one OSV affected entry.
type Affected struct {
	Package           Package           `json:"package"`
	Ranges            []Range           `json:"ranges,omitempty"`
	Versions          []string          `json:"versions,omitempty"`
	EcosystemSpecific EcosystemSpecific `json:"ecosystem_specific,omitzero"`
}

// Package identifies a source package within an ecosystem.
type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// Range is one OSV range. Only type ECOSYSTEM is evaluated.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is one OSV range event; exactly one field is set.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// EcosystemSpecific holds the distro fields vmmon keeps.
type EcosystemSpecific struct {
	// Urgency is Debian's rating, e.g. "not yet assigned", "unimportant".
	Urgency string `json:"urgency,omitempty"`
	// Availability is Ubuntu's, e.g. "No subscription required".
	Availability string `json:"availability,omitempty"`
}

// Reader looks up records for one open view of the index.
type Reader interface {
	// RecordsFor returns the records affecting a source package in the host's
	// release, ordered by ID.
	RecordsFor(sourcePackage string) ([]Record, error)
}

// Meta is the content of meta.json.
type Meta struct {
	Ecosystems map[string]EcosystemMeta `json:"ecosystems"`
	KEV        FeedMeta                 `json:"kev"`
	EPSS       FeedMeta                 `json:"epss"`
}

// EcosystemMeta describes one synced ecosystem.
type EcosystemMeta struct {
	// LastSync is when a sync last succeeded; it drives DB age.
	LastSync time.Time `json:"last_sync"`
	// LastFullSync is when the last full download succeeded.
	LastFullSync time.Time `json:"last_full_sync"`
	// LastAttempt and LastError describe the latest attempt, successful or not.
	LastAttempt time.Time `json:"last_attempt"`
	LastError   string    `json:"last_error,omitempty"`
	// Cursor is the newest modified timestamp seen in modified_id.csv.
	Cursor   time.Time `json:"cursor"`
	Records  int       `json:"records"`
	Packages int       `json:"packages"`
	// SHA256 is the checksum of the last full all.zip.
	SHA256 string `json:"sha256,omitempty"`
}

// FeedMeta describes one enrichment feed.
type FeedMeta struct {
	LastSync    time.Time `json:"last_sync"`
	LastAttempt time.Time `json:"last_attempt"`
	LastError   string    `json:"last_error,omitempty"`
	Records     int       `json:"records"`
}

// SyncResult reports what one sync did.
type SyncResult struct {
	// Mode is "full" or "incremental".
	Mode string
	// RecordsChanged counts records added, updated or removed.
	RecordsChanged int
	// ChangedPackages is the set of source packages whose records changed. It
	// drives the recheck.
	ChangedPackages []string
}
