// Package enrich maintains CISA KEV and FIRST EPSS data.
package enrich

import "time"

// Info is what the feeds know about one CVE.
type Info struct {
	KEV            bool
	KEVDateAdded   time.Time
	EPSS           float64
	EPSSPercentile float64
}

// Lookup answers enrichment queries. An unknown CVE gives the zero Info.
type Lookup interface {
	Lookup(cve string) (Info, error)
}
