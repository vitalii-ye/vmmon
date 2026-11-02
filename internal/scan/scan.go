// Package scan is the pipeline shared by `vmmon scan` and the daemon: inventory,
// local vulnerability DB, match, enrichment, report. It works entirely from local
// files and never touches the network.
package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/vitalii-ye/vmmon/internal/config"
	"github.com/vitalii-ye/vmmon/internal/enrich"
	"github.com/vitalii-ye/vmmon/internal/finding"
	"github.com/vitalii-ye/vmmon/internal/inventory"
	"github.com/vitalii-ye/vmmon/internal/match"
	"github.com/vitalii-ye/vmmon/internal/vulndb"
)

// Options configures one Run. The zero value is a full scan of the running host.
type Options struct {
	// Root is the filesystem to inventory; "" means the running host.
	Root string
	// Host is an inventory collected earlier. When set, Root is not used.
	Host *inventory.Host
	// Only limits matching to these source packages, such as
	// vulndb.SyncResult.ChangedPackages after a sync. Names that are not installed
	// are skipped, and an empty non-nil map matches nothing. The report is marked
	// Partial: a finding it lacks is not resolved unless its package is in Only.
	Only map[string]bool
	// Now defaults to time.Now.
	Now func() time.Time
}

// Run scans the host and returns the report. Having findings is not an error.
//
// A missing index gives an error matching vulndb.ErrNoDB, and a state directory
// the process may not read one matching fs.ErrPermission. Report.Warnings says
// what the scan could not vouch for, such as a stale DB or an unchecked kernel.
func Run(ctx context.Context, cfg *config.Config, opts Options) (*finding.Report, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	host := opts.Host
	if host == nil {
		var err error
		if host, err = inventory.Collect(ctx, opts.Root); err != nil {
			return nil, err
		}
	}
	store, err := vulndb.Open(cfg, host.Release)
	if err != nil {
		return nil, err
	}
	meta, err := vulndb.ReadMeta(cfg.DBDir())
	if err != nil {
		return nil, err
	}

	var res match.Result
	matchOpts := match.Options{Only: opts.Only, Ignore: cfg.Policy.Ignore}
	err = store.View(ctx, func(db vulndb.Reader) error {
		return enrich.Open(cfg).View(ctx, func(lookup enrich.Lookup) error {
			var err error
			res, err = match.Match(ctx, host, db, lookup, matchOpts)
			return err
		})
	})
	if err != nil {
		return nil, err
	}

	scanned := now().UTC()
	report := &finding.Report{
		Hostname:       host.Hostname,
		Ecosystem:      host.Release.Ecosystem,
		ScannedAt:      scanned,
		RunningKernel:  host.Kernel.Release,
		RebootRequired: host.Kernel.RebootRequired,
		PackagesCount:  len(host.Packages),
		Partial:        opts.Only != nil,
		Counts:         finding.Count(res.Findings),
		Findings:       res.Findings,
	}
	if cfg.Hostname != "" {
		report.Hostname = cfg.Hostname
	}
	synced := meta.Ecosystems[host.Release.Ecosystem].LastSync
	if !synced.IsZero() {
		report.DBSyncedAt = synced
		report.DBAgeSeconds = int64(scanned.Sub(synced).Seconds())
	}
	report.Warnings = append(res.Warnings, dbWarnings(cfg, meta, synced, scanned)...)
	return report, nil
}

// dbWarnings reports data too old to trust, and feeds that have never synced: a
// finding cannot be KEV-listed without the catalog, whose absence looks like good
// news otherwise.
func dbWarnings(cfg *config.Config, meta vulndb.Meta, synced, now time.Time) []string {
	var out []string
	switch age := now.Sub(synced); {
	case synced.IsZero():
		out = append(out, "vulnerability database has no recorded sync time: findings may be out of date")
	case age > cfg.DB.StaleAfter:
		out = append(out, fmt.Sprintf("vulnerability database is %s old, over the %s limit: findings may be out of date; run `sudo vmmon db sync`",
			age.Round(time.Minute), cfg.DB.StaleAfter))
	}
	if meta.KEV.LastSync.IsZero() {
		out = append(out, "CISA KEV catalog has never synced: no finding can show as KEV-listed")
	}
	if meta.EPSS.LastSync.IsZero() {
		out = append(out, "EPSS scores have never synced: findings have no EPSS score")
	}
	return out
}
