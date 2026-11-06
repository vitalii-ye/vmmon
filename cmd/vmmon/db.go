package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vitalii-ye/vmmon/internal/config"
	"github.com/vitalii-ye/vmmon/internal/enrich"
	"github.com/vitalii-ye/vmmon/internal/inventory"
	"github.com/vitalii-ye/vmmon/internal/vulndb"
)

func init() {
	register(func() *cobra.Command {
		db := &cobra.Command{Use: "db", Short: "Manage the local vulnerability database"}
		db.AddCommand(newDBSyncCmd(), newDBStatusCmd())
		return db
	})
}

// dbRelease returns the release named by --ecosystem, or else the host's.
func dbRelease(cmd *cobra.Command, ecosystem string) (inventory.Release, error) {
	if ecosystem != "" {
		root, _, _ := strings.Cut(ecosystem, ":")
		return inventory.Release{Ecosystem: ecosystem, Root: root}, nil
	}
	host, err := inventory.Collect(cmd.Context(), "")
	if err != nil {
		return inventory.Release{}, fmt.Errorf("detect release (--ecosystem overrides this): %w", err)
	}
	return host.Release, nil
}

func newDBSyncCmd() *cobra.Command {
	var full bool
	var ecosystem string
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Refresh the vulnerability database and the KEV and EPSS feeds",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			rel, err := dbRelease(cmd, ecosystem)
			if err != nil {
				return err
			}
			store, err := vulndb.Open(cfg, rel)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			res, syncErr := store.Sync(cmd.Context(), vulndb.SyncOptions{Full: full})
			if syncErr == nil {
				printSync(out, rel.Ecosystem, res)
			}
			ch, feedErr := enrich.Open(cfg).Sync(cmd.Context())
			if feedErr == nil {
				_, _ = fmt.Fprintf(out, "KEV: %s; EPSS: %s\n", kevSummary(ch), epssSummary(ch))
			}
			return errors.Join(syncErr, feedErr)
		},
	}
	cmd.Flags().BoolVar(&full, "full", false, "force a full download")
	cmd.Flags().StringVar(&ecosystem, "ecosystem", "", `OSV ecosystem, e.g. "Debian:12" (default: detect from the host)`)
	return cmd
}

func printSync(w io.Writer, ecosystem string, res vulndb.SyncResult) {
	mode := res.Mode
	if res.FullReason != "" {
		mode += " (" + res.FullReason + ")"
	}
	_, _ = fmt.Fprintf(w, "%s: %s sync: %d records changed, %d packages affected; %d records, %d packages total\n",
		ecosystem, mode, res.RecordsChanged, len(res.ChangedPackages), res.Records, res.Packages)
}

func kevSummary(ch enrich.Changes) string {
	switch {
	case len(ch.NewKEV) > 0:
		return fmt.Sprintf("%d newly listed", len(ch.NewKEV))
	case ch.KEVChanged:
		return "changed"
	}
	return "no change"
}

func epssSummary(ch enrich.Changes) string {
	if ch.EPSSUpdated {
		return "updated"
	}
	return "no change"
}

// statusReport is the output of `db status --json`.
type statusReport struct {
	Ecosystems []vulndb.Status `json:"ecosystems"`
	KEV        feedStatus      `json:"kev"`
	EPSS       feedStatus      `json:"epss"`
}

type feedStatus struct {
	Synced      bool      `json:"synced"`
	LastSync    time.Time `json:"last_sync,omitzero"`
	LastAttempt time.Time `json:"last_attempt,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	AgeSeconds  int64     `json:"age_seconds,omitempty"`
	Records     int       `json:"records"`
	Version     string    `json:"version,omitempty"`
}

func newFeedStatus(m vulndb.FeedMeta, now time.Time) feedStatus {
	f := feedStatus{
		Synced:      !m.LastSync.IsZero(),
		LastSync:    m.LastSync,
		LastAttempt: m.LastAttempt,
		LastError:   m.LastError,
		Records:     m.Records,
		Version:     m.Version,
	}
	if f.Synced {
		f.AgeSeconds = int64(now.Sub(m.LastSync).Seconds())
	}
	return f
}

func newDBStatusCmd() *cobra.Command {
	var asJSON bool
	var ecosystem string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show synced ecosystems, record counts and ages",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			report, err := dbStatus(cmd, cfg, ecosystem)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			printStatus(out, report, cfg.DBDir())
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	cmd.Flags().StringVar(&ecosystem, "ecosystem", "", `also report this OSV ecosystem, e.g. "Debian:12" (default: detect from the host)`)
	return cmd
}

// dbStatus covers every ecosystem in meta.json plus the host's, which shows up
// as never synced before the first sync. Failing to detect the host is not an
// error here: status must work anywhere, and at most loses that line.
func dbStatus(cmd *cobra.Command, cfg *config.Config, ecosystem string) (statusReport, error) {
	dir := cfg.DBDir()
	meta, err := vulndb.ReadMeta(dir)
	if err != nil {
		return statusReport{}, err
	}
	now := time.Now()
	names := slices.Collect(maps.Keys(meta.Ecosystems))
	if rel, err := dbRelease(cmd, ecosystem); err == nil && !slices.Contains(names, rel.Ecosystem) {
		names = append(names, rel.Ecosystem)
	}
	slices.Sort(names)

	report := statusReport{
		Ecosystems: []vulndb.Status{},
		KEV:        newFeedStatus(meta.KEV, now),
		EPSS:       newFeedStatus(meta.EPSS, now),
	}
	for _, name := range names {
		root, _, _ := strings.Cut(name, ":")
		store, err := vulndb.Open(cfg, inventory.Release{Ecosystem: name, Root: root})
		if err != nil {
			return statusReport{}, err
		}
		st, err := store.Status()
		if err != nil {
			return statusReport{}, err
		}
		report.Ecosystems = append(report.Ecosystems, st)
	}
	return report, nil
}

func printStatus(w io.Writer, r statusReport, dir string) {
	_, _ = fmt.Fprintln(w, "Database directory:", dir)
	if len(r.Ecosystems) == 0 {
		_, _ = fmt.Fprintln(w, "No ecosystem synced yet: run `vmmon db sync`.")
	}
	for _, st := range r.Ecosystems {
		_, _ = fmt.Fprintf(w, "%s: %d records, %d packages, %.1f MB, synced %s, last full %s\n",
			st.Ecosystem, st.Records, st.Packages, float64(st.Size)/(1<<20), ago(st.LastSync), ago(st.LastFullSync))
		if st.LastError != "" {
			_, _ = fmt.Fprintf(w, "  last error (%s): %s\n", ago(st.LastAttempt), st.LastError)
		}
	}
	printFeed(w, "KEV", r.KEV)
	printFeed(w, "EPSS", r.EPSS)
}

func printFeed(w io.Writer, name string, f feedStatus) {
	_, _ = fmt.Fprintf(w, "%s: %d records", name, f.Records)
	if f.Version != "" {
		_, _ = fmt.Fprintf(w, ", version %s", f.Version)
	}
	_, _ = fmt.Fprintf(w, ", synced %s\n", ago(f.LastSync))
	if f.LastError != "" {
		_, _ = fmt.Fprintf(w, "  last error (%s): %s\n", ago(f.LastAttempt), f.LastError)
	}
}

// ago renders a time for humans; the zero time is "never", not 56 years.
func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t).Round(time.Second)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%dm ago", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd ago", int(d.Hours())/24)
}
