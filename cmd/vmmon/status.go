package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"time"

	"github.com/spf13/cobra"

	"github.com/vitalii-ye/vmmon/internal/config"
	"github.com/vitalii-ye/vmmon/internal/finding"
	"github.com/vitalii-ye/vmmon/internal/notify"
	"github.com/vitalii-ye/vmmon/internal/state"
	"github.com/vitalii-ye/vmmon/internal/vulndb"
)

const (
	// statusTopKEV bounds the KEV list in `vmmon status`.
	statusTopKEV = 10
	// scanOverdue is when a missing scan suggests the daemon is not running: it
	// scans at least daily.
	scanOverdue = 26 * time.Hour
)

func init() {
	register(func() *cobra.Command {
		var asJSON bool
		cmd := &cobra.Command{
			Use:   "status",
			Short: "Show open findings, database age, pending reboot, last scan and channel health",
			Long:  "Show open findings, database age, pending reboot, last scan and channel health.\nWorks while the daemon runs. Under systemd the state directory is private, so it needs sudo.",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				cfg, err := loadConfig(cmd)
				if err != nil {
					return err
				}
				report, err := hostStatus(cfg, time.Now(), state.DefaultReadTimeout)
				if err != nil {
					return err
				}
				if asJSON {
					enc := json.NewEncoder(cmd.OutOrStdout())
					enc.SetIndent("", "  ")
					return enc.Encode(report)
				}
				printHostStatus(cmd.OutOrStdout(), report)
				return nil
			},
		}
		cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON")
		return cmd
	})
}

// hostReport is the output of `vmmon status --json`.
type hostReport struct {
	Hostname       string         `json:"hostname"`
	Ecosystem      string         `json:"ecosystem,omitempty"`
	Packages       int            `json:"packages"`
	Findings       finding.Counts `json:"findings"`
	TopKEV         []kevEntry     `json:"top_kev"`
	RebootRequired bool           `json:"reboot_required"`
	LastScan       time.Time      `json:"last_scan,omitzero"`
	LastFullScan   time.Time      `json:"last_full_scan,omitzero"`
	LastDigest     time.Time      `json:"last_digest,omitzero"`
	Database       databaseHealth `json:"database"`
	KEV            feedStatus     `json:"kev"`
	EPSS           feedStatus     `json:"epss"`
	Channel        channelHealth  `json:"channel"`
	Warnings       []string       `json:"warnings"`
}

type kevEntry struct {
	Vuln         string `json:"vuln_id"`
	Package      string `json:"source_package"`
	Version      string `json:"installed_version"`
	FixedVersion string `json:"fixed_version,omitempty"`
}

type databaseHealth struct {
	Synced      bool      `json:"synced"`
	LastSync    time.Time `json:"last_sync,omitzero"`
	AgeSeconds  int64     `json:"age_seconds,omitempty"`
	LastAttempt time.Time `json:"last_attempt,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
}

type channelHealth struct {
	Name        string    `json:"name"`
	Configured  bool      `json:"configured"`
	Token       string    `json:"token"`
	QueueLength int       `json:"queue_length"`
	LastOK      time.Time `json:"last_ok,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt time.Time `json:"last_error_at,omitzero"`
	// Permanent means retrying cannot help until setup is re-run.
	Permanent bool `json:"permanent,omitempty"`
}

// hostStatus gathers the report from local files. It opens the state read-only
// and for a moment, so it works while the daemon runs, and never needs the token.
func hostStatus(cfg *config.Config, now time.Time, readTimeout time.Duration) (*hostReport, error) {
	r := &hostReport{
		Hostname: notify.Hostname(cfg),
		TopKEV:   []kevEntry{},
		Warnings: []string{},
		Channel: channelHealth{
			Name:       "telegram",
			Configured: cfg.Telegram.Configured(),
			Token:      cfg.Telegram.Redacted(),
		},
	}
	var m state.Meta
	var overview state.Overview
	err := state.New(cfg.StatePath(), readTimeout).View(func(tx *state.Tx) error {
		var err error
		if m, err = tx.Meta(); err != nil {
			return err
		}
		if overview, err = tx.Overview(); err != nil {
			return err
		}
		r.Channel.QueueLength = tx.QueueLen()
		return nil
	})
	noState := errors.Is(err, state.ErrNoState)
	if err != nil && !noState {
		return nil, statusError(err, cfg)
	}
	meta, err := vulndb.ReadMeta(cfg.DBDir())
	if err != nil {
		return nil, statusError(err, cfg)
	}

	r.Ecosystem = m.Ecosystem
	r.Packages = m.Packages
	r.Findings = overview.Counts
	r.RebootRequired = m.RebootRequired
	r.LastScan = m.LastScan
	r.LastFullScan = m.LastFullScan
	r.LastDigest = m.LastDigest
	for i := range overview.KEV[:min(len(overview.KEV), statusTopKEV)] {
		f := &overview.KEV[i]
		r.TopKEV = append(r.TopKEV, kevEntry{f.VulnID, f.SourcePackage, f.InstalledVersion, f.FixedVersion})
	}
	r.Channel.LastOK = m.Channel.LastOK
	r.Channel.LastError = m.Channel.LastError
	r.Channel.LastErrorAt = m.Channel.LastErrorAt
	r.Channel.Permanent = m.Channel.Permanent

	var em vulndb.EcosystemMeta
	if r.Ecosystem == "" && len(meta.Ecosystems) == 1 {
		for eco := range meta.Ecosystems {
			r.Ecosystem = eco
		}
	}
	em = meta.Ecosystems[r.Ecosystem]
	r.Database = databaseHealth{Synced: !em.LastSync.IsZero(), LastSync: em.LastSync, LastAttempt: em.LastAttempt, LastError: em.LastError}
	if r.Database.Synced {
		r.Database.AgeSeconds = int64(now.Sub(em.LastSync).Seconds())
	}
	r.KEV = newFeedStatus(meta.KEV, now)
	r.EPSS = newFeedStatus(meta.EPSS, now)

	r.Warnings = append(r.Warnings, m.Warnings...)
	switch {
	case noState:
		r.Warnings = append(r.Warnings, "the daemon has not recorded anything yet: is it running? Try `systemctl status vmmon`")
	case now.Sub(m.LastScan) > scanOverdue:
		r.Warnings = append(r.Warnings, "no scan in over a day: is the daemon running? Try `systemctl status vmmon`")
	}
	if !r.Channel.Configured {
		r.Warnings = append(r.Warnings, "no notification channel configured here: run `sudo vmmon setup`, or use sudo if it is set up already")
	}
	if r.Channel.LastError != "" {
		hint := "messages stay queued and retry"
		if r.Channel.Permanent {
			hint = "retrying cannot fix this: re-run `sudo vmmon setup`"
		}
		r.Warnings = append(r.Warnings, "last send failed, "+hint)
	}
	if r.Database.Synced && now.Sub(em.LastSync) > cfg.DB.StaleAfter {
		r.Warnings = append(r.Warnings, fmt.Sprintf("vulnerability database last synced %s, over the %s limit", ago(em.LastSync), cfg.DB.StaleAfter))
	}
	return r, nil
}

// statusError turns a private state directory into an instruction.
func statusError(err error, cfg *config.Config) error {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("cannot read %s, which the daemon keeps private: try `sudo vmmon status` (%w)", cfg.StateDir, err)
	}
	return err
}

func printHostStatus(w io.Writer, r *hostReport) {
	header := r.Hostname
	if r.Ecosystem != "" {
		header += " (" + r.Ecosystem + ")"
	}
	fmt.Fprintln(w, header)
	fmt.Fprintf(w, "Open findings: %d (%d known exploited, %d with a fix, %d without a fix yet)\n",
		r.Findings.Total, r.Findings.KEV, r.Findings.FixAvailable, r.Findings.NoFixYet)
	for _, k := range r.TopKEV {
		fmt.Fprintf(w, "  %s  %s %s%s\n", k.Vuln, k.Package, k.Version, fixSuffix(k.FixedVersion, false))
	}
	if more := r.Findings.KEV - len(r.TopKEV); more > 0 {
		fmt.Fprintf(w, "  ...and %d more: `vmmon scan`\n", more)
	}
	if r.RebootRequired {
		fmt.Fprintln(w, "Reboot required.")
	}
	fmt.Fprintf(w, "Last scan: %s (full: %s, %d packages)\n", ago(r.LastScan), ago(r.LastFullScan), r.Packages)
	fmt.Fprintf(w, "Last digest: %s\n", ago(r.LastDigest))
	fmt.Fprintf(w, "Database: synced %s\n", ago(r.Database.LastSync))
	if r.Database.LastError != "" {
		fmt.Fprintf(w, "  last error (%s): %s\n", ago(r.Database.LastAttempt), r.Database.LastError)
	}
	printFeed(w, "KEV", r.KEV)
	printFeed(w, "EPSS", r.EPSS)
	fmt.Fprintf(w, "Channel: %s, token %s, %d queued, last delivery %s\n", r.Channel.Name, r.Channel.Token, r.Channel.QueueLength, ago(r.Channel.LastOK))
	if r.Channel.LastError != "" {
		fmt.Fprintf(w, "  last error (%s): %s\n", ago(r.Channel.LastErrorAt), r.Channel.LastError)
	}
	for _, warning := range r.Warnings {
		fmt.Fprintln(w, "Warning:", warning)
	}
}
