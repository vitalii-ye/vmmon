package main

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vitalii-ye/vmmon/internal/config"
	"github.com/vitalii-ye/vmmon/internal/finding"
	"github.com/vitalii-ye/vmmon/internal/match"
	"github.com/vitalii-ye/vmmon/internal/scan"
	"github.com/vitalii-ye/vmmon/internal/vulndb"
)

// maxCVEsPerLine bounds a package's line in the human output.
const maxCVEsPerLine = 3

func init() {
	register(func() *cobra.Command {
		var asJSON bool
		var root string
		cmd := &cobra.Command{
			Use:   "scan",
			Short: "Check the host against the local vulnerability database, offline",
			Long:  "Check the host against the local vulnerability database, offline.\nExits 0 with or without findings, and non-zero only when the scan fails.",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				cfg, err := loadConfig(cmd)
				if err != nil {
					return err
				}
				report, err := scan.Run(cmd.Context(), cfg, scan.Options{Root: root})
				if err != nil {
					return scanError(err, cfg)
				}
				if asJSON {
					enc := json.NewEncoder(cmd.OutOrStdout())
					enc.SetIndent("", "  ")
					return enc.Encode(report)
				}
				printReport(cmd.OutOrStdout(), report)
				return nil
			},
		}
		cmd.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
		cmd.Flags().StringVar(&root, "root", "", "scan the filesystem mounted at this path instead of the running host")
		return cmd
	})
}

// scanError turns the failures users can act on into instructions.
func scanError(err error, cfg *config.Config) error {
	switch {
	case errors.Is(err, vulndb.ErrNoDB):
		slog.Debug("no usable database", "error", err)
		return fmt.Errorf("no usable vulnerability database in %s: run `sudo vmmon db sync` first", cfg.DBDir())
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("cannot read the vulnerability database in %s, which the daemon keeps private: try `sudo vmmon scan` (%w)", cfg.DBDir(), err)
	}
	return err
}

// printReport renders a report for humans: what matters first, each package on
// one line. KEV-listed findings come first and individually, as they are the
// ones to act on today.
func printReport(w io.Writer, r *finding.Report) {
	header := r.Ecosystem
	if r.Hostname != "" {
		header = r.Hostname + " (" + r.Ecosystem + ")"
	}
	fmt.Fprintf(w, "%s: %d packages\n", header, r.PackagesCount)
	fmt.Fprintf(w, "Database: %s\n", dbAge(r))
	if r.RebootRequired {
		fmt.Fprintln(w, "Reboot required.")
	}
	for _, warning := range r.Warnings {
		fmt.Fprintln(w, "Warning:", warning)
	}

	var kev, fixable []finding.Finding
	for _, f := range r.Findings {
		switch {
		case f.KEV:
			kev = append(kev, f)
		case f.FixStatus == finding.FixAvailable:
			fixable = append(fixable, f)
		}
	}
	if len(kev) > 0 {
		slices.SortStableFunc(kev, bySeverity)
		fmt.Fprintf(w, "\nKnown exploited (%d):\n", len(kev))
		for i := range kev {
			printKEV(w, &kev[i])
		}
	}
	if len(fixable) > 0 {
		fmt.Fprintf(w, "\nFix available (%d):\n", len(fixable))
		printByPackage(w, fixable)
	}

	c := r.Counts
	fmt.Fprintf(w, "\n%d findings: %d known exploited, %d with a fix, %d without a fix yet\n", c.Total, c.KEV, c.FixAvailable, c.NoFixYet)
	if c.NoFixYet > 0 {
		fmt.Fprintln(w, "Those without a fix are listed by `vmmon scan --json`.")
	}
}

func dbAge(r *finding.Report) string {
	if r.DBSyncedAt.IsZero() {
		return "sync time unknown"
	}
	return fmt.Sprintf("synced %s ago (%s)", humanAge(time.Duration(r.DBAgeSeconds)*time.Second), r.DBSyncedAt.Format(time.DateTime))
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd", int(d.Hours())/24)
}

func printKEV(w io.Writer, f *finding.Finding) {
	fmt.Fprintf(w, "  %s  %s %s%s  %s\n", f.VulnID, f.SourcePackage, f.InstalledVersion, fixSuffix(f.FixedVersion, f.RebootRequired), severityNote(f))
}

// printByPackage prints one line per source package, worst package first: its
// highest fix and its worst few CVEs.
func printByPackage(w io.Writer, fs []finding.Finding) {
	slices.SortStableFunc(fs, bySeverity)
	var order []string
	byPackage := map[string][]*finding.Finding{}
	for i := range fs {
		name := fs[i].SourcePackage
		if byPackage[name] == nil {
			order = append(order, name)
		}
		byPackage[name] = append(byPackage[name], &fs[i])
	}
	for _, name := range order {
		list := byPackage[name]
		// All of a package's lines share one fix when one version is installed, but
		// with several the highest is what clears everything listed.
		fix, reboot := list[0].FixedVersion, false
		for _, f := range list {
			if match.CompareVersions(f.FixedVersion, fix) > 0 {
				fix = f.FixedVersion
			}
			reboot = reboot || f.RebootRequired
		}
		var cves []string
		for _, f := range list[:min(len(list), maxCVEsPerLine)] {
			cves = append(cves, f.VulnID+" "+severityNote(f))
		}
		more := ""
		if extra := len(list) - maxCVEsPerLine; extra > 0 {
			more = fmt.Sprintf(", +%d more", extra)
		}
		fmt.Fprintf(w, "  %s %s%s  %s%s\n", name, list[0].InstalledVersion, fixSuffix(fix, reboot), strings.Join(cves, ", "), more)
	}
}

func fixSuffix(fix string, reboot bool) string {
	switch {
	case fix == "":
		return " (no fix yet)"
	case reboot:
		return " -> " + fix + " (reboot required)"
	}
	return " -> " + fix
}

// severityNote is a finding's rating in a few characters, "?" when unrated.
func severityNote(f *finding.Finding) string {
	var parts []string
	if f.CVSSScore > 0 {
		parts = append(parts, fmt.Sprintf("%.1f", f.CVSSScore))
	}
	if f.SeverityLabel != "" {
		parts = append(parts, f.SeverityLabel)
	}
	if f.EPSS >= 0.01 {
		parts = append(parts, fmt.Sprintf("EPSS %.2f", f.EPSS))
	}
	if len(parts) == 0 {
		return "(?)"
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// bySeverity sorts worst first: by CVSS score, with a label standing in for a
// missing score.
func bySeverity(a, b finding.Finding) int {
	return cmp.Or(
		cmp.Compare(severityValue(&b), severityValue(&a)),
		cmp.Compare(a.SourcePackage, b.SourcePackage),
		cmp.Compare(a.VulnID, b.VulnID),
	)
}

func severityValue(f *finding.Finding) float64 {
	if f.CVSSScore > 0 {
		return f.CVSSScore
	}
	switch f.SeverityLabel {
	case "critical":
		return 9
	case "high":
		return 7
	case "medium":
		return 4
	case "low":
		return 1
	}
	return 0
}
