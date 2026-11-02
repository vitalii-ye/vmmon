package notify

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/vitalii-ye/vmmon/internal/finding"
	"github.com/vitalii-ye/vmmon/internal/match"
)

// A first scan can find 12,000 vulnerabilities and one advisory dozens, so every
// message shows a bounded top and counts the rest.
const (
	maxListed        = 15 // Findings listed in one message.
	maxListedPerPkg  = 5  // Findings of one package among them, unless KEV-listed.
	maxSummaryKEV    = 10
	maxDigestPkgs    = 10
	maxWarnings      = 5
	maxTextLen       = 200 // Longest free text quoted from errors and warnings.
	detailsHint      = "Details: <code>vmmon scan</code>"
	upgradeHint      = "Run: <code>sudo apt upgrade</code>"
	escalatedNewKEV  = "now KEV-listed"
	escalatedNewFix  = "fix now available"
	escalatedPolicy  = "now meets the alert policy"
	noFixYetSuffix   = " (no fix yet)"
	rebootNeededText = "Reboot required."
)

// Escalation is a reported finding that became more urgent.
type Escalation struct {
	Finding finding.Finding
	// NewKEV, NewFix and NewAlert say why; several can be true.
	NewKEV, NewFix, NewAlert bool
}

// RenderAlert renders the one alert for all new findings of a scan.
func RenderAlert(hostname string, fs []finding.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s <b>%s</b> · %s\n", alertIcon(fs), EscapeHTML(hostname), countNoun(len(fs), "new vulnerability", "new vulnerabilities"))
	writeFindings(&b, fs, nil)
	writeHints(&b, fs)
	return strings.TrimRight(b.String(), "\n")
}

// RenderEscalation renders the one follow-up for findings that became more urgent.
func RenderEscalation(hostname string, es []Escalation) string {
	fs := make([]finding.Finding, len(es))
	reasons := make(map[string]string, len(es))
	for i := range es {
		fs[i] = es[i].Finding
		var why []string
		if es[i].NewKEV {
			why = append(why, escalatedNewKEV)
		}
		if es[i].NewFix {
			why = append(why, escalatedNewFix)
		}
		if len(why) == 0 && es[i].NewAlert {
			why = append(why, escalatedPolicy)
		}
		reasons[fs[i].ID] = strings.Join(why, ", ")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s <b>%s</b> · %s\n", alertIcon(fs), EscapeHTML(hostname), countNoun(len(fs), "finding escalated", "findings escalated"))
	writeFindings(&b, fs, reasons)
	writeHints(&b, fs)
	return strings.TrimRight(b.String(), "\n")
}

// Summary is what the summary of a whole scan says.
type Summary struct {
	Packages int
	Counts   finding.Counts
	// KEV lists the KEV-listed findings; only the top few are shown.
	KEV            []finding.Finding
	RebootRequired bool
	Warnings       []string
}

// RenderSummary renders the summary of a full scan: counts and the top KEV items,
// never a list of everything.
func RenderSummary(hostname string, s Summary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "🔎 <b>%s</b> · vmmon scan summary\n", EscapeHTML(hostname))
	fmt.Fprintf(&b, "%s in %s: %d known exploited, %d with a fix, %d without a fix yet\n",
		countNoun(s.Counts.Total, "finding", "findings"), countNoun(s.Packages, "package", "packages"),
		s.Counts.KEV, s.Counts.FixAvailable, s.Counts.NoFixYet)
	if len(s.KEV) > 0 {
		kev := slices.Clone(s.KEV)
		sortFindings(kev)
		b.WriteString("Known exploited:\n")
		for i := range kev[:min(len(kev), maxSummaryKEV)] {
			f := &kev[i]
			fmt.Fprintf(&b, "• %s %s", EscapeHTML(f.SourcePackage), EscapeHTML(f.InstalledVersion))
			b.WriteString(fixText(f.FixedVersion, f.RebootRequired))
			fmt.Fprintf(&b, "\n  %s\n", findingNote(f, ""))
		}
		if more := len(kev) - maxSummaryKEV; more > 0 {
			fmt.Fprintf(&b, "…and %d more\n", more)
		}
	}
	if s.RebootRequired {
		b.WriteString(rebootNeededText + "\n")
	}
	writeWarnings(&b, s.Warnings)
	b.WriteString("Only new findings alert from here on. " + detailsHint)
	return b.String()
}

// Digest is what a periodic digest says.
type Digest struct {
	Weekly bool
	Open   finding.Counts
	// KEV lists the open KEV-listed findings; only the top few are shown.
	KEV      []finding.Finding
	Resolved []finding.Finding
	// Silent counts new findings below the alert policy since the last digest.
	Silent         int
	DBSyncedAt     time.Time
	Now            time.Time
	RebootRequired bool
	Warnings       []string
}

// RenderDigest renders the periodic digest: open counts, resolved, DB age, reboot.
func RenderDigest(hostname string, d Digest) string {
	var b strings.Builder
	period := "daily"
	if d.Weekly {
		period = "weekly"
	}
	fmt.Fprintf(&b, "📋 <b>%s</b> · %s digest\n", EscapeHTML(hostname), period)
	fmt.Fprintf(&b, "Open: %d (%d known exploited, %d with a fix, %d without a fix yet)\n",
		d.Open.Total, d.Open.KEV, d.Open.FixAvailable, d.Open.NoFixYet)
	if len(d.KEV) > 0 {
		kev := slices.Clone(d.KEV)
		sortFindings(kev)
		for i := range kev[:min(len(kev), maxSummaryKEV)] {
			f := &kev[i]
			fmt.Fprintf(&b, "• %s %s\n", EscapeHTML(f.VulnID), EscapeHTML(f.SourcePackage))
		}
		if more := len(kev) - maxSummaryKEV; more > 0 {
			fmt.Fprintf(&b, "…and %d more\n", more)
		}
	}
	if d.Silent > 0 {
		fmt.Fprintf(&b, "New below the alert policy: %d\n", d.Silent)
	}
	if n := len(d.Resolved); n > 0 {
		fmt.Fprintf(&b, "✅ Resolved: %d\n", n)
		writeResolved(&b, d.Resolved)
	} else {
		b.WriteString("Resolved: 0\n")
	}
	if d.DBSyncedAt.IsZero() {
		b.WriteString("Database: never synced\n")
	} else {
		fmt.Fprintf(&b, "Database: synced %s ago\n", age(d.Now.Sub(d.DBSyncedAt)))
	}
	if d.RebootRequired {
		b.WriteString(rebootNeededText + "\n")
	}
	writeWarnings(&b, d.Warnings)
	return strings.TrimRight(b.String(), "\n")
}

// Stale is what a staleness alert says.
type Stale struct {
	// LastSync is the last successful sync; zero if there never was one.
	LastSync time.Time
	// Since is when the daemon first ran, for a database that never synced.
	Since     time.Time
	Now       time.Time
	LastError string
}

// RenderStale renders the alert for a database that stopped syncing.
func RenderStale(hostname string, s Stale) string {
	var b strings.Builder
	fmt.Fprintf(&b, "⚠️ <b>%s</b> · vulnerability database is stale\n", EscapeHTML(hostname))
	if s.LastSync.IsZero() {
		fmt.Fprintf(&b, "It has not synced in the %s since vmmon started, so new advisories cannot alert.\n", age(s.Now.Sub(s.Since)))
	} else {
		fmt.Fprintf(&b, "Last successful sync was %s ago, so new advisories may not alert.\n", age(s.Now.Sub(s.LastSync)))
	}
	if s.LastError != "" {
		fmt.Fprintf(&b, "Last error: %s\n", EscapeHTML(truncate(s.LastError)))
	}
	b.WriteString("Check: <code>vmmon status</code>")
	return b.String()
}

// RenderDropped renders the note put before the next message after the queue
// overflowed.
func RenderDropped(hostname string, n int) string {
	return fmt.Sprintf("⚠️ <b>%s</b> · %s lost in a long outage. Check: <code>vmmon status</code>\n\n",
		EscapeHTML(hostname), countNoun(n, "older message", "older messages"))
}

// writeFindings lists the top findings grouped by package, and counts the rest.
// reasons, keyed by finding ID, adds why a finding is listed.
func writeFindings(b *strings.Builder, fs []finding.Finding, reasons map[string]string) {
	sorted := slices.Clone(fs)
	sortFindings(sorted)

	total := map[string]int{}
	fix := map[string]string{}
	reboot := map[string]bool{}
	for i := range sorted {
		f := &sorted[i]
		total[f.SourcePackage]++
		if match.CompareVersions(f.FixedVersion, fix[f.SourcePackage]) > 0 {
			fix[f.SourcePackage] = f.FixedVersion
		}
		reboot[f.SourcePackage] = reboot[f.SourcePackage] || f.RebootRequired
	}

	// Take the top, keeping one package from filling the whole message.
	var order []string
	listed := map[string][]*finding.Finding{}
	shown := 0
	for i := range sorted {
		if shown == maxListed {
			break
		}
		f := &sorted[i]
		name := f.SourcePackage
		if !f.KEV && len(listed[name]) >= maxListedPerPkg {
			continue
		}
		if listed[name] == nil {
			order = append(order, name)
		}
		listed[name] = append(listed[name], f)
		shown++
	}

	for _, name := range order {
		list := listed[name]
		fmt.Fprintf(b, "• %s %s%s\n", EscapeHTML(name), EscapeHTML(list[0].InstalledVersion), fixText(fix[name], reboot[name]))
		for _, f := range list {
			note := findingNote(f, reasons[f.ID])
			if f.FixedVersion == "" && fix[name] != "" {
				note += noFixYetSuffix
			}
			fmt.Fprintf(b, "  %s\n", note)
		}
	}
	if more := len(sorted) - shown; more > 0 {
		fmt.Fprintf(b, "…and %d more\n", more)
	}
}

func writeHints(b *strings.Builder, fs []finding.Finding) {
	if slices.ContainsFunc(fs, func(f finding.Finding) bool { return f.FixStatus == finding.FixAvailable }) {
		b.WriteString(upgradeHint + "\n")
	}
	if len(fs) > maxListed {
		b.WriteString(detailsHint + "\n")
	}
}

// writeResolved counts resolved findings per package, largest first.
func writeResolved(b *strings.Builder, fs []finding.Finding) {
	counts := map[string]int{}
	var names []string
	for i := range fs {
		name := fs[i].SourcePackage
		if counts[name] == 0 {
			names = append(names, name)
		}
		counts[name]++
	}
	slices.SortFunc(names, func(x, y string) int { return cmp.Or(cmp.Compare(counts[y], counts[x]), cmp.Compare(x, y)) })
	for _, name := range names[:min(len(names), maxDigestPkgs)] {
		fmt.Fprintf(b, "• %s: %d\n", EscapeHTML(name), counts[name])
	}
	if more := len(names) - maxDigestPkgs; more > 0 {
		fmt.Fprintf(b, "…and %d more packages\n", more)
	}
}

func writeWarnings(b *strings.Builder, warnings []string) {
	for _, w := range warnings[:min(len(warnings), maxWarnings)] {
		fmt.Fprintf(b, "⚠️ %s\n", EscapeHTML(truncate(w)))
	}
	if more := len(warnings) - maxWarnings; more > 0 {
		fmt.Fprintf(b, "…and %d more warnings\n", more)
	}
}

// fixText follows a package and version: where to go from there.
func fixText(fix string, reboot bool) string {
	switch {
	case fix == "":
		return noFixYetSuffix
	case reboot:
		return " → fix " + EscapeHTML(fix) + " (reboot required)"
	}
	return " → fix " + EscapeHTML(fix)
}

// findingNote is a finding's line: its ID and what makes it matter.
func findingNote(f *finding.Finding, reason string) string {
	parts := []string{EscapeHTML(f.VulnID)}
	if f.KEV {
		parts = append(parts, "KEV")
	}
	if f.CVSSScore > 0 {
		parts = append(parts, fmt.Sprintf("CVSS %.1f", f.CVSSScore))
	}
	if f.EPSS >= 0.01 {
		parts = append(parts, fmt.Sprintf("EPSS %.2f", f.EPSS))
	}
	if reason != "" {
		parts = append(parts, EscapeHTML(reason))
	}
	return strings.Join(parts, " · ")
}

// sortFindings orders worst first: KEV-listed, then fix available, each by severity.
func sortFindings(fs []finding.Finding) {
	rank := func(f *finding.Finding) int {
		switch {
		case f.KEV:
			return 0
		case f.FixStatus == finding.FixAvailable:
			return 1
		}
		return 2
	}
	slices.SortStableFunc(fs, func(a, b finding.Finding) int {
		return cmp.Or(
			cmp.Compare(rank(&a), rank(&b)),
			cmp.Compare(severity(&b), severity(&a)),
			cmp.Compare(b.EPSS, a.EPSS),
			cmp.Compare(a.SourcePackage, b.SourcePackage),
			cmp.Compare(a.VulnID, b.VulnID),
		)
	})
}

// severity is the CVSS score, with the distro's label standing in for a missing one.
func severity(f *finding.Finding) float64 {
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

func alertIcon(fs []finding.Finding) string {
	for i := range fs {
		if fs[i].KEV || severity(&fs[i]) >= 7 || fs[i].EPSS >= 0.1 {
			return "🔴"
		}
	}
	return "🟡"
}

func countNoun(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func age(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours())/24)
}

func truncate(s string) string {
	if r := []rune(s); len(r) > maxTextLen {
		return string(r[:maxTextLen]) + "…"
	}
	return s
}
