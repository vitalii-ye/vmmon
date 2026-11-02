package match

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/vitalii-ye/vmmon/internal/config"
	"github.com/vitalii-ye/vmmon/internal/enrich"
	"github.com/vitalii-ye/vmmon/internal/finding"
	"github.com/vitalii-ye/vmmon/internal/inventory"
	"github.com/vitalii-ye/vmmon/internal/vulndb"
)

// baseKernelSource is always a kernel source: its non-kernel binaries, such as
// linux-libc-dev and linux-tools-common, are installed without any image from it.
const baseKernelSource = "linux"

// Options narrows a match.
type Options struct {
	// Only limits matching to these source packages when not nil. A kernel source
	// named here is still matched at the running kernel's version only.
	Only map[string]bool
	// Ignore suppresses findings by VulnID, and by source or binary package name.
	Ignore config.Ignore
}

// Result is the outcome of one match.
type Result struct {
	// Findings are sorted by source package, then VulnID.
	Findings []finding.Finding
	// Warnings report what the match could not check.
	Warnings []string
}

// Match evaluates db's records against host and enriches the findings. The same
// input gives the same output.
//
// A package is affected when its source version is within an ECOSYSTEM range or
// listed in versions. Each record is fanned out to the CVEs it names, then the
// candidates for one (source package, CVE) are merged into one finding. See
// vulnState for how they merge.
//
// Kernel sources are matched only at the running kernel's version. Everything
// else built from them is skipped: old images, linux-libc-dev, linux-headers and
// linux-tools are not the running kernel. The sources are the ones installed
// images come from, plus "linux"; a linux* prefix would also catch ordinary
// packages such as linux-pam, linux-base and linux-atm.
func Match(ctx context.Context, host *inventory.Host, db vulndb.Reader, lookup enrich.Lookup, opts Options) (Result, error) {
	ignore := newIgnoreSet(opts.Ignore)
	res := Result{Findings: []finding.Finding{}}
	for _, t := range newTargets(host) {
		if (opts.Only != nil && !opts.Only[t.source]) || ignore.packages[t.source] {
			continue
		}
		fs, err := t.evaluate(ctx, host, db, lookup, ignore)
		if err != nil {
			return Result{}, fmt.Errorf("match %s: %w", t.source, err)
		}
		res.Findings = append(res.Findings, fs...)
	}
	w, err := kernelWarning(host, db)
	if err != nil {
		return Result{}, err
	}
	if w != "" {
		res.Warnings = append(res.Warnings, w)
	}
	return res, nil
}

// errStop ends a record iteration early.
var errStop = errors.New("stop")

// kernelWarning reports a kernel whose source has no records. OSV leaves some
// correctly identified kernels out entirely, such as linux-6.12 in Debian:12,
// which would otherwise look exactly like a clean kernel. A host with no kernel
// image (a container) gets no warning.
func kernelWarning(host *inventory.Host, db vulndb.Reader) (string, error) {
	k := host.Kernel
	if k.SourceName == "" {
		return "", nil
	}
	err := db.EachRecord(k.SourceName, func(vulndb.Record) error { return errStop })
	switch {
	case errors.Is(err, errStop):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("match %s: %w", k.SourceName, err)
	}
	return fmt.Sprintf("kernel vulnerabilities could not be checked: %s has no records for kernel source %s (running version %s)",
		host.Release.Ecosystem, k.SourceName, k.Version), nil
}

type ignoreSet struct {
	vulns, packages map[string]bool
}

func newIgnoreSet(ig config.Ignore) ignoreSet {
	s := ignoreSet{vulns: map[string]bool{}, packages: map[string]bool{}}
	for _, v := range ig.CVEs {
		s.vulns[strings.ToUpper(strings.TrimSpace(v))] = true
	}
	for _, p := range ig.Packages {
		s.packages[strings.TrimSpace(p)] = true
	}
	return s
}

// suppresses reports whether a finding is ignored. Naming any of its binaries
// suppresses it, as the finding is what the user is looking at when writing the
// ignore entry.
func (s ignoreSet) suppresses(f *finding.Finding) bool {
	return s.vulns[strings.ToUpper(f.VulnID)] || s.packages[f.SourcePackage] ||
		slices.ContainsFunc(f.BinaryPackages, func(b string) bool { return s.packages[b] })
}

// target is one source package to evaluate, with its distinct installed versions
// in ascending order.
type target struct {
	source   string
	kernel   bool
	versions []string
	binaries map[string][]string // by source version
}

// newTargets lists what to evaluate, sorted by source package.
func newTargets(host *inventory.Host) []*target {
	kernelSources := map[string]bool{baseKernelSource: true}
	for i := range host.Packages {
		if p := &host.Packages[i]; p.IsKernelImage {
			kernelSources[p.SourceName] = true
		}
	}
	bySource := map[string]*target{}
	add := func(source string, kernel bool) *target {
		t := bySource[source]
		if t == nil {
			t = &target{source: source, kernel: kernel, binaries: map[string][]string{}}
			bySource[source] = t
		}
		return t
	}
	k := host.Kernel
	if k.SourceName != "" {
		add(k.SourceName, true).binaries[k.Version] = nil
	}
	for i := range host.Packages {
		p := &host.Packages[i]
		if !kernelSources[p.SourceName] {
			t := add(p.SourceName, false)
			t.binaries[p.SourceVersion] = append(t.binaries[p.SourceVersion], p.Name)
		} else if p.SourceName == k.SourceName && p.SourceVersion == k.Version && isRunningKernelPart(p) {
			t := bySource[p.SourceName]
			t.binaries[p.SourceVersion] = append(t.binaries[p.SourceVersion], p.Name)
		}
	}
	out := make([]*target, 0, len(bySource))
	for _, source := range slices.Sorted(maps.Keys(bySource)) {
		t := bySource[source]
		t.versions = slices.SortedFunc(maps.Keys(t.binaries), func(a, b string) int {
			return cmp.Or(CompareVersions(a, b), strings.Compare(a, b))
		})
		out = append(out, t)
	}
	return out
}

// isRunningKernelPart keeps a kernel finding's binaries to what actually runs:
// linux-libc-dev and linux-headers of the same version hold no kernel code, and
// listing them would let an ignore entry for one suppress kernel findings.
func isRunningKernelPart(p *inventory.Package) bool {
	return p.IsKernelImage || strings.HasPrefix(p.Name, "linux-modules-")
}

// vulnState is what the matcher retains about one (source package, vuln). It
// never holds whole records: linux alone has over 10000 of them.
//
// Candidates merge like this. The fix is the highest fixed event above the
// installed version among the affecting records, as that one addresses every
// merged advisory. The score is the highest, and the label the strongest Ubuntu
// priority or else the strongest Debian urgency.
//
// Severity describes the vulnerability, not an installed version, so it comes
// also from records that do not affect the installed version. It only ever comes
// from a record naming that one vulnerability: a DSA or USN listing many CVEs
// says nothing about the severity of each.
type vulnState struct {
	byVersion []versionState // Parallel to target.versions.
	score     float64
	vector    string
	priority  string // Ubuntu
	urgency   string // Debian
}

// versionState holds the verdicts for one installed version.
//
// A record with no fixed event affecting the version is dropped when another
// record for the same vulnerability has a fixed event at or below it (patched):
// the package has the fix, and the unfixed record merely lags. The typical case
// is a DEBIAN-CVE record with no fix beside a DSA that fixed it. A record with a
// fixed event above the version stays affected regardless, and a record naming
// the vulnerability only through a sibling ID cannot set patched (see vulnIDs).
type versionState struct {
	fixedBy   []advisory // Affecting, with a fixed event above the version.
	unfixedBy []advisory // Affecting, without one.
	fix       string     // Highest fixed event above the version in fixedBy.
	patched   bool
}

// advisory is a record affecting a version.
type advisory struct {
	id, summary string
	// single means the record names only this vulnerability, which makes its
	// summary specific to it.
	single bool
}

func (t *target) evaluate(ctx context.Context, host *inventory.Host, db vulndb.Reader, lookup enrich.Lookup, ignore ignoreSet) ([]finding.Finding, error) {
	state := map[string]*vulnState{}
	err := db.EachRecord(t.source, func(rec vulndb.Record) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		t.apply(state, &rec)
		return nil
	})
	if err != nil {
		return nil, err
	}

	var out []finding.Finding
	for _, vuln := range slices.Sorted(maps.Keys(state)) {
		f := t.finding(host, vuln, state[vuln])
		if f == nil || ignore.suppresses(f) {
			continue
		}
		if strings.HasPrefix(vuln, cvePrefix) {
			info, err := lookup.Lookup(vuln)
			if err != nil {
				return nil, fmt.Errorf("enrich %s: %w", vuln, err)
			}
			f.KEV, f.EPSS, f.EPSSPercentile = info.KEV, info.EPSS, info.EPSSPercentile
			if info.KEV {
				date := info.KEVDateAdded
				f.KEVDateAdded = &date
			}
		}
		out = append(out, *f)
	}
	return out, nil
}

// apply folds one record into the state.
func (t *target) apply(state map[string]*vulnState, rec *vulndb.Record) {
	ids, inferred := vulnIDs(rec)
	verdicts := make([]verdict, len(t.versions))
	for i, v := range t.versions {
		verdicts[i] = evaluateRecord(rec.Affected, v)
	}
	sev := severity{}
	if len(ids) == 1 {
		sev = recordSeverity(rec)
	}
	for _, id := range ids {
		st := state[id]
		if st == nil {
			st = &vulnState{byVersion: make([]versionState, len(t.versions))}
			state[id] = st
		}
		st.merge(sev)
		adv := advisory{id: rec.ID, summary: rec.Summary, single: len(ids) == 1}
		for i := range verdicts {
			vs, v := &st.byVersion[i], &verdicts[i]
			switch {
			case !v.affected:
				vs.patched = vs.patched || (v.patched && !inferred[id])
			case v.fix == "":
				vs.unfixedBy = append(vs.unfixedBy, adv)
			default:
				vs.fixedBy = append(vs.fixedBy, adv)
				vs.fix = higherVersion(vs.fix, v.fix)
			}
		}
	}
}

func higherVersion(a, b string) string {
	if a == "" || CompareVersions(b, a) > 0 {
		return b
	}
	return a
}

// finding builds the finding for one vulnerability, or returns nil if no
// installed version is affected. InstalledVersion is the lowest affected version
// and BinaryPackages only what was built from affected versions.
func (t *target) finding(host *inventory.Host, vuln string, st *vulnState) *finding.Finding {
	var installed, fix string
	var advisories []advisory
	binaries := []string{}
	for i, version := range t.versions {
		vs := &st.byVersion[i]
		count := len(advisories)
		advisories = append(advisories, vs.fixedBy...)
		if !vs.patched {
			advisories = append(advisories, vs.unfixedBy...)
		}
		if len(advisories) == count {
			continue
		}
		if installed == "" {
			installed = version
		}
		if vs.fix != "" {
			fix = higherVersion(fix, vs.fix)
		}
		binaries = append(binaries, t.binaries[version]...)
	}
	if installed == "" {
		return nil
	}
	slices.Sort(binaries)

	f := &finding.Finding{
		ID:               finding.NewID(host.Release.Ecosystem, t.source, vuln),
		Ecosystem:        host.Release.Ecosystem,
		SourcePackage:    t.source,
		InstalledVersion: installed,
		BinaryPackages:   slices.Compact(binaries),
		VulnID:           vuln,
		AdvisoryIDs:      advisoryIDs(advisories),
		Summary:          bestSummary(advisories),
		FixStatus:        finding.NoFixYet,
		FixedVersion:     fix,
		CVSSScore:        st.score,
		CVSSVector:       st.vector,
		SeverityLabel:    cmp.Or(st.priority, st.urgency),
		Kernel:           t.kernel,
	}
	if fix != "" {
		f.FixStatus = finding.FixAvailable
		f.RebootRequired = t.kernel && fixedImageInstalled(host, t.source, fix)
	}
	return f
}

// fixedImageInstalled reports whether an image of the running kernel's source
// has the fix: installed, but not running, or the finding would not exist.
func fixedImageInstalled(host *inventory.Host, source, fix string) bool {
	return slices.ContainsFunc(host.Packages, func(p inventory.Package) bool {
		return p.IsKernelImage && p.SourceName == source && CompareVersions(p.SourceVersion, fix) >= 0
	})
}

func advisoryIDs(advisories []advisory) []string {
	ids := make([]string, len(advisories))
	for i := range advisories {
		ids[i] = advisories[i].id
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// bestSummary prefers a record about this vulnerability alone, then the lowest ID.
func bestSummary(advisories []advisory) string {
	var best *advisory
	for i := range advisories {
		a := &advisories[i]
		if a.summary == "" {
			continue
		}
		if best == nil || (a.single && !best.single) || (a.single == best.single && a.id < best.id) {
			best = a
		}
	}
	if best == nil {
		return ""
	}
	return best.summary
}

const (
	cvePrefix       = "CVE-"
	debianCVEPrefix = "DEBIAN-" + cvePrefix
	ubuntuCVEPrefix = "UBUNTU-" + cvePrefix
)

// vulnIDs returns what a record is about, sorted: the CVEs it names, or else its
// own ID. A DEBIAN-CVE-X or UBUNTU-CVE-X ID stands for CVE-X. An advisory can name
// its CVEs only that way, and on some releases such a USN is the only link to the
// CVE, as the UBUNTU-CVE record has no entry there.
//
// inferred holds the CVEs an advisory reaches only through a sibling ID. They
// identify the vulnerability and its fix, but are too weak to prove a version
// patched: a USN listing many CVEs across releases may not fix each one on this
// release, and hiding a real vulnerability costs more than one extra finding.
func vulnIDs(rec *vulndb.Record) (ids []string, inferred map[string]bool) {
	add := func(id string) {
		if strings.HasPrefix(id, cvePrefix) && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	own, isCVERecord := siblingCVE(strings.ToUpper(rec.ID))
	add(own)
	lists := [][]string{rec.Aliases, rec.Upstream, rec.Related}
	for _, list := range lists {
		for _, id := range list {
			add(strings.ToUpper(id))
		}
	}
	if !isCVERecord {
		for _, list := range lists {
			for _, id := range list {
				if cve, ok := siblingCVE(strings.ToUpper(id)); ok && !slices.Contains(ids, cve) {
					ids = append(ids, cve)
					if inferred == nil {
						inferred = map[string]bool{}
					}
					inferred[cve] = true
				}
			}
		}
	}
	if len(ids) == 0 {
		return []string{rec.ID}, nil
	}
	slices.Sort(ids)
	return ids, inferred
}

// siblingCVE maps DEBIAN-CVE-X and UBUNTU-CVE-X to CVE-X. Any other ID is returned
// unchanged with false.
func siblingCVE(id string) (string, bool) {
	if strings.HasPrefix(id, debianCVEPrefix) || strings.HasPrefix(id, ubuntuCVEPrefix) {
		return id[len("DEBIAN-"):], true // Both prefixes have the same length.
	}
	return id, false
}

// verdict is what one record says about one installed version.
type verdict struct {
	affected bool
	// fix is the record's fix for an affected version, "" if it has none.
	fix string
	// patched means the version is not affected and has a fixed event at or below
	// it, not merely that no range contains it.
	patched bool
}

// evaluateRecord applies a record's entries for one package to one version.
func evaluateRecord(entries []vulndb.Affected, version string) verdict {
	var v verdict
	var inRange, patched bool
	var above string // Lowest fixed event above the version in ranges not containing it.
	for i := range entries {
		a := &entries[i]
		if slices.Contains(a.Versions, version) {
			v.affected = true
		}
		for j := range a.Ranges {
			r := &a.Ranges[j]
			if r.Type != "ECOSYSTEM" {
				continue
			}
			contains, nextFix, fixedBelow := evaluateRange(r.Events, version)
			patched = patched || fixedBelow
			switch {
			case contains:
				inRange = true
				if nextFix != "" {
					v.fix = higherVersion(v.fix, nextFix)
				}
			case nextFix != "" && (above == "" || CompareVersions(nextFix, above) < 0):
				above = nextFix
			}
		}
	}
	if inRange {
		v.affected = true
		return v
	}
	if v.affected {
		v.fix = above // Listed in versions only.
		return v
	}
	v.patched = patched
	return v
}

// evaluateRange implements the OSV range algorithm over events ordered by
// version. It reports whether version is in the range, the first fixed event
// above it, and whether a fixed event at or below it exists. introduced "0"
// precedes every version, including ones that sort below a literal 0.
func evaluateRange(events []vulndb.Event, version string) (contains bool, nextFix string, fixedBelow bool) {
	if !slices.IsSortedFunc(events, compareEvents) {
		events = slices.Clone(events)
		slices.SortStableFunc(events, compareEvents)
	}
	for i := range events {
		e := &events[i]
		switch {
		case e.Introduced != "":
			if e.Introduced == "0" || CompareVersions(version, e.Introduced) >= 0 {
				contains = true
			}
		case e.Fixed != "":
			if CompareVersions(version, e.Fixed) >= 0 {
				contains = false
				fixedBelow = true
			} else if nextFix == "" {
				nextFix = e.Fixed
			}
		case e.LastAffected != "":
			if CompareVersions(version, e.LastAffected) > 0 {
				contains = false
			}
		}
	}
	return contains, nextFix, fixedBelow
}

// compareEvents orders events by version. At the same version a range opens
// before it closes, so an empty range stays empty.
func compareEvents(a, b vulndb.Event) int {
	av, ao := eventKey(a)
	bv, bo := eventKey(b)
	if av != bv {
		switch {
		case av == "0" && ao == 0:
			return -1
		case bv == "0" && bo == 0:
			return 1
		}
		if c := CompareVersions(av, bv); c != 0 {
			return c
		}
	}
	return ao - bo
}

// eventKey returns an event's version, and 0 if it opens the range.
func eventKey(e vulndb.Event) (string, int) {
	switch {
	case e.Introduced != "":
		return e.Introduced, 0
	case e.Fixed != "":
		return e.Fixed, 1
	}
	return e.LastAffected, 1
}

// severity is the rating of one record.
type severity struct {
	score             float64
	vector            string
	priority, urgency string
}

// recordSeverity extracts what a record says. Debian's urgency sits on the
// affected entry, the rest in severity: vectors of type CVSS_V3 or CVSS_V4, or a
// word of type Ubuntu. A few entries have a word and no type.
func recordSeverity(rec *vulndb.Record) severity {
	var s severity
	for _, sv := range rec.Severity {
		if strings.HasPrefix(sv.Score, "CVSS:") {
			if score, ok := baseScore(rec.ID, sv.Score); ok && (s.vector == "" || score > s.score || (score == s.score && sv.Score < s.vector)) {
				s.score, s.vector = score, sv.Score
			}
		} else if sv.Type == "Ubuntu" || sv.Type == "" {
			s.priority = strongerLabel(s.priority, normalizeLabel(sv.Score))
		}
	}
	for i := range rec.Affected {
		s.urgency = strongerLabel(s.urgency, normalizeLabel(rec.Affected[i].EcosystemSpecific.Urgency))
	}
	return s
}

func (st *vulnState) merge(s severity) {
	if s.vector != "" && (st.vector == "" || s.score > st.score || (s.score == st.score && s.vector < st.vector)) {
		st.score, st.vector = s.score, s.vector
	}
	st.priority = strongerLabel(st.priority, s.priority)
	st.urgency = strongerLabel(st.urgency, s.urgency)
}
