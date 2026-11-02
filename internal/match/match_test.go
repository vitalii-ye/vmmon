package match

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vitalii-ye/vmmon/internal/config"
	"github.com/vitalii-ye/vmmon/internal/enrich"
	"github.com/vitalii-ye/vmmon/internal/finding"
	"github.com/vitalii-ye/vmmon/internal/inventory"
	"github.com/vitalii-ye/vmmon/internal/vulndb"
)

const eco = "Debian:12"

// fakeDB serves handwritten records, in ID order like the real index.
type fakeDB map[string][]vulndb.Record

func (db fakeDB) RecordsFor(pkg string) ([]vulndb.Record, error) { return db[pkg], nil }

func (db fakeDB) EachRecord(pkg string, fn func(vulndb.Record) error) error {
	for _, r := range db[pkg] {
		if err := fn(r); err != nil {
			return err
		}
	}
	return nil
}

type fakeLookup map[string]enrich.Info

func (l fakeLookup) Lookup(cve string) (enrich.Info, error) { return l[cve], nil }

// rec parses a record written as compact JSON, with the package and ecosystem
// filled into each affected entry.
func rec(t *testing.T, pkg, body string) vulndb.Record {
	t.Helper()
	var r vulndb.Record
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("bad record %s: %v", body, err)
	}
	for i := range r.Affected {
		r.Affected[i].Package = vulndb.Package{Name: pkg, Ecosystem: eco}
	}
	return r
}

// open is a range with no fix; fixedAt one with a fix.
func open() string { return `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]` }

func fixedAt(v string) string {
	return `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"` + v + `"}]}]`
}

func pkgs(specs ...string) []inventory.Package {
	var out []inventory.Package
	for _, s := range specs {
		f := strings.Split(s, " ")
		out = append(out, inventory.Package{Name: f[0], Version: f[2], SourceName: f[1], SourceVersion: f[2]})
	}
	return out
}

func hostWith(packages ...inventory.Package) *inventory.Host {
	return &inventory.Host{Hostname: "h", Release: inventory.Release{Ecosystem: eco}, Packages: packages}
}

func run(t *testing.T, h *inventory.Host, db fakeDB, opts Options) Result {
	t.Helper()
	res, err := Match(context.Background(), h, db, fakeLookup{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// only returns the single finding of a match.
func only(t *testing.T, h *inventory.Host, db fakeDB) finding.Finding {
	t.Helper()
	res := run(t, h, db, Options{})
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(res.Findings), res.Findings)
	}
	return res.Findings[0]
}

func vulnsOf(fs []finding.Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.SourcePackage+"/"+f.VulnID)
	}
	return out
}

func checkVulns(t *testing.T, fs []finding.Finding, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if got := vulnsOf(fs); !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %v, want %v", got, want)
	}
}

func TestEvaluateRange(t *testing.T) {
	type ev = vulndb.Event
	for _, tc := range []struct {
		name       string
		events     []ev
		version    string
		contains   bool
		nextFix    string
		fixedBelow bool
	}{
		{"below fix", []ev{{Introduced: "0"}, {Fixed: "1.2-1"}}, "1.1-1", true, "1.2-1", false},
		{"at fix", []ev{{Introduced: "0"}, {Fixed: "1.2-1"}}, "1.2-1", false, "", true},
		{"above fix", []ev{{Introduced: "0"}, {Fixed: "1.2-1"}}, "1.3-1", false, "", true},
		{"tilde is before the fix", []ev{{Introduced: "0"}, {Fixed: "1.2-1"}}, "1.2-1~deb12u1", true, "1.2-1", false},
		{"binNMU is after the fix", []ev{{Introduced: "0"}, {Fixed: "1.2-1"}}, "1.2-1+b1", false, "", true},
		{"epoch outranks upstream", []ev{{Introduced: "0"}, {Fixed: "1:1.0-1"}}, "2.0-1", true, "1:1.0-1", false},
		{"no fix", []ev{{Introduced: "0"}}, "9-1", true, "", false},
		{"below introduced", []ev{{Introduced: "2.0"}, {Fixed: "3.0"}}, "1.0", false, "3.0", false},
		{"at introduced", []ev{{Introduced: "2.0"}, {Fixed: "3.0"}}, "2.0", true, "3.0", false},
		{"introduced 0 precedes tilde versions", []ev{{Introduced: "0"}}, "0~rc1", true, "", false},
		{"last_affected includes", []ev{{Introduced: "0"}, {LastAffected: "2.0"}}, "2.0", true, "", false},
		{"last_affected excludes above, without being a fix", []ev{{Introduced: "0"}, {LastAffected: "2.0"}}, "2.0-1", false, "", false},
		{"reintroduced, first interval", []ev{{Introduced: "0"}, {Fixed: "2"}, {Introduced: "4"}, {Fixed: "6"}}, "1", true, "2", false},
		{"reintroduced, gap", []ev{{Introduced: "0"}, {Fixed: "2"}, {Introduced: "4"}, {Fixed: "6"}}, "3", false, "6", true},
		{"reintroduced, second interval", []ev{{Introduced: "0"}, {Fixed: "2"}, {Introduced: "4"}, {Fixed: "6"}}, "5", true, "6", true},
		{"reintroduced, past all", []ev{{Introduced: "0"}, {Fixed: "2"}, {Introduced: "4"}, {Fixed: "6"}}, "7", false, "", true},
		{"events out of order", []ev{{Fixed: "10"}, {Introduced: "9"}, {Fixed: "2"}, {Introduced: "0"}}, "9.5", true, "10", true},
		{"dpkg order, not string order", []ev{{Introduced: "0"}, {Fixed: "1.10"}}, "1.9", true, "1.10", false},
		{"empty range", []ev{{Fixed: "2"}, {Introduced: "2"}}, "2", false, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contains, nextFix, fixedBelow := evaluateRange(tc.events, tc.version)
			if contains != tc.contains || nextFix != tc.nextFix || fixedBelow != tc.fixedBelow {
				t.Errorf("got (%v, %q, %v), want (%v, %q, %v)", contains, nextFix, fixedBelow, tc.contains, tc.nextFix, tc.fixedBelow)
			}
		})
	}
}

func TestEvaluateRangeLeavesEventsUntouched(t *testing.T) {
	events := []vulndb.Event{{Fixed: "2"}, {Introduced: "0"}}
	evaluateRange(events, "1")
	if events[0].Fixed != "2" {
		t.Error("evaluateRange reordered the caller's events")
	}
}

func TestRangesAndVersions(t *testing.T) {
	h := hostWith(pkgs("foo foo 1.5-1")...)
	for _, tc := range []struct {
		name, body string
		want       []string
		status     finding.FixStatus
		fixed      string
	}{
		{"in range", `{"id":"CVE-1",` + `"affected":[{` + fixedAt("2.0-1") + `}]}`, []string{"foo/CVE-1"}, finding.FixAvailable, "2.0-1"},
		{"past fix", `{"id":"CVE-1","affected":[{` + fixedAt("1.5-1") + `}]}`, nil, "", ""},
		{"no fix", `{"id":"CVE-1","affected":[{` + open() + `}]}`, []string{"foo/CVE-1"}, finding.NoFixYet, ""},
		{"versions only", `{"id":"CVE-1","affected":[{"versions":["1.0-1","1.5-1"]}]}`, []string{"foo/CVE-1"}, finding.NoFixYet, ""},
		{"not in versions", `{"id":"CVE-1","affected":[{"versions":["1.0-1"]}]}`, nil, "", ""},
		{"in versions beyond the range is a union", `{"id":"CVE-1","affected":[{"versions":["1.5-1"],` + fixedAt("1.0-1") + `}]}`, []string{"foo/CVE-1"}, finding.NoFixYet, ""},
		{"versions with a later range", `{"id":"CVE-1","affected":[{"versions":["1.5-1"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"3.0"},{"fixed":"4.0"}]}]}]}`, []string{"foo/CVE-1"}, finding.FixAvailable, "4.0"},
		{"non-ECOSYSTEM range ignored", `{"id":"CVE-1","affected":[{"ranges":[{"type":"GIT","events":[{"introduced":"0"}]},{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`, nil, "", ""},
		{"multiple ranges", `{"id":"CVE-1","affected":[{"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0"}]},{"type":"ECOSYSTEM","events":[{"introduced":"1.4"},{"fixed":"1.6"}]}]}]}`, []string{"foo/CVE-1"}, finding.FixAvailable, "1.6"},
		{"multiple entries", `{"id":"CVE-1","affected":[{` + fixedAt("1.0") + `},{` + fixedAt("1.7") + `}]}`, []string{"foo/CVE-1"}, finding.FixAvailable, "1.7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := run(t, h, fakeDB{"foo": {rec(t, "foo", tc.body)}}, Options{})
			checkVulns(t, res.Findings, tc.want...)
			if len(res.Findings) == 1 {
				f := res.Findings[0]
				if f.FixStatus != tc.status || f.FixedVersion != tc.fixed {
					t.Errorf("fix = %s %q, want %s %q", f.FixStatus, f.FixedVersion, tc.status, tc.fixed)
				}
			}
		})
	}
}

func TestFindingFields(t *testing.T) {
	f := only(t, hostWith(pkgs("libfoo1 foo 1.0", "foo-bin foo 1.0", "foo-bin foo 1.0")...), fakeDB{"foo": {
		rec(t, "foo", `{"id":"DSA-1","summary":"foo - security update","upstream":["CVE-2026-1"],"affected":[{`+fixedAt("2.0")+`}]}`),
	}})
	if f.ID != finding.NewID(eco, "foo", "CVE-2026-1") {
		t.Errorf("ID = %s", f.ID)
	}
	if f.Ecosystem != eco || f.SourcePackage != "foo" || f.InstalledVersion != "1.0" || f.Summary != "foo - security update" {
		t.Errorf("unexpected finding %+v", f)
	}
	if want := []string{"foo-bin", "libfoo1"}; !reflect.DeepEqual(f.BinaryPackages, want) {
		t.Errorf("BinaryPackages = %v, want %v", f.BinaryPackages, want)
	}
}

func TestFanOut(t *testing.T) {
	h := hostWith(pkgs("foo foo 1.0")...)
	for _, tc := range []struct {
		name, body string
		want       []string
	}{
		{"own CVE ID", `{"id":"CVE-2026-1"}`, []string{"CVE-2026-1"}},
		{"Debian ID stripped", `{"id":"DEBIAN-CVE-2026-1"}`, []string{"CVE-2026-1"}},
		{"Ubuntu ID stripped", `{"id":"UBUNTU-CVE-2026-1"}`, []string{"CVE-2026-1"}},
		{"case normalised", `{"id":"debian-cve-2026-1","upstream":["cve-2026-2"]}`, []string{"CVE-2026-1", "CVE-2026-2"}},
		{"upstream", `{"id":"DSA-1","upstream":["CVE-2026-2","CVE-2026-1"]}`, []string{"CVE-2026-1", "CVE-2026-2"}},
		{"aliases", `{"id":"USN-1","aliases":["CVE-2026-1"]}`, []string{"CVE-2026-1"}},
		{"related with a CVE", `{"id":"USN-1","related":["CVE-2026-1"]}`, []string{"CVE-2026-1"}},
		{"advisory sibling IDs name CVEs", `{"id":"USN-1","upstream":["CVE-2026-1","UBUNTU-CVE-2026-1"],"related":["UBUNTU-CVE-2026-9"]}`, []string{"CVE-2026-1", "CVE-2026-9"}},
		{"only sibling IDs still name CVEs", `{"id":"USN-1","related":["UBUNTU-CVE-2026-9"]}`, []string{"CVE-2026-9"}},
		{"a CVE record's siblings are not its own", `{"id":"UBUNTU-CVE-2026-1","upstream":["CVE-2026-1"],"related":["UBUNTU-CVE-2026-9","USN-1"]}`, []string{"CVE-2026-1"}},
		{"no CVE at all", `{"id":"DSA-1"}`, []string{"DSA-1"}},
		{"duplicates collapse", `{"id":"DEBIAN-CVE-2026-1","upstream":["CVE-2026-1"],"aliases":["CVE-2026-1"]}`, []string{"CVE-2026-1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r vulndb.Record
			if err := json.Unmarshal([]byte(tc.body), &r); err != nil {
				t.Fatal(err)
			}
			if got, _ := vulnIDs(&r); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("vulnIDs = %v, want %v", got, tc.want)
			}
		})
	}

	res := run(t, h, fakeDB{"foo": {
		rec(t, "foo", `{"id":"DSA-1","upstream":["CVE-2026-1","CVE-2026-2","DEBIAN-CVE-2026-1"],"affected":[{`+fixedAt("2.0")+`}]}`),
		rec(t, "foo", `{"id":"DSA-2","affected":[{`+fixedAt("2.0")+`}]}`),
	}}, Options{})
	checkVulns(t, res.Findings, "foo/CVE-2026-1", "foo/CVE-2026-2", "foo/DSA-2")
	for _, f := range res.Findings[:2] {
		if !reflect.DeepEqual(f.AdvisoryIDs, []string{"DSA-1"}) {
			t.Errorf("%s: AdvisoryIDs = %v", f.VulnID, f.AdvisoryIDs)
		}
	}
}

func TestMergeFixes(t *testing.T) {
	f := only(t, hostWith(pkgs("foo foo 1.0-1")...), fakeDB{"foo": {
		rec(t, "foo", `{"id":"DEBIAN-CVE-2026-1","affected":[{`+open()+`}]}`),
		rec(t, "foo", `{"id":"DSA-1","upstream":["CVE-2026-1"],"affected":[{`+fixedAt("1.2-1")+`}]}`),
		rec(t, "foo", `{"id":"DSA-2","upstream":["CVE-2026-1"],"affected":[{`+fixedAt("1.10-1")+`}]}`),
		rec(t, "foo", `{"id":"DSA-3","upstream":["CVE-2026-1"],"affected":[{`+fixedAt("1.3-1")+`}]}`),
	}})
	if f.FixStatus != finding.FixAvailable || f.FixedVersion != "1.10-1" {
		t.Errorf("fix = %s %q, want the highest by dpkg order", f.FixStatus, f.FixedVersion)
	}
	if want := []string{"DEBIAN-CVE-2026-1", "DSA-1", "DSA-2", "DSA-3"}; !reflect.DeepEqual(f.AdvisoryIDs, want) {
		t.Errorf("AdvisoryIDs = %v, want %v", f.AdvisoryIDs, want)
	}
}

// A record past its fix is not merged, and its fixed event never becomes the
// finding's: it is below the installed version.
func TestMergeIgnoresFixesBelowInstalled(t *testing.T) {
	f := only(t, hostWith(pkgs("foo foo 1.5-1")...), fakeDB{"foo": {
		rec(t, "foo", `{"id":"DEBIAN-CVE-2026-1","affected":[{`+fixedAt("1.2-1")+`}]}`),
		rec(t, "foo", `{"id":"DSA-1","upstream":["CVE-2026-1"],"affected":[{`+fixedAt("1.6-1")+`}]}`),
	}})
	if f.FixedVersion != "1.6-1" || !reflect.DeepEqual(f.AdvisoryIDs, []string{"DSA-1"}) {
		t.Errorf("got fix %q, advisories %v", f.FixedVersion, f.AdvisoryIDs)
	}
}

// A USN can name its CVEs only through UBUNTU-CVE IDs, and be the only record for
// that CVE on the release. The CVE must survive for KEV and EPSS lookups.
func TestAdvisoryNamingCVEThroughSibling(t *testing.T) {
	h := hostWith(pkgs("foo foo 1.5-1")...)
	usn := func(id, fix string) vulndb.Record {
		return rec(t, "foo", `{"id":"`+id+`","upstream":["UBUNTU-CVE-2026-1"],"related":["UBUNTU-CVE-2026-1"],"affected":[{`+fixedAt(fix)+`}]}`)
	}
	unfixed := rec(t, "foo", `{"id":"UBUNTU-CVE-2026-1","upstream":["CVE-2026-1"],"affected":[{`+open()+`}]}`)

	t.Run("gives the CVE, its KEV status and its fix", func(t *testing.T) {
		db := fakeDB{"foo": {usn("USN-1", "1.6-1")}}
		res, err := Match(context.Background(), h, db, fakeLookup{"CVE-2026-1": {KEV: true}}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("got %d findings", len(res.Findings))
		}
		f := res.Findings[0]
		if f.VulnID != "CVE-2026-1" || !f.KEV || f.FixedVersion != "1.6-1" {
			t.Errorf("got %s kev=%v fix=%q", f.VulnID, f.KEV, f.FixedVersion)
		}
	})
	t.Run("regression notices merge into the highest fix", func(t *testing.T) {
		f := only(t, h, fakeDB{"foo": {usn("USN-1", "1.6-1"), usn("USN-1-2", "1.7-1")}})
		if f.FixedVersion != "1.7-1" || len(f.AdvisoryIDs) != 2 {
			t.Errorf("got fix %q, advisories %v", f.FixedVersion, f.AdvisoryIDs)
		}
	})
	t.Run("does not prove the installed version patched", func(t *testing.T) {
		f := only(t, h, fakeDB{"foo": {unfixed, usn("USN-1", "1.5-1")}})
		if f.FixStatus != finding.NoFixYet || !reflect.DeepEqual(f.AdvisoryIDs, []string{"UBUNTU-CVE-2026-1"}) {
			t.Errorf("got %s, advisories %v", f.FixStatus, f.AdvisoryIDs)
		}
	})
	t.Run("a literal CVE name in the same notice does", func(t *testing.T) {
		literal := rec(t, "foo", `{"id":"USN-1","upstream":["CVE-2026-1","UBUNTU-CVE-2026-1"],"affected":[{`+fixedAt("1.5-1")+`}]}`)
		res := run(t, h, fakeDB{"foo": {unfixed, literal}}, Options{})
		checkVulns(t, res.Findings)
	})
}

func TestFixedVersionOverride(t *testing.T) {
	unfixed := `{"id":"DEBIAN-CVE-2026-1","affected":[{` + open() + `}]}`
	h := hostWith(pkgs("foo foo 1.5-1")...)

	t.Run("patched drops the unfixed record", func(t *testing.T) {
		res := run(t, h, fakeDB{"foo": {
			rec(t, "foo", unfixed),
			rec(t, "foo", `{"id":"DSA-1","upstream":["CVE-2026-1"],"affected":[{`+fixedAt("1.5-1")+`}]}`),
		}}, Options{})
		checkVulns(t, res.Findings)
	})
	t.Run("regardless of record order", func(t *testing.T) {
		res := run(t, h, fakeDB{"foo": {
			rec(t, "foo", `{"id":"A-1","upstream":["CVE-2026-1"],"affected":[{`+fixedAt("1.4-1")+`}]}`),
			rec(t, "foo", unfixed),
		}}, Options{})
		checkVulns(t, res.Findings)
	})
	t.Run("a fix above installed does not override", func(t *testing.T) {
		f := only(t, h, fakeDB{"foo": {
			rec(t, "foo", unfixed),
			rec(t, "foo", `{"id":"DSA-1","upstream":["CVE-2026-1"],"affected":[{`+fixedAt("1.6-1")+`}]}`),
		}})
		if f.FixedVersion != "1.6-1" {
			t.Errorf("fix = %q", f.FixedVersion)
		}
	})
	t.Run("a record with a fix above stays affected when another is patched", func(t *testing.T) {
		f := only(t, h, fakeDB{"foo": {
			rec(t, "foo", unfixed),
			rec(t, "foo", `{"id":"DSA-1","upstream":["CVE-2026-1"],"affected":[{`+fixedAt("1.2-1")+`}]}`),
			rec(t, "foo", `{"id":"DSA-2","upstream":["CVE-2026-1"],"affected":[{`+fixedAt("1.6-1")+`}]}`),
		}})
		if f.FixedVersion != "1.6-1" || !reflect.DeepEqual(f.AdvisoryIDs, []string{"DSA-2"}) {
			t.Errorf("got fix %q, advisories %v", f.FixedVersion, f.AdvisoryIDs)
		}
	})
	t.Run("a fix for another CVE does not override", func(t *testing.T) {
		f := only(t, h, fakeDB{"foo": {
			rec(t, "foo", unfixed),
			rec(t, "foo", `{"id":"DSA-1","upstream":["CVE-2026-2"],"affected":[{`+fixedAt("1.2-1")+`}]}`),
		}})
		if f.VulnID != "CVE-2026-1" || f.FixStatus != finding.NoFixYet {
			t.Errorf("got %+v", f)
		}
	})
	t.Run("last_affected is not a fix", func(t *testing.T) {
		f := only(t, h, fakeDB{"foo": {
			rec(t, "foo", unfixed),
			rec(t, "foo", `{"id":"DSA-1","upstream":["CVE-2026-1"],"affected":[{"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"1.2-1"}]}]}]}`),
		}})
		if f.VulnID != "CVE-2026-1" {
			t.Errorf("got %+v", f)
		}
	})
	t.Run("multi-CVE record patches each CVE it names", func(t *testing.T) {
		res := run(t, h, fakeDB{"foo": {
			rec(t, "foo", unfixed),
			rec(t, "foo", `{"id":"DEBIAN-CVE-2026-2","affected":[{`+open()+`}]}`),
			rec(t, "foo", `{"id":"DEBIAN-CVE-2026-3","affected":[{`+open()+`}]}`),
			rec(t, "foo", `{"id":"DSA-1","upstream":["CVE-2026-1","CVE-2026-2"],"affected":[{`+fixedAt("1.0-1")+`}]}`),
		}}, Options{})
		checkVulns(t, res.Findings, "foo/CVE-2026-3")
	})
}

func TestSeverity(t *testing.T) {
	h := hostWith(pkgs("foo foo 1.0")...)
	const (
		v98 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		v75 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
		v3  = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
		v4  = "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X"
	)
	sev := func(pairs ...string) string {
		var parts []string
		for i := 0; i < len(pairs); i += 2 {
			parts = append(parts, `{"type":"`+pairs[i]+`","score":"`+pairs[i+1]+`"}`)
		}
		return `"severity":[` + strings.Join(parts, ",") + `],`
	}

	t.Run("highest score across records", func(t *testing.T) {
		f := only(t, h, fakeDB{"foo": {
			rec(t, "foo", `{"id":"DEBIAN-CVE-2026-1",`+sev("CVSS_V3", v75)+`"affected":[{`+open()+`}]}`),
			rec(t, "foo", `{"id":"UBUNTU-CVE-2026-1",`+sev("CVSS_V3", v98)+`"affected":[{`+open()+`}]}`),
			rec(t, "foo", `{"id":"XX-1","upstream":["CVE-2026-1"],`+sev("CVSS_V3", v75)+`"affected":[{`+open()+`}]}`),
		}})
		if f.CVSSScore != 9.8 || f.CVSSVector != v98 {
			t.Errorf("got %v %q", f.CVSSScore, f.CVSSVector)
		}
	})
	t.Run("CVSS 3.0 and 4.0 with explicit X fields", func(t *testing.T) {
		f := only(t, h, fakeDB{"foo": {rec(t, "foo", `{"id":"CVE-2026-1",`+sev("CVSS_V3", v3)+`"affected":[{`+open()+`}]}`)}})
		if f.CVSSScore != 7.5 {
			t.Errorf("3.0 score = %v", f.CVSSScore)
		}
		f = only(t, h, fakeDB{"foo": {rec(t, "foo", `{"id":"CVE-2026-1",`+sev("CVSS_V4", v4)+`"affected":[{`+open()+`}]}`)}})
		if f.CVSSScore != 2.1 || f.CVSSVector != v4 {
			t.Errorf("4.0 score = %v %q", f.CVSSScore, f.CVSSVector)
		}
	})
	t.Run("4.0 base score ignores threat metrics", func(t *testing.T) {
		a, ok1 := baseScore("r", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
		b, ok2 := baseScore("r", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U")
		if !ok1 || !ok2 || a != b {
			t.Errorf("scores %v (%v), %v (%v)", a, ok1, b, ok2)
		}
	})
	t.Run("unparseable vectors are ignored", func(t *testing.T) {
		f := only(t, h, fakeDB{"foo": {rec(t, "foo", `{"id":"CVE-2026-1",`+sev("CVSS_V3", "CVSS:3.1/garbage", "CVSS_V4", "CVSS:4.0/AV:Q", "CVSS_V2", "AV:N/AC:L/Au:N/C:P/I:P/A:P", "CVSS_V3", v75)+`"affected":[{`+open()+`}]}`)}})
		if f.CVSSScore != 7.5 {
			t.Errorf("score = %v", f.CVSSScore)
		}
	})
	t.Run("not smeared across a multi-CVE record", func(t *testing.T) {
		res := run(t, h, fakeDB{"foo": {
			rec(t, "foo", `{"id":"USN-1","upstream":["CVE-2026-1","CVE-2026-2"],`+sev("CVSS_V3", v98, "Ubuntu", "critical")+`"affected":[{"ecosystem_specific":{"urgency":"high"},`+fixedAt("2.0")+`}]}`),
			rec(t, "foo", `{"id":"UBUNTU-CVE-2026-2",`+sev("CVSS_V3", v75, "Ubuntu", "low")+`"affected":[{`+fixedAt("2.0")+`}]}`),
		}}, Options{})
		checkVulns(t, res.Findings, "foo/CVE-2026-1", "foo/CVE-2026-2")
		a, b := res.Findings[0], res.Findings[1]
		if a.CVSSScore != 0 || a.CVSSVector != "" || a.SeverityLabel != "" {
			t.Errorf("CVE-2026-1 got severity from a record naming two CVEs: %+v", a)
		}
		if b.CVSSScore != 7.5 || b.SeverityLabel != "low" {
			t.Errorf("CVE-2026-2 = %v %q", b.CVSSScore, b.SeverityLabel)
		}
	})
	t.Run("severity comes from a record not affecting the version", func(t *testing.T) {
		f := only(t, h, fakeDB{"foo": {
			rec(t, "foo", `{"id":"DEBIAN-CVE-2026-1",`+sev("CVSS_V3", v75)+`"affected":[{"ecosystem_specific":{"urgency":"medium"},`+fixedAt("0.5")+`}]}`),
			rec(t, "foo", `{"id":"DSA-1","upstream":["CVE-2026-1"],"affected":[{`+fixedAt("2.0")+`}]}`),
		}})
		if f.CVSSScore != 7.5 || f.SeverityLabel != "medium" || !reflect.DeepEqual(f.AdvisoryIDs, []string{"DSA-1"}) {
			t.Errorf("got %+v", f)
		}
	})

	labels := []struct {
		name  string
		bodys []string
		want  string
	}{
		{"strongest Ubuntu priority", []string{`"severity":[{"type":"Ubuntu","score":"low"}],`, `"severity":[{"type":"Ubuntu","score":"High"}],`}, "high"},
		{"word with no type", []string{`"severity":[{"type":"","score":"Medium"}],`}, "medium"},
		{"no vector from the word", []string{`"severity":[{"type":"Ubuntu","score":"negligible"}],`}, "negligible"},
	}
	for _, tc := range labels {
		t.Run(tc.name, func(t *testing.T) {
			var recs []vulndb.Record
			for _, b := range tc.bodys {
				recs = append(recs, rec(t, "foo", `{"id":"UBUNTU-CVE-2026-1",`+b+`"affected":[{`+open()+`}]}`))
			}
			if f := only(t, h, fakeDB{"foo": recs}); f.SeverityLabel != tc.want || f.CVSSScore != 0 {
				t.Errorf("label = %q, score %v, want %q", f.SeverityLabel, f.CVSSScore, tc.want)
			}
		})
	}
	urgency := func(u string) vulndb.Record {
		return rec(t, "foo", `{"id":"DEBIAN-CVE-2026-1","affected":[{"ecosystem_specific":{"urgency":"`+u+`"},`+open()+`}]}`)
	}
	for u, want := range map[string]string{"not yet assigned": "", "Not Yet Assigned": "", "unimportant": "unimportant", "end-of-life": "end-of-life", "HIGH": "high"} {
		t.Run("urgency "+u, func(t *testing.T) {
			if f := only(t, h, fakeDB{"foo": {urgency(u)}}); f.SeverityLabel != want {
				t.Errorf("label = %q, want %q", f.SeverityLabel, want)
			}
		})
	}
	t.Run("Ubuntu priority beats Debian urgency", func(t *testing.T) {
		f := only(t, h, fakeDB{"foo": {
			urgency("high"),
			rec(t, "foo", `{"id":"UBUNTU-CVE-2026-1","severity":[{"type":"Ubuntu","score":"low"}],"affected":[{`+open()+`}]}`),
		}})
		if f.SeverityLabel != "low" {
			t.Errorf("label = %q", f.SeverityLabel)
		}
	})
	t.Run("strongest urgency", func(t *testing.T) {
		f := only(t, h, fakeDB{"foo": {urgency("unimportant"), rec(t, "foo", `{"id":"XX-1","upstream":["CVE-2026-1"],"affected":[{"ecosystem_specific":{"urgency":"low"},`+open()+`}]}`)}})
		if f.SeverityLabel != "low" {
			t.Errorf("label = %q", f.SeverityLabel)
		}
	})
}

func TestStrongerLabelIsSymmetric(t *testing.T) {
	words := []string{"", "critical", "high", "medium", "low", "negligible", "end-of-life", "unimportant", "odd", "weird"}
	for _, a := range words {
		for _, b := range words {
			if x, y := strongerLabel(a, b), strongerLabel(b, a); x != y {
				t.Errorf("strongerLabel(%q, %q) = %q but reversed %q", a, b, x, y)
			}
		}
	}
}

// kernelHost is a running generic 6.8.0-45 with an older image of the same
// source, the fixed image pending and a HWE one, plus what else "linux" builds.
func kernelHost() *inventory.Host {
	h := hostWith(
		inventory.Package{Name: "linux-image-6.8.0-31-generic", Version: "6.8.0-31.31", SourceName: "linux", SourceVersion: "6.8.0-31.31", IsKernelImage: true},
		inventory.Package{Name: "linux-image-6.8.0-45-generic", Version: "6.8.0-45.45", SourceName: "linux", SourceVersion: "6.8.0-45.45", IsKernelImage: true},
		inventory.Package{Name: "linux-image-6.8.0-50-generic", Version: "6.8.0-50.50", SourceName: "linux", SourceVersion: "6.8.0-50.50", IsKernelImage: true},
		inventory.Package{Name: "linux-modules-6.8.0-45-generic", Version: "6.8.0-45.45", SourceName: "linux", SourceVersion: "6.8.0-45.45"},
		inventory.Package{Name: "linux-libc-dev", Version: "6.8.0-20.20", SourceName: "linux", SourceVersion: "6.8.0-20.20"},
		inventory.Package{Name: "linux-headers-6.8.0-45", Version: "6.8.0-45.45", SourceName: "linux", SourceVersion: "6.8.0-45.45"},
		inventory.Package{Name: "linux-tools-common", Version: "6.8.0-20.20", SourceName: "linux", SourceVersion: "6.8.0-20.20"},
		inventory.Package{Name: "libpam-modules", Version: "1.5.3-5", SourceName: "pam", SourceVersion: "1.5.3-5"},
		inventory.Package{Name: "linux-pam-doc", Version: "1.0-1", SourceName: "linux-pam", SourceVersion: "1.0-1"},
		inventory.Package{Name: "linux-base", Version: "4.5", SourceName: "linux-base", SourceVersion: "4.5"},
		inventory.Package{Name: "linux-atm", Version: "2.5", SourceName: "linux-atm", SourceVersion: "2.5"},
	)
	h.Kernel = inventory.Kernel{Release: "6.8.0-45-generic", SourceName: "linux", Version: "6.8.0-45.45"}
	return h
}

func TestKernel(t *testing.T) {
	h := kernelHost()
	db := fakeDB{"linux": {
		rec(t, "linux", `{"id":"CVE-2026-1","affected":[{`+fixedAt("6.8.0-30.30")+`}]}`), // Only old enough images.
		rec(t, "linux", `{"id":"CVE-2026-2","affected":[{`+fixedAt("6.8.0-40.40")+`}]}`), // The running one has it.
		rec(t, "linux", `{"id":"CVE-2026-3","affected":[{`+fixedAt("6.8.0-48.48")+`}]}`), // Pending reboot.
		rec(t, "linux", `{"id":"CVE-2026-4","affected":[{`+fixedAt("6.8.0-50.50")+`}]}`), // Pending reboot, exactly.
		rec(t, "linux", `{"id":"CVE-2026-5","affected":[{`+fixedAt("6.8.0-60.60")+`}]}`), // Fix not installed.
		rec(t, "linux", `{"id":"CVE-2026-6","affected":[{`+open()+`}]}`),                 // No fix.
	}}
	res := run(t, h, db, Options{})
	checkVulns(t, res.Findings, "linux/CVE-2026-3", "linux/CVE-2026-4", "linux/CVE-2026-5", "linux/CVE-2026-6")
	reboot := map[string]bool{"CVE-2026-3": true, "CVE-2026-4": true}
	for _, f := range res.Findings {
		if !f.Kernel || f.InstalledVersion != "6.8.0-45.45" {
			t.Errorf("%s: Kernel=%v InstalledVersion=%q", f.VulnID, f.Kernel, f.InstalledVersion)
		}
		if f.RebootRequired != reboot[f.VulnID] {
			t.Errorf("%s: RebootRequired = %v", f.VulnID, f.RebootRequired)
		}
		if want := []string{"linux-image-6.8.0-45-generic", "linux-modules-6.8.0-45-generic"}; !reflect.DeepEqual(f.BinaryPackages, want) {
			t.Errorf("%s: BinaryPackages = %v", f.VulnID, f.BinaryPackages)
		}
	}
	if len(res.Warnings) != 0 {
		t.Errorf("Warnings = %v", res.Warnings)
	}
}

func TestKernelSourcesAreExact(t *testing.T) {
	cve := func(pkg, id string) vulndb.Record {
		return rec(t, pkg, `{"id":"`+id+`","affected":[{`+open()+`}]}`)
	}
	db := fakeDB{
		"linux":      {cve("linux", "CVE-2026-1")},
		"linux-pam":  {cve("linux-pam", "CVE-2026-2")},
		"linux-base": {cve("linux-base", "CVE-2026-3")},
		"linux-atm":  {cve("linux-atm", "CVE-2026-4")},
		"pam":        {cve("pam", "CVE-2026-5")},
	}
	res := run(t, kernelHost(), db, Options{})
	checkVulns(t, res.Findings, "linux/CVE-2026-1", "linux-atm/CVE-2026-4", "linux-base/CVE-2026-3", "linux-pam/CVE-2026-2", "pam/CVE-2026-5")
}

// Running HWE: the GA "linux" images and linux-libc-dev are not what is running.
func TestKernelFlavour(t *testing.T) {
	h := hostWith(
		inventory.Package{Name: "linux-image-5.15.0-100-generic", Version: "5.15.0-100.110", SourceName: "linux", SourceVersion: "5.15.0-100.110", IsKernelImage: true},
		inventory.Package{Name: "linux-image-6.8.0-45-generic", Version: "6.8.0-45.45~22.04.1", SourceName: "linux-hwe-6.8", SourceVersion: "6.8.0-45.45~22.04.1", IsKernelImage: true},
		inventory.Package{Name: "linux-hwe-6.8-headers-6.8.0-40", Version: "6.8.0-40.40~22.04.1", SourceName: "linux-hwe-6.8", SourceVersion: "6.8.0-40.40~22.04.1"},
		inventory.Package{Name: "linux-libc-dev", Version: "5.15.0-100.110", SourceName: "linux", SourceVersion: "5.15.0-100.110"},
	)
	h.Kernel = inventory.Kernel{SourceName: "linux-hwe-6.8", Version: "6.8.0-45.45~22.04.1"}
	f := only(t, h, fakeDB{
		"linux":         {rec(t, "linux", `{"id":"CVE-2026-1","affected":[{`+open()+`}]}`)},
		"linux-hwe-6.8": {rec(t, "linux-hwe-6.8", `{"id":"CVE-2026-2","affected":[{`+open()+`}]}`)},
	})
	if f.VulnID != "CVE-2026-2" || !f.Kernel || !reflect.DeepEqual(f.BinaryPackages, []string{"linux-image-6.8.0-45-generic"}) {
		t.Errorf("got %+v", f)
	}
}

func TestKernelNoImage(t *testing.T) {
	h := hostWith(pkgs("linux-libc-dev linux 6.1.0-1", "bash bash 5.2-1")...)
	res := run(t, h, fakeDB{
		"linux": {rec(t, "linux", `{"id":"CVE-2026-1","affected":[{`+open()+`}]}`)},
		"bash":  {rec(t, "bash", `{"id":"CVE-2026-2","affected":[{`+open()+`}]}`)},
	}, Options{})
	checkVulns(t, res.Findings, "bash/CVE-2026-2")
	if len(res.Warnings) != 0 {
		t.Errorf("a container got warnings: %v", res.Warnings)
	}
}

func TestKernelWithoutRecordsWarns(t *testing.T) {
	h := hostWith(inventory.Package{Name: "linux-image-6.12.1-amd64", Version: "6.12.1-1", SourceName: "linux-6.12", SourceVersion: "6.12.1-1", IsKernelImage: true})
	h.Kernel = inventory.Kernel{SourceName: "linux-6.12", Version: "6.12.1-1"}
	res := run(t, h, fakeDB{"linux": {rec(t, "linux", `{"id":"CVE-2026-1","affected":[{`+open()+`}]}`)}}, Options{})
	checkVulns(t, res.Findings)
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "linux-6.12") {
		t.Errorf("Warnings = %v", res.Warnings)
	}

	// It warns in partial runs too, whatever they cover.
	res = run(t, h, fakeDB{}, Options{Only: map[string]bool{"bash": true}})
	if len(res.Warnings) != 1 {
		t.Errorf("partial run: Warnings = %v", res.Warnings)
	}

	// A kernel whose every record is fixed has records, so nothing to warn about.
	res = run(t, h, fakeDB{"linux-6.12": {rec(t, "linux-6.12", `{"id":"CVE-2026-1","affected":[{`+fixedAt("6.12.0-1")+`}]}`)}}, Options{})
	checkVulns(t, res.Findings)
	if len(res.Warnings) != 0 {
		t.Errorf("Warnings = %v", res.Warnings)
	}
}

func TestMultipleSourceVersions(t *testing.T) {
	h := hostWith(pkgs("libfoo1 foo 1.0-1", "libfoo2 foo 2.0-1", "libfoo2-dev foo 2.0-1", "libfoo3 foo 3.0-1")...)
	db := fakeDB{"foo": {
		rec(t, "foo", `{"id":"CVE-2026-1","affected":[{`+fixedAt("2.5-1")+`}]}`),
		rec(t, "foo", `{"id":"CVE-2026-2","affected":[{`+fixedAt("1.5-1")+`}]}`),
		rec(t, "foo", `{"id":"CVE-2026-3","affected":[{`+open()+`}]}`),
		rec(t, "foo", `{"id":"CVE-2026-4","affected":[{"versions":["2.0-1"]}]}`),
	}}
	res := run(t, h, db, Options{})
	checkVulns(t, res.Findings, "foo/CVE-2026-1", "foo/CVE-2026-2", "foo/CVE-2026-3", "foo/CVE-2026-4")
	for _, tc := range []struct {
		installed, fixed string
		binaries         []string
	}{
		{"1.0-1", "2.5-1", []string{"libfoo1", "libfoo2", "libfoo2-dev"}},
		{"1.0-1", "1.5-1", []string{"libfoo1"}},
		{"1.0-1", "", []string{"libfoo1", "libfoo2", "libfoo2-dev", "libfoo3"}},
		{"2.0-1", "", []string{"libfoo2", "libfoo2-dev"}},
	} {
		f := res.Findings[0]
		res.Findings = res.Findings[1:]
		if f.InstalledVersion != tc.installed || f.FixedVersion != tc.fixed || !reflect.DeepEqual(f.BinaryPackages, tc.binaries) {
			t.Errorf("%s: installed %q fix %q binaries %v, want %+v", f.VulnID, f.InstalledVersion, f.FixedVersion, f.BinaryPackages, tc)
		}
	}
}

// The override applies per version: libfoo2 has the fix, libfoo1 does not.
func TestOverrideIsPerVersion(t *testing.T) {
	f := only(t, hostWith(pkgs("libfoo1 foo 1.0-1", "libfoo2 foo 2.0-1")...), fakeDB{"foo": {
		rec(t, "foo", `{"id":"DEBIAN-CVE-2026-1","affected":[{`+open()+`}]}`),
		rec(t, "foo", `{"id":"DSA-1","upstream":["CVE-2026-1"],"affected":[{`+fixedAt("1.5-1")+`}]}`),
	}})
	if f.InstalledVersion != "1.0-1" || f.FixedVersion != "1.5-1" || !reflect.DeepEqual(f.BinaryPackages, []string{"libfoo1"}) {
		t.Errorf("got %+v", f)
	}
}

// A binNMU's binary version carries +b1, but matching uses the source version:
// bash 5.2.15-2+b2 is built from 5.2.15-2, which a fix at 5.2.15-2+b1 would not
// otherwise be distinguishable from.
func TestBinNMUUsesSourceVersion(t *testing.T) {
	h := hostWith(inventory.Package{Name: "bash", Version: "5.2.15-2+b2", SourceName: "bash", SourceVersion: "5.2.15-2"})
	f := only(t, h, fakeDB{"bash": {rec(t, "bash", `{"id":"CVE-2026-1","affected":[{"versions":["5.2.15-2"],`+fixedAt("5.2.15-3")+`}]}`)}})
	if f.InstalledVersion != "5.2.15-2" {
		t.Errorf("InstalledVersion = %q", f.InstalledVersion)
	}
	// A version list naming the source version hits; the +b2 form would not.
	res := run(t, h, fakeDB{"bash": {rec(t, "bash", `{"id":"CVE-2026-1","affected":[{"versions":["5.2.15-2+b2"]}]}`)}}, Options{})
	checkVulns(t, res.Findings)
}

func TestIgnore(t *testing.T) {
	h := hostWith(pkgs("foo-bin foo 1.0", "libfoo1 foo 1.0", "bar bar 1.0", "baz baz 1.0")...)
	cve := func(pkg, id string) vulndb.Record {
		return rec(t, pkg, `{"id":"`+id+`","affected":[{`+open()+`}]}`)
	}
	db := fakeDB{
		"foo": {cve("foo", "CVE-2026-1"), cve("foo", "CVE-2026-2")},
		"bar": {cve("bar", "CVE-2026-3"), cve("bar", "CVE-2026-4")},
		"baz": {cve("baz", "DSA-1")},
	}
	for _, tc := range []struct {
		name   string
		ignore config.Ignore
		want   []string
	}{
		{"nothing", config.Ignore{}, []string{"bar/CVE-2026-3", "bar/CVE-2026-4", "baz/DSA-1", "foo/CVE-2026-1", "foo/CVE-2026-2"}},
		{"CVE, in any case", config.Ignore{CVEs: []string{"cve-2026-3"}}, []string{"bar/CVE-2026-4", "baz/DSA-1", "foo/CVE-2026-1", "foo/CVE-2026-2"}},
		{"non-CVE VulnID", config.Ignore{CVEs: []string{"DSA-1"}}, []string{"bar/CVE-2026-3", "bar/CVE-2026-4", "foo/CVE-2026-1", "foo/CVE-2026-2"}},
		{"source package", config.Ignore{Packages: []string{"foo"}}, []string{"bar/CVE-2026-3", "bar/CVE-2026-4", "baz/DSA-1"}},
		{"binary package", config.Ignore{Packages: []string{"libfoo1"}}, []string{"bar/CVE-2026-3", "bar/CVE-2026-4", "baz/DSA-1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkVulns(t, run(t, h, db, Options{Ignore: tc.ignore}).Findings, tc.want...)
		})
	}
}

func TestOnly(t *testing.T) {
	h := hostWith(pkgs("foo foo 1.0", "bar bar 1.0")...)
	cve := func(pkg, id string) vulndb.Record {
		return rec(t, pkg, `{"id":"`+id+`","affected":[{`+open()+`}]}`)
	}
	db := fakeDB{"foo": {cve("foo", "CVE-2026-1")}, "bar": {cve("bar", "CVE-2026-2")}}
	checkVulns(t, run(t, h, db, Options{Only: map[string]bool{"bar": true, "not-installed": true}}).Findings, "bar/CVE-2026-2")
	checkVulns(t, run(t, h, db, Options{Only: map[string]bool{}}).Findings)
	checkVulns(t, run(t, h, db, Options{Only: map[string]bool{"foo": false}}).Findings)
}

// Only names a kernel source, still at the running version alone.
func TestOnlyKernel(t *testing.T) {
	f := run(t, kernelHost(), fakeDB{"linux": {rec(t, "linux", `{"id":"CVE-2026-1","affected":[{`+open()+`}]}`)}}, Options{Only: map[string]bool{"linux": true}}).Findings
	if len(f) != 1 || f[0].InstalledVersion != "6.8.0-45.45" {
		t.Errorf("got %+v", f)
	}
}

func TestEnrichment(t *testing.T) {
	added := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	h := hostWith(pkgs("foo foo 1.0")...)
	db := fakeDB{"foo": {
		rec(t, "foo", `{"id":"CVE-2026-1","affected":[{`+open()+`}]}`),
		rec(t, "foo", `{"id":"DSA-1","affected":[{`+open()+`}]}`),
	}}
	lookup := recordingLookup{info: enrich.Info{KEV: true, KEVDateAdded: added, EPSS: 0.5, EPSSPercentile: 0.9}}
	res, err := Match(context.Background(), h, db, &lookup, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(lookup.asked, []string{"CVE-2026-1"}) {
		t.Errorf("asked about %v, want only the CVE", lookup.asked)
	}
	f := res.Findings[0]
	if !f.KEV || f.KEVDateAdded == nil || !f.KEVDateAdded.Equal(added) || f.EPSS != 0.5 || f.EPSSPercentile != 0.9 {
		t.Errorf("got %+v", f)
	}
	if g := res.Findings[1]; g.KEV || g.EPSS != 0 {
		t.Errorf("DSA-1 was enriched: %+v", g)
	}
}

type recordingLookup struct {
	info  enrich.Info
	asked []string
	err   error
}

func (l *recordingLookup) Lookup(cve string) (enrich.Info, error) {
	l.asked = append(l.asked, cve)
	return l.info, l.err
}

func TestErrorsPropagate(t *testing.T) {
	h := hostWith(pkgs("foo foo 1.0")...)
	db := fakeDB{"foo": {rec(t, "foo", `{"id":"CVE-2026-1","affected":[{`+open()+`}]}`)}}
	boom := errors.New("boom")
	if _, err := Match(context.Background(), h, db, &recordingLookup{err: boom}, Options{}); !errors.Is(err, boom) {
		t.Errorf("lookup error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Match(ctx, h, db, fakeLookup{}, Options{}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

func TestDeterministic(t *testing.T) {
	h := kernelHost()
	h.Packages = append(h.Packages, pkgs("zed zed 1.0", "alpha alpha 1.0", "alpha2 alpha 2.0")...)
	db := fakeDB{
		"zed":   {rec(t, "zed", `{"id":"CVE-2026-9","affected":[{`+open()+`}]}`)},
		"alpha": {rec(t, "alpha", `{"id":"USN-2","summary":"b","upstream":["CVE-2026-2","CVE-2026-1"],"affected":[{`+fixedAt("3.0")+`}]}`), rec(t, "alpha", `{"id":"USN-1","summary":"a","upstream":["CVE-2026-1","CVE-2026-2"],"affected":[{`+fixedAt("3.0")+`}]}`)},
		"linux": {rec(t, "linux", `{"id":"CVE-2026-5","affected":[{`+open()+`}]}`)},
	}
	first := run(t, h, db, Options{})
	checkVulns(t, first.Findings, "alpha/CVE-2026-1", "alpha/CVE-2026-2", "linux/CVE-2026-5", "zed/CVE-2026-9")
	if s := first.Findings[0].Summary; s != "a" {
		t.Errorf("Summary = %q, want the lowest ID's", s)
	}
	for range 20 {
		if again := run(t, h, db, Options{}); !reflect.DeepEqual(first, again) {
			t.Fatalf("results differ:\n%+v\n%+v", first, again)
		}
	}
}
