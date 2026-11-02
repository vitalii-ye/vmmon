package notify

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vitalii-ye/vmmon/internal/finding"
)

func renderVuln(pkg, cve string) finding.Finding {
	return finding.Finding{
		ID: pkg + cve, SourcePackage: pkg, VulnID: cve, InstalledVersion: "1.0-1",
		FixStatus: finding.FixAvailable, FixedVersion: "1.1-1", CVSSScore: 7.8,
	}
}

func TestRenderAlertFollowsThePlan(t *testing.T) {
	kev := renderVuln("openssl", "CVE-2026-1")
	kev.KEV, kev.EPSS = true, 0.42
	kernel := renderVuln("linux", "CVE-2026-2")
	kernel.Kernel, kernel.RebootRequired = true, true
	got := RenderAlert("web-01", []finding.Finding{kernel, kev})
	for _, want := range []string{
		"🔴 <b>web-01</b> · 2 new vulnerabilities",
		"openssl 1.0-1 → fix 1.1-1",
		"CVE-2026-1 · KEV · CVSS 7.8 · EPSS 0.42",
		"reboot required",
		"sudo apt upgrade",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Index(got, "openssl") > strings.Index(got, "linux") {
		t.Errorf("KEV should come first:\n%s", got)
	}
}

func TestRenderEscapesEverythingFromData(t *testing.T) {
	evil := `<script>&"`
	f := renderVuln(evil, evil)
	f.InstalledVersion, f.FixedVersion = evil, evil
	f.KEV = true
	messages := map[string]string{
		"alert":      RenderAlert(evil, []finding.Finding{f}),
		"escalation": RenderEscalation(evil, []Escalation{{Finding: f, NewKEV: true}}),
		"summary":    RenderSummary(evil, Summary{KEV: []finding.Finding{f}, Warnings: []string{evil}}),
		"digest":     RenderDigest(evil, Digest{KEV: []finding.Finding{f}, Resolved: []finding.Finding{f}, Warnings: []string{evil}}),
		"stale":      RenderStale(evil, Stale{LastError: evil}),
		"dropped":    RenderDropped(evil, 2),
	}
	for name, got := range messages {
		if strings.Contains(got, "<script>") {
			t.Errorf("%s not escaped:\n%s", name, got)
		}
	}
}

func TestRenderStaysBounded(t *testing.T) {
	var fs []finding.Finding
	for i := range 12000 {
		f := renderVuln(fmt.Sprintf("pkg%d", i%400), fmt.Sprintf("CVE-2026-%d", i))
		f.KEV = i%2 == 0
		fs = append(fs, f)
	}
	es := make([]Escalation, len(fs))
	for i := range fs {
		es[i] = Escalation{Finding: fs[i], NewKEV: true}
	}
	messages := map[string]string{
		"alert":      RenderAlert("h", fs),
		"escalation": RenderEscalation("h", es),
		"summary":    RenderSummary("h", Summary{Counts: finding.Count(fs), KEV: fs}),
		"digest":     RenderDigest("h", Digest{Open: finding.Count(fs), KEV: fs, Resolved: fs, Now: time.Unix(100, 0)}),
	}
	for name, got := range messages {
		if len(got) > 4096 {
			t.Errorf("%s is %d bytes", name, len(got))
		}
		if !strings.Contains(got, "more") {
			t.Errorf("%s does not say the list is cut:\n%s", name, got)
		}
	}
}

func TestRenderStaleSaysWhy(t *testing.T) {
	now := time.Unix(1000000, 0)
	got := RenderStale("h", Stale{LastSync: now.Add(-49 * time.Hour), Now: now, LastError: "connection refused"})
	if !strings.Contains(got, "connection refused") || !strings.Contains(got, "ago") {
		t.Errorf("got %q", got)
	}
	got = RenderStale("h", Stale{Since: now.Add(-49 * time.Hour), Now: now})
	if !strings.Contains(got, "has not synced") {
		t.Errorf("never synced: %q", got)
	}
}
