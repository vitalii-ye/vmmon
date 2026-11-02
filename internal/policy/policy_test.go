package policy

import (
	"testing"

	"github.com/vitalii-ye/vmmon/internal/config"
	"github.com/vitalii-ye/vmmon/internal/finding"
)

func TestAlert(t *testing.T) {
	fix := finding.FixAvailable
	no := finding.NoFixYet
	for _, tc := range []struct {
		name                  string
		f                     finding.Finding
		quiet, critical, ever bool
	}{
		{"KEV without a fix", finding.Finding{KEV: true, FixStatus: no}, true, true, true},
		{"KEV and unimportant", finding.Finding{KEV: true, FixStatus: no, SeverityLabel: "unimportant"}, true, true, true},
		{"fix, CVSS at threshold", finding.Finding{FixStatus: fix, CVSSScore: 7}, true, false, true},
		{"fix, CVSS below", finding.Finding{FixStatus: fix, CVSSScore: 6.9}, false, false, true},
		{"fix, EPSS at threshold", finding.Finding{FixStatus: fix, EPSS: 0.1}, true, false, true},
		{"fix, EPSS below", finding.Finding{FixStatus: fix, EPSS: 0.09}, false, false, true},
		{"no fix, high CVSS", finding.Finding{FixStatus: no, CVSSScore: 9.8}, false, false, true},
		{"fix, high CVSS, unimportant", finding.Finding{FixStatus: fix, CVSSScore: 9.8, SeverityLabel: "unimportant"}, false, false, true},
		{"fix, high EPSS, end-of-life", finding.Finding{FixStatus: fix, EPSS: 0.9, SeverityLabel: "end-of-life"}, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check := func(preset string, want bool) {
				t.Helper()
				cfg := config.Default().Policy
				cfg.Preset = preset
				if got := New(cfg).Alert(&tc.f); got != want {
					t.Errorf("%s: Alert = %v, want %v", preset, got, want)
				}
			}
			check(config.PresetQuiet, tc.quiet)
			check(config.PresetCritical, tc.critical)
			check(config.PresetEverything, tc.ever)
		})
	}
}

func TestThresholdsComeFromConfig(t *testing.T) {
	p := New(config.Policy{Preset: config.PresetQuiet, MinCVSS: 9, MinEPSS: 0.5})
	if p.Alert(&finding.Finding{FixStatus: finding.FixAvailable, CVSSScore: 8, EPSS: 0.4}) {
		t.Error("below the configured thresholds should not alert")
	}
	if !p.Alert(&finding.Finding{FixStatus: finding.FixAvailable, CVSSScore: 9}) {
		t.Error("at the configured CVSS threshold should alert")
	}
}

func TestWeeklyDigest(t *testing.T) {
	for preset, want := range map[string]bool{config.PresetQuiet: false, config.PresetCritical: true, config.PresetEverything: false} {
		if got := New(config.Policy{Preset: preset}).WeeklyDigest(); got != want {
			t.Errorf("%s: WeeklyDigest = %v, want %v", preset, got, want)
		}
	}
}
