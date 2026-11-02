// Package policy decides which findings alert immediately and how often the
// digest goes out.
package policy

import (
	"github.com/vitalii-ye/vmmon/internal/config"
	"github.com/vitalii-ye/vmmon/internal/finding"
)

// Policy is one preset with its thresholds.
type Policy struct {
	preset  string
	minCVSS float64
	minEPSS float64
}

// New returns the policy cfg selects. config.Policy.Ignore is not used here:
// matching already applied it.
func New(cfg config.Policy) Policy {
	return Policy{preset: cfg.Preset, minCVSS: cfg.MinCVSS, minEPSS: cfg.MinEPSS}
}

// Alert reports whether f warrants an immediate alert. The CVSS score is a base
// score on purpose: exploitation evidence comes from KEV and EPSS.
func (p Policy) Alert(f *finding.Finding) bool {
	switch p.preset {
	case config.PresetEverything:
		return true
	case config.PresetCritical:
		return f.KEV
	}
	if f.KEV {
		return true
	}
	if f.SeverityLabel == "unimportant" || f.SeverityLabel == "end-of-life" {
		return false
	}
	return f.FixStatus == finding.FixAvailable && (f.CVSSScore >= p.minCVSS || f.EPSS >= p.minEPSS)
}

// WeeklyDigest reports whether the digest is weekly rather than daily.
func (p Policy) WeeklyDigest() bool { return p.preset == config.PresetCritical }
