package match

import (
	"log/slog"
	"strings"

	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// nonBaseCVSS4 lists the CVSS 4.0 threat and environmental metrics. Real vectors
// spell them out, mostly as X, and go-cvss scores what is set.
var nonBaseCVSS4 = []string{
	"E", "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
}

// baseScore returns a vector's CVSS base score. An unparseable vector is logged
// at debug and gives false: bad upstream data must not fail a scan.
func baseScore(recordID, vector string) (float64, bool) {
	var score float64
	var err error
	switch {
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		var v *gocvss31.CVSS31
		if v, err = gocvss31.ParseVector(vector); err == nil {
			score = v.BaseScore()
		}
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		var v *gocvss30.CVSS30
		if v, err = gocvss30.ParseVector(vector); err == nil {
			score = v.BaseScore()
		}
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		var v *gocvss40.CVSS40
		if v, err = gocvss40.ParseVector(vector); err == nil {
			for _, metric := range nonBaseCVSS4 {
				if err = v.Set(metric, "X"); err != nil {
					break
				}
			}
		}
		if err == nil {
			score = v.Score()
		}
	default:
		slog.Debug("unsupported severity vector", "record", recordID, "vector", vector)
		return 0, false
	}
	if err != nil {
		slog.Debug("unparseable severity vector", "record", recordID, "vector", vector, "error", err)
		return 0, false
	}
	return score, true
}

// labelRanks orders distro ratings. Ubuntu priorities and Debian urgencies share
// the common words. A word not listed ranks below all of these.
var labelRanks = map[string]int{
	"critical":    7,
	"high":        6,
	"medium":      5,
	"low":         4,
	"negligible":  3,
	"end-of-life": 2,
	"unimportant": 1,
}

// normalizeLabel lower-cases a distro rating. "not yet assigned", Debian's most
// common urgency, means no rating at all. An `unimportant` label is kept: what
// to do about it is policy.
func normalizeLabel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "not yet assigned" {
		return ""
	}
	return s
}

// strongerLabel returns the stronger of two labels, independently of their order.
func strongerLabel(a, b string) string {
	ra, rb := labelRanks[a], labelRanks[b]
	switch {
	case a == "":
		return b
	case b == "":
		return a
	case ra != rb:
		if ra > rb {
			return a
		}
		return b
	case a < b:
		return a
	}
	return b
}
