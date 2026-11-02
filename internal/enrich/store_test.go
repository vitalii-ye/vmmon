package enrich

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vitalii-ye/vmmon/internal/vulndb"
)

const kevBody = `{"title":"t","catalogVersion":"2026.10.30","count":2,"vulnerabilities":[
 {"cveID":"CVE-2024-0002","vendorProject":"x","dateAdded":"2024-02-02","notes":"long"},
 {"cveID":"CVE-2024-0001","dateAdded":"2024-01-01"}]}`

const epssBody = `#model_version:v2026.06.15,score_date:2026-11-02T12:00:30Z
cve,epss,percentile
CVE-2024-0001,0.5,0.75
CVE-2024-0003,0.04753,0.91883
`

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write([]byte(s))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// feeds serves the two feeds. A nil body gives HTTP 500.
type feeds struct {
	mu   sync.Mutex
	kev  []byte
	epss []byte
}

func (f *feeds) set(kev, epss []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kev, f.epss = kev, epss
}

func newStore(t *testing.T, f *feeds) (*Store, string) {
	t.Helper()
	mux := http.NewServeMux()
	serve := func(get func() []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			f.mu.Lock()
			body := get()
			f.mu.Unlock()
			if body == nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Write(body)
		}
	}
	mux.HandleFunc("/kev.json", serve(func() []byte { return f.kev }))
	mux.HandleFunc("/epss-today.csv.gz", serve(func() []byte { return f.epss }))
	// The real EPSS URL answers with a relative redirect.
	mux.Handle("/epss.csv.gz", http.RedirectHandler("epss-today.csv.gz", http.StatusFound))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	dir := filepath.Join(t.TempDir(), "db")
	return New(dir, Options{
		KEVURL:   srv.URL + "/kev.json",
		EPSSURL:  srv.URL + "/epss.csv.gz",
		Download: vulndb.DownloadOptions{Retries: 1, RetryDelay: time.Millisecond},
	}), dir
}

func lookupOne(t *testing.T, s *Store, cve string) Info {
	t.Helper()
	var info Info
	err := s.View(context.Background(), func(l Lookup) error {
		var err error
		info, err = l.Lookup(cve)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func noTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("leftover temp file %s", e.Name())
		}
	}
}

func TestSyncAndLookup(t *testing.T) {
	f := &feeds{kev: []byte(kevBody), epss: gz(t, epssBody)}
	s, dir := newStore(t, f)
	ch, err := s.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !ch.KEVChanged || !ch.EPSSUpdated || !slices.Equal(ch.NewKEV, []string{"CVE-2024-0001", "CVE-2024-0002"}) {
		t.Fatalf("changes: %+v", ch)
	}

	got := lookupOne(t, s, "cve-2024-0001") // case-insensitive
	want := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	if !got.KEV || !got.KEVDateAdded.Equal(want) || got.EPSS != 0.5 || got.EPSSPercentile != 0.75 {
		t.Fatalf("info: %+v", got)
	}
	if got := lookupOne(t, s, "CVE-2024-0003"); got.KEV || got.EPSS != 0.04753 || got.EPSSPercentile != 0.91883 {
		t.Fatalf("EPSS only: %+v", got)
	}
	if got := lookupOne(t, s, "CVE-2024-0002"); !got.KEV || got.EPSS != 0 {
		t.Fatalf("KEV only: %+v", got)
	}
	if got := lookupOne(t, s, "CVE-1999-9999"); got != (Info{}) {
		t.Fatalf("unknown: %+v", got)
	}

	m, err := vulndb.ReadMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m.KEV.Records != 2 || m.KEV.Version != "2026.10.30" || m.KEV.LastSync.IsZero() || m.KEV.LastError != "" {
		t.Fatalf("KEV meta: %+v", m.KEV)
	}
	if m.EPSS.Records != 2 || m.EPSS.Version != "2026-11-02T12:00:30Z" || m.EPSS.SHA256 == "" {
		t.Fatalf("EPSS meta: %+v", m.EPSS)
	}
	noTemps(t, dir)

	data, err := os.ReadFile(filepath.Join(dir, kevFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "vendorProject") {
		t.Fatalf("kev.json keeps free text: %s", data)
	}
}

func TestSecondSyncReportsOnlyChanges(t *testing.T) {
	f := &feeds{kev: []byte(kevBody), epss: gz(t, epssBody)}
	s, dir := newStore(t, f)
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, epssFile))
	if err != nil {
		t.Fatal(err)
	}

	ch, err := s.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ch.KEVChanged || ch.EPSSUpdated || len(ch.NewKEV) != 0 {
		t.Fatalf("unchanged feeds: %+v", ch)
	}
	again, _ := os.Stat(filepath.Join(dir, epssFile))
	if !os.SameFile(info, again) {
		t.Fatal("rebuilt epss.bolt for an identical file")
	}
	if m, _ := vulndb.ReadMeta(dir); m.EPSS.Records != 2 || m.EPSS.SHA256 == "" {
		t.Fatalf("meta lost on no-op: %+v", m.EPSS)
	}

	f.set([]byte(`{"catalogVersion":"2","vulnerabilities":[
		{"cveID":"CVE-2024-0001","dateAdded":"2024-01-01"},
		{"cveID":"CVE-2024-0002","dateAdded":"2024-02-02"},
		{"cveID":"cve-2025-0009","dateAdded":"2025-03-03"}]}`),
		gz(t, "#model_version:v2,score_date:2026-11-03T00:00:00Z\ncve,epss,percentile\nCVE-2024-0001,0.9,0.99\n"))
	ch, err = s.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !ch.KEVChanged || !ch.EPSSUpdated || !slices.Equal(ch.NewKEV, []string{"CVE-2025-0009"}) {
		t.Fatalf("changes: %+v", ch)
	}
	if got := lookupOne(t, s, "CVE-2024-0001"); got.EPSS != 0.9 {
		t.Fatalf("not replaced: %+v", got)
	}
	if got := lookupOne(t, s, "CVE-2024-0003"); got.EPSS != 0 {
		t.Fatalf("stale row kept: %+v", got)
	}

	// Removal from the catalog is a change too, though nothing is new.
	f.set([]byte(`{"catalogVersion":"3","vulnerabilities":[{"cveID":"CVE-2024-0001","dateAdded":"2024-01-01"}]}`), f.epss)
	ch, err = s.Sync(context.Background())
	if err != nil || !ch.KEVChanged || len(ch.NewKEV) != 0 {
		t.Fatalf("removal: %+v, %v", ch, err)
	}
}

func TestFeedsFailIndependently(t *testing.T) {
	for name, tc := range map[string]struct {
		kev, epss          []byte
		wantErr            string
		wantKEVOK, wantEOK bool
	}{
		"kev down":    {nil, gz(t, epssBody), "KEV", false, true},
		"epss down":   {[]byte(kevBody), nil, "EPSS", true, false},
		"kev garbage": {[]byte("<html>"), gz(t, epssBody), "KEV", false, true},
		"kev empty":   {[]byte(`{"vulnerabilities":[]}`), gz(t, epssBody), "KEV", false, true},
		"not gzip":    {[]byte(kevBody), []byte("not gzip"), "EPSS", true, false},
		"truncated":   {[]byte(kevBody), gz(t, epssBody)[:30], "EPSS", true, false},
		"bad header":  {[]byte(kevBody), gz(t, "a,b,c\n1,2,3\n"), "EPSS", true, false},
		"bad row":     {[]byte(kevBody), gz(t, "cve,epss,percentile\nCVE-1,oops,0.1\n"), "EPSS", true, false},
		"bad range":   {[]byte(kevBody), gz(t, "cve,epss,percentile\nCVE-1,7,0.1\n"), "EPSS", true, false},
		"no rows":     {[]byte(kevBody), gz(t, "#c\ncve,epss,percentile\n"), "EPSS", true, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := &feeds{kev: tc.kev, epss: tc.epss}
			s, dir := newStore(t, f)
			_, err := s.Sync(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v", err)
			}
			m, _ := vulndb.ReadMeta(dir)
			if tc.wantKEVOK != (m.KEV.LastError == "") || tc.wantKEVOK == m.KEV.LastSync.IsZero() {
				t.Fatalf("KEV meta: %+v", m.KEV)
			}
			if tc.wantEOK != (m.EPSS.LastError == "") || tc.wantEOK == m.EPSS.LastSync.IsZero() {
				t.Fatalf("EPSS meta: %+v", m.EPSS)
			}
			if got := lookupOne(t, s, "CVE-2024-0001"); got.KEV != tc.wantKEVOK || (got.EPSS != 0) != tc.wantEOK {
				t.Fatalf("lookup: %+v", got)
			}
			noTemps(t, dir)
		})
	}
}

func TestFailureKeepsPreviousData(t *testing.T) {
	f := &feeds{kev: []byte(kevBody), epss: gz(t, epssBody)}
	s, dir := newStore(t, f)
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.set([]byte("broken"), gz(t, "cve,epss,percentile\nCVE-1,bad,bad\n"))
	if _, err := s.Sync(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if got := lookupOne(t, s, "CVE-2024-0001"); !got.KEV || got.EPSS != 0.5 {
		t.Fatalf("lost data: %+v", got)
	}
	m, _ := vulndb.ReadMeta(dir)
	if m.KEV.Records != 2 || m.EPSS.Records != 2 || m.KEV.LastError == "" || m.EPSS.LastError == "" {
		t.Fatalf("meta: %+v", m)
	}
}

func TestViewWithoutData(t *testing.T) {
	s, _ := newStore(t, &feeds{})
	if got := lookupOne(t, s, "CVE-2024-0001"); got != (Info{}) {
		t.Fatalf("info: %+v", got)
	}
}

func TestSyncDoesNotDisturbVulndbMeta(t *testing.T) {
	f := &feeds{kev: []byte(kevBody), epss: gz(t, epssBody)}
	s, dir := newStore(t, f)
	err := vulndb.UpdateMeta(dir, func(m *vulndb.Meta) {
		m.Ecosystems["Debian:12"] = vulndb.EcosystemMeta{Records: 7}
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m, _ := vulndb.ReadMeta(dir); m.Ecosystems["Debian:12"].Records != 7 || m.KEV.Records != 2 {
		t.Fatalf("meta: %+v", m)
	}
}

func TestConcurrentSyncRefused(t *testing.T) {
	s, dir := newStore(t, &feeds{})
	if err := vulndb.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	unlock, err := vulndb.TryLock(filepath.Join(dir, "enrich.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := s.Sync(context.Background()); !errors.Is(err, vulndb.ErrSyncInProgress) {
		t.Fatalf("err = %v", err)
	}
}

func TestLargeFeedIsStreamed(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("#model_version:v1,score_date:2026-11-02T00:00:00Z\ncve,epss,percentile\n")
	for i := range 3*epssBatch + 5 {
		fmt.Fprintf(&sb, "CVE-2024-%d,0.1,0.2\n", i)
	}
	f := &feeds{kev: []byte(kevBody), epss: gz(t, sb.String())}
	s, dir := newStore(t, f)
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m, _ := vulndb.ReadMeta(dir); m.EPSS.Records != 3*epssBatch+5 {
		t.Fatalf("records = %d", m.EPSS.Records)
	}
	if got := lookupOne(t, s, fmt.Sprintf("CVE-2024-%d", 3*epssBatch+4)); got.EPSS != 0.1 {
		t.Fatalf("last row: %+v", got)
	}
}
