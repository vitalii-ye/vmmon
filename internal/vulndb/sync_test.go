package vulndb

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const eco12 = "Debian:12"

// fakeOSV serves all.zip, modified_id.csv and single records for one root.
type fakeOSV struct {
	t *testing.T
	*httptest.Server

	mu      sync.Mutex
	records map[string]fakeRecord
	zipHook func(w http.ResponseWriter, r *http.Request) bool
	recHook func(w http.ResponseWriter, id string) bool
	zipGets int
	recGets int
}

type fakeRecord struct {
	modified time.Time
	body     []byte
}

func newFake(t *testing.T) *fakeOSV {
	f := &fakeOSV{t: t, records: map[string]fakeRecord{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeOSV) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name, ok := strings.CutPrefix(r.URL.Path, "/Debian/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch {
	case name == "all.zip":
		f.zipGets++
		if f.zipHook != nil {
			hook := f.zipHook
			f.mu.Unlock()
			handled := hook(w, r)
			f.mu.Lock()
			if handled {
				return
			}
		}
		http.ServeContent(w, r, "all.zip", time.Time{}, bytes.NewReader(f.zipLocked()))
	case name == "modified_id.csv":
		fmt.Fprint(w, f.csvLocked())
	default:
		id := strings.TrimSuffix(name, ".json")
		f.recGets++
		if f.recHook != nil && f.recHook(w, id) {
			return
		}
		rec, ok := f.records[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(rec.body)
	}
}

func (f *fakeOSV) zipLocked() []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, id := range slices.Sorted(mapsKeys(f.records)) {
		w, err := zw.Create(id + ".json")
		if err != nil {
			f.t.Fatal(err)
		}
		w.Write(f.records[id].body)
	}
	if err := zw.Close(); err != nil {
		f.t.Fatal(err)
	}
	return buf.Bytes()
}

func mapsKeys(m map[string]fakeRecord) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func (f *fakeOSV) csvLocked() string {
	ids := slices.Collect(mapsKeys(f.records))
	sort.Slice(ids, func(i, j int) bool {
		a, b := f.records[ids[i]].modified, f.records[ids[j]].modified
		if a.Equal(b) {
			return ids[i] < ids[j]
		}
		return a.After(b)
	})
	var sb strings.Builder
	for _, id := range ids {
		fmt.Fprintf(&sb, "%s,%s\n", f.records[id].modified.Format(time.RFC3339Nano), id)
	}
	return sb.String()
}

// set adds or replaces a record built from "ecosystem/package" entries.
func (f *fakeOSV) set(id string, modified time.Time, entries ...string) {
	f.t.Helper()
	f.setRaw(id, modified, recordJSON(f.t, id, modified, nil, entries...))
}

func (f *fakeOSV) setRaw(id string, modified time.Time, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[id] = fakeRecord{modified: modified, body: body}
}

func (f *fakeOSV) withdraw(id string, modified time.Time, entries ...string) {
	f.t.Helper()
	f.setRaw(id, modified, recordJSON(f.t, id, modified, &modified, entries...))
}

func (f *fakeOSV) delete(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.records, id)
}

func (f *fakeOSV) gets() (zips, recs int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.zipGets, f.recGets
}

func (f *fakeOSV) hooks(zipHook func(http.ResponseWriter, *http.Request) bool, recHook func(http.ResponseWriter, string) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.zipHook, f.recHook = zipHook, recHook
}

func recordJSON(t *testing.T, id string, modified time.Time, withdrawn *time.Time, entries ...string) []byte {
	t.Helper()
	var affected []map[string]any
	for _, e := range entries {
		eco, name, ok := strings.Cut(e, "/")
		if !ok {
			t.Fatalf("bad entry %q", e)
		}
		affected = append(affected, map[string]any{
			"package": map[string]string{"name": name, "ecosystem": eco},
			"ranges": []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{
				{"introduced": "0"}, {"fixed": "1.2-3"},
			}}},
			"versions":           []string{"1.0-1", "1.1-1"},
			"ecosystem_specific": map[string]any{"urgency": "high", "binaries": []string{"dropped-binary"}},
		})
	}
	m := map[string]any{"id": id, "modified": modified, "upstream": []string{"CVE-2026-1"}, "affected": affected}
	if withdrawn != nil {
		m["withdrawn"] = *withdrawn
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testStore(t *testing.T, f *fakeOSV, change ...func(*Options)) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "db")
	return storeIn(t, dir, f, change...), dir
}

func storeIn(t *testing.T, dir string, f *fakeOSV, change ...func(*Options)) *Store {
	t.Helper()
	opts := Options{
		Ecosystem:           eco12,
		Root:                "Debian",
		BaseURL:             f.URL,
		FullSyncThreshold:   10,
		FullRefreshInterval: 7 * 24 * time.Hour,
		Download:            DownloadOptions{Retries: 2, RetryDelay: time.Millisecond, IdleTimeout: 5 * time.Second},
	}
	for _, c := range change {
		c(&opts)
	}
	s, err := New(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustSync(t *testing.T, s *Store, opts SyncOptions) SyncResult {
	t.Helper()
	res, err := s.Sync(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func recordIDs(t *testing.T, s *Store, pkg string) []string {
	t.Helper()
	ids := []string{}
	err := s.View(context.Background(), func(r Reader) error {
		recs, err := r.RecordsFor(pkg)
		for _, rec := range recs {
			ids = append(ids, rec.ID)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func wantStrings(t *testing.T, name string, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) && (len(got) != 0 || len(want) != 0) {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
}

func assertNoTemps(t *testing.T, dir string) {
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

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 123456789, time.UTC)

func TestFullFiltersByRelease(t *testing.T) {
	f := newFake(t)
	f.set("DSA-1", t0, "Debian:12/openssl", "Debian:13/openssl", "Debian:11/curl")
	f.set("DSA-2", t0, "Debian:13/nginx")
	f.withdraw("DSA-3", t0, "Debian:12/openssl")
	f.set("DSA-4", t0, "Debian:12/openssl", "Debian:12/curl")
	s, dir := testStore(t, f)

	res := mustSync(t, s, SyncOptions{})
	if res.Mode != "full" || res.Records != 2 || res.Packages != 2 {
		t.Fatalf("unexpected result: %+v", res)
	}
	wantStrings(t, "changed", res.ChangedPackages, "curl", "openssl")
	wantStrings(t, "openssl", recordIDs(t, s, "openssl"), "DSA-1", "DSA-4")
	wantStrings(t, "curl", recordIDs(t, s, "curl"), "DSA-4")
	wantStrings(t, "nginx", recordIDs(t, s, "nginx"))

	if filepath.Base(s.Path()) != "Debian_12.bolt" {
		t.Fatalf("path = %s", s.Path())
	}
	assertNoTemps(t, dir)

	err := s.View(context.Background(), func(r Reader) error {
		recs, err := r.RecordsFor("openssl")
		if err != nil {
			return err
		}
		rec := recs[0]
		if len(rec.Affected) != 1 || rec.Affected[0].Package.Ecosystem != eco12 {
			t.Fatalf("other releases kept: %+v", rec.Affected)
		}
		curl, err := r.RecordsFor("curl")
		if err != nil {
			return err
		}
		if len(curl[0].Affected) != 1 || curl[0].Affected[0].Package.Name != "curl" {
			t.Fatalf("other packages kept: %+v", curl[0].Affected)
		}
		a := rec.Affected[0]
		if a.EcosystemSpecific.Urgency != "high" || len(a.Versions) != 2 || a.Ranges[0].Events[1].Fixed != "1.2-3" {
			t.Fatalf("fields lost: %+v", a)
		}
		if !rec.Modified.Equal(t0) || rec.Upstream[0] != "CVE-2026-1" {
			t.Fatalf("fields lost: %+v", rec)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	st, err := s.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Synced || st.Records != 2 || st.Packages != 2 || st.Size == 0 || st.LastError != "" {
		t.Fatalf("status: %+v", st)
	}
}

func TestProFilter(t *testing.T) {
	const eco = "Ubuntu:24.04:LTS"
	f := newFake(t)
	f.set("USN-1", t0, eco+"/openssl", "Ubuntu:Pro:24.04:LTS/openssl", "Ubuntu:Pro:22.04:LTS/curl")
	f.set("USN-2", t0, "Ubuntu:Pro:24.04:LTS/nginx")
	debianRoot := func(o *Options) { o.Ecosystem = eco }
	plain, dir := testStore(t, f, debianRoot)
	mustSync(t, plain, SyncOptions{})
	wantStrings(t, "nginx without pro", recordIDs(t, plain, "nginx"))
	if filepath.Base(plain.Path()) != "Ubuntu_24.04_LTS.bolt" {
		t.Fatalf("path = %s", plain.Path())
	}

	// Turning Pro on rebuilds the index without being asked, and reports it.
	pro := storeIn(t, dir, f, debianRoot, func(o *Options) { o.UbuntuPro = true })
	res := mustSync(t, pro, SyncOptions{})
	if res.Mode != "full" || res.FullReason != "filter changed" {
		t.Fatalf("result: %+v", res)
	}
	wantStrings(t, "changed", res.ChangedPackages, "nginx", "openssl")
	wantStrings(t, "nginx with pro", recordIDs(t, pro, "nginx"), "USN-2")
	wantStrings(t, "22.04 pro stays out", recordIDs(t, pro, "curl"))

	// Turned off again, reads hide Pro entries even before the next sync.
	wantStrings(t, "nginx hidden", recordIDs(t, plain, "nginx"))
}

func TestFailedDownloadKeepsOldDB(t *testing.T) {
	f := newFake(t)
	f.set("DSA-1", t0, eco12+"/openssl")
	s, dir := testStore(t, f)
	mustSync(t, s, SyncOptions{})

	f.set("DSA-2", t0.Add(time.Hour), eco12+"/curl")
	f.hooks(func(w http.ResponseWriter, _ *http.Request) bool {
		// Promise more than is sent, so the client sees a truncated body.
		w.Header().Set("Content-Length", "100000")
		w.Write([]byte("PK partial"))
		return true
	}, nil)
	_, err := s.Sync(context.Background(), SyncOptions{Full: true})
	if err == nil {
		t.Fatal("want error")
	}
	wantStrings(t, "old data", recordIDs(t, s, "openssl"), "DSA-1")
	wantStrings(t, "no new data", recordIDs(t, s, "curl"))
	assertNoTemps(t, dir)

	st, _ := s.Status()
	if st.LastError == "" || !st.Synced || st.LastAttempt.IsZero() {
		t.Fatalf("status: %+v", st)
	}

	f.hooks(nil, nil)
	mustSync(t, s, SyncOptions{Full: true})
	st, _ = s.Status()
	if st.LastError != "" {
		t.Fatalf("error not cleared: %+v", st)
	}
	wantStrings(t, "new data", recordIDs(t, s, "curl"), "DSA-2")
}

func TestDownloadResumesWithRange(t *testing.T) {
	f := newFake(t)
	for i := range 50 {
		f.set(fmt.Sprintf("DSA-%d", i), t0, eco12+"/openssl")
	}
	var ranges []string
	var mu sync.Mutex
	first := true
	f.hooks(func(w http.ResponseWriter, r *http.Request) bool {
		mu.Lock()
		defer mu.Unlock()
		if v := r.Header.Get("Range"); v != "" {
			ranges = append(ranges, v)
		}
		if first {
			first = false
			f.mu.Lock()
			z := f.zipLocked()
			f.mu.Unlock()
			w.Header().Set("Content-Length", fmt.Sprint(len(z)))
			w.Write(z[:len(z)/2])
			w.(http.Flusher).Flush()
			return true
		}
		return false
	}, nil)
	s, _ := testStore(t, f)
	res := mustSync(t, s, SyncOptions{})
	if res.Records != 50 {
		t.Fatalf("records = %d", res.Records)
	}
	if len(ranges) != 1 || !strings.HasPrefix(ranges[0], "bytes=") || ranges[0] == "bytes=0-" {
		t.Fatalf("ranges = %v", ranges)
	}
}

func TestDownloadRecoversFromStall(t *testing.T) {
	f := newFake(t)
	f.set("DSA-1", t0, eco12+"/openssl")
	var calls atomic.Int32
	stop := make(chan struct{})
	defer close(stop)
	f.hooks(func(w http.ResponseWriter, _ *http.Request) bool {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-stop
			return true
		}
		return false
	}, nil)
	s, _ := testStore(t, f, func(o *Options) { o.Download.IdleTimeout = 50 * time.Millisecond })
	if res := mustSync(t, s, SyncOptions{}); res.Records != 1 {
		t.Fatalf("records = %d", res.Records)
	}
}

func TestCorruptEntryFailsAndKeepsOldDB(t *testing.T) {
	f := newFake(t)
	f.set("DSA-1", t0, eco12+"/openssl")
	s, dir := testStore(t, f)
	mustSync(t, s, SyncOptions{})

	f.setRaw("DSA-2", t0.Add(time.Hour), []byte(`{"id":"DSA-2", not json`))
	_, err := s.Sync(context.Background(), SyncOptions{Full: true})
	if err == nil || !strings.Contains(err.Error(), "DSA-2") {
		t.Fatalf("err = %v", err)
	}
	wantStrings(t, "old data", recordIDs(t, s, "openssl"), "DSA-1")
	assertNoTemps(t, dir)
}

func TestArchiveWithNothingForReleaseKeepsOldDB(t *testing.T) {
	f := newFake(t)
	f.set("DSA-1", t0, eco12+"/openssl")
	s, _ := testStore(t, f)
	mustSync(t, s, SyncOptions{})

	f.set("DSA-1", t0.Add(time.Hour), "Debian:13/openssl")
	if _, err := s.Sync(context.Background(), SyncOptions{Full: true}); err == nil {
		t.Fatal("want error")
	}
	wantStrings(t, "old data", recordIDs(t, s, "openssl"), "DSA-1")
}

func TestIncrementalExactChanges(t *testing.T) {
	f := newFake(t)
	f.set("DSA-1", t0, eco12+"/openssl")
	f.set("DSA-2", t0, eco12+"/curl", eco12+"/libcurl3")
	f.set("DSA-3", t0, eco12+"/nginx")
	f.set("DSA-4", t0, eco12+"/bash")
	f.set("DSA-5", t0, eco12+"/untouched")
	f.set("DSA-6", t0, eco12+"/shared", eco12+"/left")
	f.set("DSA-7", t0, eco12+"/shared")
	s, _ := testStore(t, f)
	mustSync(t, s, SyncOptions{})
	zipsBefore, _ := f.gets()

	t1 := t0.Add(time.Hour)
	f.set("DSA-1", t1, eco12+"/openssl", eco12+"/openssl3") // gains a package
	f.set("DSA-2", t1, eco12+"/curl2")                      // moves off curl, libcurl3
	f.withdraw("DSA-3", t1, eco12+"/nginx")                 // withdrawn
	f.set("DSA-4", t1, "Debian:13/bash")                    // no longer this release
	f.set("DSA-8", t1, eco12+"/brandnew")                   // added
	f.set("DSA-9", t1, "Debian:13/irrelevant")              // never relevant
	f.set("DSA-6", t1, eco12+"/shared")                     // leaves left, stays on shared

	res := mustSync(t, s, SyncOptions{})
	if res.Mode != "incremental" {
		t.Fatalf("mode = %s (%s)", res.Mode, res.FullReason)
	}
	if zips, _ := f.gets(); zips != zipsBefore {
		t.Fatal("incremental downloaded the archive")
	}
	wantStrings(t, "changed", res.ChangedPackages,
		"bash", "brandnew", "curl", "curl2", "left", "libcurl3", "nginx", "openssl", "openssl3", "shared")
	if res.RecordsChanged != 6 {
		t.Fatalf("records changed = %d", res.RecordsChanged)
	}

	wantStrings(t, "curl", recordIDs(t, s, "curl"))
	wantStrings(t, "curl2", recordIDs(t, s, "curl2"), "DSA-2")
	wantStrings(t, "nginx", recordIDs(t, s, "nginx"))
	wantStrings(t, "bash", recordIDs(t, s, "bash"))
	wantStrings(t, "openssl3", recordIDs(t, s, "openssl3"), "DSA-1")
	wantStrings(t, "brandnew", recordIDs(t, s, "brandnew"), "DSA-8")
	wantStrings(t, "left", recordIDs(t, s, "left"))
	wantStrings(t, "shared", recordIDs(t, s, "shared"), "DSA-6", "DSA-7")
	wantStrings(t, "untouched", recordIDs(t, s, "untouched"), "DSA-5")

	// DSA-1, DSA-2, DSA-5, DSA-6, DSA-7, DSA-8 remain; emptied package buckets
	// are gone from the count.
	st, _ := s.Status()
	if st.Records != 6 || st.Packages != 6 {
		t.Fatalf("status: %+v", st)
	}

	// A full sync of the same data agrees and reports nothing new.
	if res := mustSync(t, s, SyncOptions{Full: true}); len(res.ChangedPackages) != 0 || res.RecordsChanged != 0 {
		t.Fatalf("full after incremental: %+v", res)
	}
}

func TestFullSyncChangedPackages(t *testing.T) {
	f := newFake(t)
	f.set("DSA-1", t0, eco12+"/openssl")
	f.set("DSA-2", t0, eco12+"/curl")
	f.set("DSA-3", t0, eco12+"/nginx")
	f.set("DSA-4", t0, eco12+"/keep")
	s, _ := testStore(t, f)

	res := mustSync(t, s, SyncOptions{})
	wantStrings(t, "first sync", res.ChangedPackages, "curl", "keep", "nginx", "openssl")

	// Unchanged re-download.
	res = mustSync(t, s, SyncOptions{Full: true})
	if res.Mode != "full" || res.RecordsChanged != 0 {
		t.Fatalf("unchanged: %+v", res)
	}
	wantStrings(t, "unchanged", res.ChangedPackages)

	t1 := t0.Add(time.Hour)
	f.set("DSA-1", t1, eco12+"/openssl3") // moved
	f.delete("DSA-2")                     // gone from the archive
	f.withdraw("DSA-3", t1, eco12+"/nginx")
	res = mustSync(t, s, SyncOptions{Full: true})
	wantStrings(t, "changes", res.ChangedPackages, "curl", "nginx", "openssl", "openssl3")
	if res.RecordsChanged != 3 || res.Records != 2 {
		t.Fatalf("result: %+v", res)
	}
}

func TestChangeForAnotherReleaseIsNotAChange(t *testing.T) {
	f := newFake(t)
	f.set("DSA-1", t0, eco12+"/openssl", "Debian:13/openssl")
	s, _ := testStore(t, f)
	mustSync(t, s, SyncOptions{})

	// Only Debian:13's entry changed; the modified time moves regardless.
	t1 := t0.Add(time.Hour)
	f.set("DSA-1", t1, eco12+"/openssl")
	res := mustSync(t, s, SyncOptions{})
	if res.Mode != "incremental" || res.RecordsChanged != 0 {
		t.Fatalf("incremental: %+v", res)
	}
	wantStrings(t, "incremental", res.ChangedPackages)

	f.set("DSA-1", t1.Add(time.Hour), eco12+"/openssl", "Debian:13/openssl")
	res = mustSync(t, s, SyncOptions{Full: true})
	wantStrings(t, "full", res.ChangedPackages)
}

func TestIncrementalUnchangedAndCursor(t *testing.T) {
	f := newFake(t)
	f.set("DSA-1", t0, eco12+"/openssl")
	f.set("DSA-2", t0.Add(-time.Minute), eco12+"/old")
	s, dir := testStore(t, f)
	mustSync(t, s, SyncOptions{})
	m, _ := ReadMeta(dir)
	if !m.Ecosystems[eco12].Cursor.Equal(t0) {
		t.Fatalf("cursor = %v", m.Ecosystems[eco12].Cursor)
	}

	_, before := f.gets()
	res := mustSync(t, s, SyncOptions{})
	if res.Mode != "incremental" || res.RecordsChanged != 0 || res.Records != 2 {
		t.Fatalf("result: %+v", res)
	}
	wantStrings(t, "changed", res.ChangedPackages)
	if _, after := f.gets(); after != before {
		t.Fatalf("re-fetched %d stored records inside the overlap", after-before)
	}

	// A record published at exactly the cursor's timestamp after the last sync
	// is still picked up.
	f.set("DSA-3", t0, eco12+"/late")
	res = mustSync(t, s, SyncOptions{})
	wantStrings(t, "same timestamp", res.ChangedPackages, "late")

	// So is one inside the overlap, but older ones are not looked at.
	f.set("DSA-4", t0.Add(-cursorOverlap/2), eco12+"/almost")
	f.set("DSA-5", t0.Add(-2*cursorOverlap), eco12+"/toolate")
	res = mustSync(t, s, SyncOptions{})
	wantStrings(t, "overlap", res.ChangedPackages, "almost")
}

func TestThresholdFallsBackToFull(t *testing.T) {
	f := newFake(t)
	f.set("DSA-0", t0, eco12+"/openssl")
	s, _ := testStore(t, f, func(o *Options) { o.FullSyncThreshold = 3 })
	mustSync(t, s, SyncOptions{})

	t1 := t0.Add(time.Hour)
	for i := 1; i <= 3; i++ {
		f.set(fmt.Sprintf("DSA-%d", i), t1.Add(time.Duration(i)), eco12+fmt.Sprintf("/p%d", i))
	}
	res := mustSync(t, s, SyncOptions{})
	if res.Mode != "incremental" || len(res.ChangedPackages) != 3 {
		t.Fatalf("at threshold: %+v", res)
	}

	t2 := t1.Add(time.Hour)
	for i := 4; i <= 7; i++ {
		f.set(fmt.Sprintf("DSA-%d", i), t2.Add(time.Duration(i)), eco12+fmt.Sprintf("/p%d", i))
	}
	_, recsBefore := f.gets()
	res = mustSync(t, s, SyncOptions{})
	if res.Mode != "full" || !strings.Contains(res.FullReason, "more than 3") {
		t.Fatalf("over threshold: %+v", res)
	}
	wantStrings(t, "changed", res.ChangedPackages, "p4", "p5", "p6", "p7")
	if _, recs := f.gets(); recs != recsBefore {
		t.Fatal("fetched records one by one despite the threshold")
	}
}

func TestIncrementalBadRecordFallsBackToFull(t *testing.T) {
	for name, hook := range map[string]func(http.ResponseWriter, string) bool{
		"parse failure": func(w http.ResponseWriter, id string) bool {
			if id == "DSA-2" {
				w.Write([]byte("not json"))
				return true
			}
			return false
		},
		"wrong record": func(w http.ResponseWriter, id string) bool {
			if id == "DSA-2" {
				w.Write([]byte(`{"id":"DSA-X","modified":"2026-11-01T00:00:00Z"}`))
				return true
			}
			return false
		},
		"not found": func(w http.ResponseWriter, id string) bool {
			if id == "DSA-2" {
				w.WriteHeader(http.StatusNotFound)
				return true
			}
			return false
		},
		"server error": func(w http.ResponseWriter, id string) bool {
			if id == "DSA-2" {
				w.WriteHeader(http.StatusBadGateway)
				return true
			}
			return false
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.set("DSA-1", t0, eco12+"/openssl")
			s, _ := testStore(t, f)
			mustSync(t, s, SyncOptions{})

			f.set("DSA-2", t0.Add(time.Hour), eco12+"/curl")
			f.hooks(nil, hook)
			res := mustSync(t, s, SyncOptions{})
			if res.Mode != "full" {
				t.Fatalf("result: %+v", res)
			}
			wantStrings(t, "changed", res.ChangedPackages, "curl")
		})
	}
}

func TestBadCSVFallsBackToFull(t *testing.T) {
	for _, body := range []string{"garbage\n", "not-a-time,DSA-1\n"} {
		lines := []string{body}
		_, _, _, _, err := readChanges(strings.NewReader(strings.Join(lines, "")), t0, t0, 10)
		if _, bad := errors.AsType[malformedError](err); !bad {
			t.Fatalf("%q: err = %v", body, err)
		}
	}
	unsorted := fmt.Sprintf("%s,A\n%s,B\n", t0.Format(time.RFC3339Nano), t0.Add(time.Hour).Format(time.RFC3339Nano))
	_, _, _, _, err := readChanges(strings.NewReader(unsorted), t0.Add(-time.Hour), t0.Add(-time.Hour), 10)
	if _, bad := errors.AsType[malformedError](err); !bad {
		t.Fatalf("unsorted: err = %v", err)
	}
}

func TestPeriodicRefresh(t *testing.T) {
	f := newFake(t)
	f.set("DSA-1", t0, eco12+"/openssl")
	now := t0
	s, _ := testStore(t, f, func(o *Options) { o.Now = func() time.Time { return now } })
	mustSync(t, s, SyncOptions{})

	now = now.Add(6 * 24 * time.Hour)
	if res := mustSync(t, s, SyncOptions{}); res.Mode != "incremental" {
		t.Fatalf("day 6: %+v", res)
	}
	now = now.Add(2 * 24 * time.Hour)
	res := mustSync(t, s, SyncOptions{})
	if res.Mode != "full" || res.FullReason != "periodic refresh" {
		t.Fatalf("day 8: %+v", res)
	}
	wantStrings(t, "changed", res.ChangedPackages)
	st, _ := s.Status()
	if st.Age != 0 {
		t.Fatalf("age = %v", st.Age)
	}
	now = now.Add(time.Hour)
	if st, _ = s.Status(); st.Age != time.Hour || st.AgeSeconds != 3600 {
		t.Fatalf("age = %v", st.Age)
	}
}

func TestMissingCursorForcesFull(t *testing.T) {
	f := newFake(t)
	f.set("DSA-1", t0, eco12+"/openssl")
	s, dir := testStore(t, f)
	mustSync(t, s, SyncOptions{})
	if err := os.Remove(filepath.Join(dir, metaFile)); err != nil {
		t.Fatal(err)
	}
	res := mustSync(t, s, SyncOptions{})
	if res.Mode != "full" || res.FullReason != "no cursor" {
		t.Fatalf("result: %+v", res)
	}
	wantStrings(t, "diff still works", res.ChangedPackages)
}

func TestMissingDBForcesFull(t *testing.T) {
	f := newFake(t)
	f.set("DSA-1", t0, eco12+"/openssl")
	s, _ := testStore(t, f)
	mustSync(t, s, SyncOptions{})
	if err := os.Remove(s.Path()); err != nil {
		t.Fatal(err)
	}
	res := mustSync(t, s, SyncOptions{})
	if res.Mode != "full" || res.FullReason != "no database" {
		t.Fatalf("result: %+v", res)
	}
	wantStrings(t, "all packages", res.ChangedPackages, "openssl")
}

func TestViewWithoutDB(t *testing.T) {
	s, _ := testStore(t, newFake(t))
	err := s.View(context.Background(), func(Reader) error {
		t.Fatal("fn must not run")
		return nil
	})
	if !errors.Is(err, ErrNoDB) || !strings.Contains(err.Error(), "vmmon db sync") {
		t.Fatalf("err = %v", err)
	}
	st, err := s.Status()
	if err != nil || st.Synced || st.Age != 0 {
		t.Fatalf("status: %+v, %v", st, err)
	}
}

// blockedDownload starts a sync whose download hangs after the headers.
func blockedDownload(t *testing.T, f *fakeOSV, s *Store, ctx context.Context) (<-chan error, func()) {
	t.Helper()
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	f.hooks(func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Length", "1000")
		w.Write([]byte("PK"))
		w.(http.Flusher).Flush()
		once.Do(func() { close(entered) })
		select {
		case <-release:
		case <-r.Context().Done():
		}
		return true
	}, nil)
	done := make(chan error, 1)
	go func() {
		_, err := s.Sync(ctx, SyncOptions{Full: true})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("download never started")
	}
	var rel sync.Once
	stop := func() { rel.Do(func() { close(release) }) }
	t.Cleanup(stop)
	return done, stop
}

func TestCancelDuringDownload(t *testing.T) {
	f := newFake(t)
	f.set("DSA-1", t0, eco12+"/openssl")
	s, dir := testStore(t, f)
	mustSync(t, s, SyncOptions{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done, _ := blockedDownload(t, f, s, ctx)

	// Reads are unaffected while a sync is downloading: no bolt file is held.
	wantStrings(t, "during sync", recordIDs(t, s, "openssl"), "DSA-1")

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	wantStrings(t, "after cancel", recordIDs(t, s, "openssl"), "DSA-1")
	assertNoTemps(t, dir)
	st, _ := s.Status()
	if !strings.Contains(st.LastError, "context canceled") {
		t.Fatalf("status: %+v", st)
	}
}

func TestSecondSyncGetsLockError(t *testing.T) {
	f := newFake(t)
	f.set("DSA-1", t0, eco12+"/openssl")
	s, dir := testStore(t, f)
	mustSync(t, s, SyncOptions{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done, _ := blockedDownload(t, f, s, ctx)

	second := storeIn(t, dir, f)
	before, _ := s.Status()
	if _, err := second.Sync(context.Background(), SyncOptions{}); !errors.Is(err, ErrSyncInProgress) {
		t.Fatalf("err = %v", err)
	}
	if after, _ := s.Status(); after.LastError != before.LastError {
		t.Fatalf("lost race recorded as a failure: %+v", after)
	}
	cancel()
	<-done
	f.hooks(nil, nil)
	mustSync(t, second, SyncOptions{Full: true})
}

func TestLeftoverTempsCleanedAtNextRun(t *testing.T) {
	f := newFake(t)
	f.set("DSA-1", t0, eco12+"/openssl")
	s, dir := testStore(t, f)
	mustSync(t, s, SyncOptions{})

	stale := []string{"Debian_12.zip.tmp-111", "Debian_12.bolt.tmp-222", "meta.json.tmp-333"}
	for _, name := range stale {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("junk"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	other := filepath.Join(dir, "Ubuntu_24.04_LTS.zip.tmp-444")
	if err := os.WriteFile(other, []byte("another ecosystem's sync"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustSync(t, s, SyncOptions{})
	for _, name := range stale {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s survived: %v", name, err)
		}
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("removed another ecosystem's temp: %v", err)
	}
}

func TestFilesAreWorldReadable(t *testing.T) {
	f := newFake(t)
	f.set("DSA-1", t0, eco12+"/openssl")
	s, dir := testStore(t, f)
	mustSync(t, s, SyncOptions{})
	for _, name := range []string{"Debian_12.bolt", metaFile, "sync.lock", metaLockFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o444 != 0o444 {
			t.Fatalf("%s: mode %v", name, info.Mode())
		}
	}
	info, _ := os.Stat(dir)
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("dir mode %v", info.Mode())
	}
}

func TestDiskSpacePreflight(t *testing.T) {
	if err := checkDiskSpace(t.TempDir(), 1); err != nil {
		t.Fatal(err)
	}
	err := checkDiskSpace(t.TempDir(), 1<<62)
	if err == nil || !strings.Contains(err.Error(), "not enough disk space") {
		t.Fatalf("err = %v", err)
	}
}

func TestUpdateMetaMergesConcurrentWriters(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			err := UpdateMeta(dir, func(m *Meta) {
				m.Ecosystems[fmt.Sprintf("Eco:%d", i)] = EcosystemMeta{Records: i}
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	m, err := ReadMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Ecosystems) != 20 {
		t.Fatalf("kept %d of 20 updates", len(m.Ecosystems))
	}
}

func TestUpdateMetaReplacesCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, metaFile), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMeta(dir); err == nil {
		t.Fatal("want parse error")
	}
	if err := UpdateMeta(dir, func(m *Meta) { m.KEV.Records = 3 }); err != nil {
		t.Fatal(err)
	}
	if m, err := ReadMeta(dir); err != nil || m.KEV.Records != 3 {
		t.Fatalf("meta: %+v, %v", m, err)
	}
}

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.DiscardHandler))
	os.Exit(m.Run())
}

func TestEachRecord(t *testing.T) {
	f := newFake(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f.set("B-2", base, eco12+"/foo", eco12+"/bar")
	f.set("A-1", base, eco12+"/foo", "Debian:13/foo")
	f.set("C-3", base, "Debian:13/foo")
	s, _ := testStore(t, f)
	mustSync(t, s, SyncOptions{Full: true})

	err := s.View(context.Background(), func(r Reader) error {
		var ids []string
		err := r.EachRecord("foo", func(rec Record) error {
			ids = append(ids, rec.ID)
			for _, a := range rec.Affected {
				if a.Package.Name != "foo" || a.Package.Ecosystem != eco12 {
					t.Errorf("%s has entry %+v", rec.ID, a.Package)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		if want := []string{"A-1", "B-2"}; !slices.Equal(ids, want) {
			t.Errorf("ids = %v, want %v", ids, want)
		}
		all, err := r.RecordsFor("foo")
		if err != nil {
			return err
		}
		if len(all) != 2 || all[0].ID != "A-1" {
			t.Errorf("RecordsFor = %+v", all)
		}

		stop := errors.New("stop")
		calls := 0
		err = r.EachRecord("foo", func(Record) error { calls++; return stop })
		if !errors.Is(err, stop) || calls != 1 {
			t.Errorf("err = %v after %d calls", err, calls)
		}
		for _, pkg := range []string{"", "absent"} {
			if err := r.EachRecord(pkg, func(Record) error { t.Error("called"); return nil }); err != nil {
				t.Errorf("EachRecord(%q) = %v", pkg, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
