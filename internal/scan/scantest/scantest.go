// Package scantest builds a real state directory for tests from frozen OSV
// records and feeds, by running the real sync against a local server.
package scantest

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vitalii-ye/vmmon/internal/enrich"
	"github.com/vitalii-ye/vmmon/internal/vulndb"
)

// Feeds are the enrichment files to serve, as `db sync` would download them.
type Feeds struct {
	// KEV is CISA's catalog JSON. Empty means no KEV catalog is synced.
	KEV []byte
	// EPSS is the scores CSV, uncompressed. Empty means no scores are synced.
	EPSS []byte
}

// BuildDB syncs records, each one OSV JSON file, and feeds into dbDir as of now.
// root is the OSV bucket directory of ecosystem, e.g. "Debian".
func BuildDB(t testing.TB, dbDir, ecosystem, root string, records map[string][]byte, feeds Feeds, now time.Time) {
	t.Helper()
	var zipped bytes.Buffer
	zw := zip.NewWriter(&zipped)
	for name, body := range records {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	var epss bytes.Buffer
	gz := gzip.NewWriter(&epss)
	_, _ = gz.Write(feeds.EPSS)
	_ = gz.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/"+root+"/all.zip", func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "all.zip", time.Time{}, bytes.NewReader(zipped.Bytes()))
	})
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(feeds.KEV) })
	mux.HandleFunc("/epss.csv.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(epss.Bytes()) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	clock := func() time.Time { return now }
	store, err := vulndb.New(dbDir, vulndb.Options{
		Ecosystem:           ecosystem,
		Root:                root,
		BaseURL:             srv.URL,
		FullSyncThreshold:   1000,
		FullRefreshInterval: 7 * 24 * time.Hour,
		Now:                 clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := store.Sync(ctx, vulndb.SyncOptions{Full: true}); err != nil {
		t.Fatalf("sync records: %v", err)
	}
	if len(feeds.KEV) == 0 || len(feeds.EPSS) == 0 {
		return // Sync does both feeds or fails; a test leaves them out on purpose.
	}
	feedStore := enrich.New(dbDir, enrich.Options{KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv.gz", Now: clock})
	if _, err := feedStore.Sync(ctx); err != nil {
		t.Fatalf("sync feeds: %v", err)
	}
}

// Record is a minimal record for tests that do not care about its contents.
func Record(id, ecosystem, pkg, fixed string) []byte {
	events := []map[string]string{{"introduced": "0"}}
	if fixed != "" {
		events = append(events, map[string]string{"fixed": fixed})
	}
	data, err := json.Marshal(map[string]any{
		"id":       id,
		"modified": "2026-01-01T00:00:00Z",
		"affected": []map[string]any{{
			"package": map[string]string{"name": pkg, "ecosystem": ecosystem},
			"ranges":  []map[string]any{{"type": "ECOSYSTEM", "events": events}},
		}},
	})
	if err != nil {
		panic(err)
	}
	return data
}

// ReadRecords loads every file in dir as a record for BuildDB.
func ReadRecords(t testing.TB, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = data
	}
	if len(out) == 0 {
		t.Fatalf("no records in %s", dir)
	}
	return out
}
