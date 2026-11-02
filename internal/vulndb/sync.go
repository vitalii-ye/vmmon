package vulndb

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	// cursorOverlap re-reads a little before the cursor, so records sharing the
	// cursor's timestamp or published slightly out of order are not lost. It is
	// short because OSV rewrites thousands of records within minutes, and the
	// weekly full sync catches anything later still.
	cursorOverlap = 5 * time.Second

	fetchWorkers   = 8
	fetchTimeout   = 60 * time.Second
	csvTimeout     = 5 * time.Minute
	maxRecordBytes = 64 << 20

	// A batch of the temporary index is committed at whichever limit comes
	// first, which bounds memory during a full sync.
	batchRecords = 1000
	batchBytes   = 4 << 20

	writeOpenTimeout = 30 * time.Second
)

// SyncOptions selects how Sync runs.
type SyncOptions struct {
	// Full forces a full download.
	Full bool
}

// Sync brings the index up to date. It runs a full download when forced, when
// there is no usable index or cursor, when the last full sync is too old, and
// when an incremental sync finds too many changes or any it cannot read. A
// concurrent sync of the same directory fails with ErrSyncInProgress.
//
// On failure, including being killed, the previous index stays intact.
func (s *Store) Sync(ctx context.Context, opts SyncOptions) (SyncResult, error) {
	if err := EnsureDir(s.dir); err != nil {
		return SyncResult{}, err
	}
	unlock, err := TryLock(filepath.Join(s.dir, "sync.lock"))
	if err != nil {
		return SyncResult{}, err
	}
	defer unlock()
	RemoveTemps(s.dir, s.base()+".")

	eco := s.opts.Ecosystem
	attempt := s.opts.Now()
	var em EcosystemMeta
	err = UpdateMeta(s.dir, func(m *Meta) {
		em = m.Ecosystems[eco]
		e := em
		e.LastAttempt = attempt
		m.Ecosystems[eco] = e
	})
	if err != nil {
		return SyncResult{}, err
	}

	res, update, err := s.run(ctx, opts, em)
	metaErr := UpdateMeta(s.dir, func(m *Meta) {
		e := m.Ecosystems[eco]
		e.LastAttempt = attempt
		e.LastError = ""
		if err != nil {
			e.LastError = err.Error()
		} else {
			update(&e, s.opts.Now())
		}
		m.Ecosystems[eco] = e
	})
	if err != nil {
		return SyncResult{}, err
	}
	return res, metaErr
}

// run picks the mode. The returned update applies the outcome to the metadata.
func (s *Store) run(ctx context.Context, opts SyncOptions, em EcosystemMeta) (SyncResult, func(*EcosystemMeta, time.Time), error) {
	reason := s.fullReason(opts, em)
	if reason == "" {
		res, update, err := s.incremental(ctx, em)
		var fb fallbackError
		if !errors.As(err, &fb) {
			return res, update, err
		}
		reason = fb.reason
	}
	slog.Info("full sync", "ecosystem", s.opts.Ecosystem, "reason", reason)
	res, update, err := s.full(ctx)
	res.FullReason = reason
	return res, update, err
}

func (s *Store) fullReason(opts SyncOptions, em EcosystemMeta) string {
	switch {
	case opts.Full:
		return "requested"
	case em.Cursor.IsZero():
		return "no cursor"
	case s.opts.FullRefreshInterval > 0 && s.opts.Now().Sub(em.LastFullSync) > s.opts.FullRefreshInterval:
		return "periodic refresh"
	}
	db, err := s.openRead()
	if errors.Is(err, ErrNoDB) {
		return "no database"
	}
	if err != nil {
		return "unreadable database: " + err.Error()
	}
	defer db.Close()
	reason := ""
	err = db.View(func(tx *bolt.Tx) error {
		if err := checkFormat(tx); err != nil {
			return err
		}
		if string(tx.Bucket(bucketInfo).Get(keyFilter)) != s.filterKey() {
			reason = "filter changed"
		}
		return nil
	})
	if err != nil {
		return "unusable database: " + err.Error()
	}
	return reason
}

// fallbackError asks for a full sync instead of an incremental one.
type fallbackError struct{ reason string }

func (e fallbackError) Error() string { return "fall back to full sync: " + e.reason }

func (s *Store) url(elem ...string) (string, error) {
	return url.JoinPath(s.opts.BaseURL, append([]string{url.PathEscape(s.opts.Root)}, elem...)...)
}

// full downloads all.zip into a temp file in the data directory, builds a new
// index beside the old one and renames it into place. It holds no bolt file
// open during the download.
func (s *Store) full(ctx context.Context) (SyncResult, func(*EcosystemMeta, time.Time), error) {
	zipURL, err := s.url("all.zip")
	if err != nil {
		return SyncResult{}, nil, err
	}
	zf, err := os.CreateTemp(s.dir, s.base()+".zip.tmp-*")
	if err != nil {
		return SyncResult{}, nil, err
	}
	defer os.Remove(zf.Name())
	defer zf.Close()

	dl := s.opts.Download
	dl.Preflight = func(size int64) error {
		// Room for the zip, the index being built and its compacted copy, which
		// peak near 400 MB for the largest release.
		return checkDiskSpace(s.dir, size+512<<20)
	}
	sum, err := Download(ctx, s.opts.HTTPClient, zipURL, zf, dl)
	if err != nil {
		return SyncResult{}, nil, fmt.Errorf("download %s: %w", zipURL, err)
	}
	size, err := zf.Seek(0, io.SeekCurrent)
	if err != nil {
		return SyncResult{}, nil, err
	}

	tmp, err := os.CreateTemp(s.dir, s.base()+".bolt.tmp-*")
	if err != nil {
		return SyncResult{}, nil, err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	b, err := s.build(ctx, zf, size, tmp.Name())
	if err != nil {
		return SyncResult{}, nil, err
	}
	compacted, err := Compact(tmp.Name())
	if err != nil {
		return SyncResult{}, nil, err
	}
	defer os.Remove(compacted)
	if err := PublishFile(compacted, s.Path()); err != nil {
		return SyncResult{}, nil, err
	}
	res := SyncResult{
		Mode:            "full",
		RecordsChanged:  b.recordsChanged,
		ChangedPackages: sortedSet(b.changed),
		Records:         b.records,
		Packages:        b.packages,
	}
	return res, func(e *EcosystemMeta, now time.Time) {
		e.LastSync = now
		e.LastFullSync = now
		e.Cursor = b.newest
		e.Records = b.records
		e.Packages = b.packages
		e.SHA256 = sum
	}, nil
}

type buildResult struct {
	records, packages int
	recordsChanged    int
	changed           map[string]struct{}
	// newest is the latest modified time in the archive. Used as the cursor it
	// cannot skip anything, even when the archive lags modified_id.csv.
	newest time.Time
}

// build writes the filtered index to path, reading entries one at a time, and
// diffs it against the current index, which it holds open read-only.
func (s *Store) build(ctx context.Context, zf io.ReaderAt, size int64, path string) (buildResult, error) {
	b := buildResult{changed: map[string]struct{}{}}
	zr, err := zip.NewReader(zf, size)
	if err != nil {
		return b, fmt.Errorf("read archive: %w", err)
	}
	// The temp file is thrown away on any crash, so skip per-commit fsyncs.
	db, err := bolt.Open(path, 0o644, &bolt.Options{NoSync: true, NoFreelistSync: true, Timeout: time.Second})
	if err != nil {
		return b, err
	}
	defer db.Close()
	var oldTx *bolt.Tx
	if old := s.openOld(); old != nil {
		defer old.Close()
		if oldTx, err = old.Begin(false); err != nil {
			return b, err
		}
		defer oldTx.Rollback()
	}

	var tx *bolt.Tx
	defer func() {
		if tx != nil {
			tx.Rollback()
		}
	}()
	begin := func() error {
		var err error
		tx, err = db.Begin(true)
		return err
	}
	if err := begin(); err != nil {
		return b, err
	}
	if err := initBuckets(tx, s.filterKey()); err != nil {
		return b, err
	}

	var buf bytes.Buffer
	var plain, stored, pending int
	inBatch := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return b, err
		}
		rec, err := readEntry(f, &buf)
		if err != nil {
			return b, fmt.Errorf("archive entry %s: %w", f.Name, err)
		}
		if rec.Modified.After(b.newest) {
			b.newest = rec.Modified
		}
		if !s.filter(rec) {
			continue
		}
		data, err := json.Marshal(rec)
		if err != nil {
			return b, err
		}
		if err := b.diff(oldTx, rec, data); err != nil {
			return b, err
		}
		value := compress(data)
		if err := putRecord(tx, rec, value); err != nil {
			return b, err
		}
		plain += len(data)
		stored += len(value)
		pending += len(value)
		inBatch++
		if inBatch >= batchRecords || pending >= batchBytes {
			if err := tx.Commit(); err != nil {
				return b, err
			}
			tx = nil
			inBatch, pending = 0, 0
			if err := begin(); err != nil {
				return b, err
			}
		}
	}
	b.records, b.packages = countIndex(tx)
	if b.records == 0 {
		return b, fmt.Errorf("archive has no records for ecosystem %q", s.opts.Ecosystem)
	}
	err = tx.Commit()
	tx = nil
	if err != nil {
		return b, err
	}
	slog.Debug("index built", "records", b.records, "packages", b.packages, "json_bytes", plain, "stored_bytes", stored)

	if oldTx != nil {
		if err := db.View(func(newTx *bolt.Tx) error { return b.removed(oldTx, newTx) }); err != nil {
			return b, err
		}
	}
	if err := db.Sync(); err != nil {
		return b, err
	}
	return b, db.Close()
}

// openOld opens the current index for diffing. Without a usable one every
// package counts as changed.
func (s *Store) openOld() *bolt.DB {
	db, err := s.openRead()
	if err != nil {
		if !errors.Is(err, ErrNoDB) {
			slog.Warn("cannot read the current index, rebuilding from scratch", "err", err)
		}
		return nil
	}
	if err := db.View(checkFormat); err != nil {
		db.Close()
		return nil
	}
	return db
}

func (b *buildResult) note(names []string) {
	b.recordsChanged++
	for _, n := range names {
		b.changed[n] = struct{}{}
	}
}

// diff notes rec's packages when its content differs from the old index, if any.
func (b *buildResult) diff(oldTx *bolt.Tx, rec *Record, data []byte) error {
	if oldTx == nil {
		b.note(packageNames(rec))
		return nil
	}
	changed, names, err := compareStored(oldTx, rec, data)
	if err != nil {
		return err
	}
	if changed {
		b.note(names)
	}
	return nil
}

// removed notes the packages of records absent from the new index.
func (b *buildResult) removed(oldTx, newTx *bolt.Tx) error {
	current := newTx.Bucket(bucketRecords)
	return oldTx.Bucket(bucketRecords).ForEach(func(id, value []byte) error {
		if current.Get(id) != nil {
			return nil
		}
		var old Record
		if err := decodeRecord(value, &old); err != nil {
			return fmt.Errorf("index: record %s: %w", id, err)
		}
		b.note(packageNames(&old))
		return nil
	})
}

// compareStored reports whether rec differs from its stored version, and the
// union of old and new package names. A new modified time alone is not a
// change: OSV bumps it when a record changes for any release, and what this
// index holds may be the same.
func compareStored(tx *bolt.Tx, rec *Record, data []byte) (bool, []string, error) {
	names := packageNames(rec)
	value := tx.Bucket(bucketRecords).Get([]byte(rec.ID))
	if value == nil {
		return true, names, nil
	}
	oldData, err := decompress(value)
	if err != nil {
		return false, nil, fmt.Errorf("index: record %s: %w", rec.ID, err)
	}
	if bytes.Equal(oldData, data) {
		return false, nil, nil
	}
	var old Record
	if err := json.Unmarshal(oldData, &old); err != nil {
		return false, nil, fmt.Errorf("index: record %s: %w", rec.ID, err)
	}
	same := *rec
	same.Modified = old.Modified
	if sameData, err := json.Marshal(same); err == nil && bytes.Equal(sameData, oldData) {
		return false, nil, nil
	}
	for _, n := range packageNames(&old) {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	return true, names, nil
}

func readEntry(f *zip.File, buf *bytes.Buffer) (*Record, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	buf.Reset()
	// Reading to the end makes the zip reader check the entry's CRC.
	if _, err := buf.ReadFrom(io.LimitReader(rc, maxRecordBytes)); err != nil {
		return nil, err
	}
	return parseRecord(buf.Bytes())
}

func parseRecord(data []byte) (*Record, error) {
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	if rec.ID == "" {
		return nil, errors.New("record has no id")
	}
	return &rec, nil
}

// malformedError marks a modified_id.csv that downloaded fine but cannot be read.
type malformedError struct{ error }

func (e malformedError) Unwrap() error { return e.error }

type changeEntry struct {
	id       string
	modified time.Time
}

// readChanges reads modified_id.csv, newest first, until a timestamp at or
// before the cutoff. Only entries newer than cursor count towards limit; overlap
// holds those at or before it. It reports whether limit was exceeded.
func readChanges(r io.Reader, cursor, cutoff time.Time, limit int) (fresh, overlap []changeEntry, newest time.Time, over bool, err error) {
	sc := bufio.NewScanner(r)
	last := time.Time{}
	for sc.Scan() {
		ts, id, ok := strings.Cut(strings.TrimSpace(sc.Text()), ",")
		if !ok || id == "" {
			return nil, nil, newest, false, malformedError{fmt.Errorf("bad line %q", sc.Text())}
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return nil, nil, newest, false, malformedError{fmt.Errorf("bad line %q: %w", sc.Text(), err)}
		}
		if !last.IsZero() && t.After(last) {
			return nil, nil, newest, false, malformedError{fmt.Errorf("not sorted at line %q", sc.Text())}
		}
		last = t
		if newest.IsZero() {
			newest = t
		}
		if !t.After(cutoff) {
			return fresh, overlap, newest, false, nil
		}
		e := changeEntry{id: id, modified: t}
		if t.After(cursor) {
			fresh = append(fresh, e)
			if limit > 0 && len(fresh) > limit {
				return fresh, overlap, newest, true, nil
			}
		} else {
			overlap = append(overlap, e)
		}
	}
	return fresh, overlap, newest, false, sc.Err()
}

// fetchedRecord is a changed record, filtered for this index. When keep is
// false the record must not be stored, and any stored version goes away.
type fetchedRecord struct {
	rec  *Record
	data []byte
	keep bool
}

// incremental fetches changed records first, with no bolt file open, then
// applies them in one transaction.
func (s *Store) incremental(ctx context.Context, em EcosystemMeta) (SyncResult, func(*EcosystemMeta, time.Time), error) {
	csvURL, err := s.url("modified_id.csv")
	if err != nil {
		return SyncResult{}, nil, err
	}
	var fresh, overlap []changeEntry
	var newest time.Time
	var over bool
	cutoff := em.Cursor.Add(-cursorOverlap)
	err = withRetry(ctx, s.opts.Download, func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, csvTimeout)
		defer cancel()
		body, err := s.get(ctx, csvURL)
		if err != nil {
			return err
		}
		defer body.Close()
		fresh, overlap, newest, over, err = readChanges(body, em.Cursor, cutoff, s.opts.FullSyncThreshold)
		if _, bad := errors.AsType[malformedError](err); bad {
			return permanentError{err}
		}
		return err
	})
	if _, bad := errors.AsType[malformedError](err); bad {
		return SyncResult{}, nil, fallbackError{"modified_id.csv: " + err.Error()}
	}
	if err != nil {
		return SyncResult{}, nil, fmt.Errorf("read %s: %w", csvURL, err)
	}
	if over {
		return SyncResult{}, nil, fallbackError{fmt.Sprintf("more than %d records changed", s.opts.FullSyncThreshold)}
	}

	work, err := s.pending(fresh, overlap)
	if err != nil {
		return SyncResult{}, nil, err
	}
	fetched, err := s.fetchAll(ctx, work)
	if err != nil {
		return SyncResult{}, nil, err
	}

	res := SyncResult{Mode: "incremental"}
	counted := false
	if len(fetched) > 0 {
		if res.RecordsChanged, res.ChangedPackages, res.Records, res.Packages, err = s.apply(fetched); err != nil {
			return SyncResult{}, nil, err
		}
		counted = true
	} else {
		res.Records, res.Packages = em.Records, em.Packages
	}
	return res, func(e *EcosystemMeta, now time.Time) {
		e.LastSync = now
		if newest.After(e.Cursor) {
			e.Cursor = newest
		}
		if counted {
			e.Records, e.Packages = res.Records, res.Packages
		}
	}, nil
}

// pending dedups the changes and drops overlap entries already stored at that
// exact version, so a burst just before the cursor is not re-fetched each run.
func (s *Store) pending(fresh, overlap []changeEntry) ([]string, error) {
	seen := map[string]struct{}{}
	var ids []string
	add := func(id string) {
		if _, dup := seen[id]; !dup {
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	for _, e := range fresh {
		add(e.id)
	}
	if len(overlap) == 0 {
		return ids, nil
	}
	err := s.withRead(func(tx *bolt.Tx) error {
		records := tx.Bucket(bucketRecords)
		for _, e := range overlap {
			if value := records.Get([]byte(e.id)); value != nil {
				var rec Record
				if err := decodeRecord(value, &rec); err == nil && rec.Modified.Equal(e.modified) {
					continue
				}
			}
			add(e.id)
		}
		return nil
	})
	return ids, err
}

func (s *Store) withRead(fn func(*bolt.Tx) error) error {
	db, err := s.openRead()
	if err != nil {
		return err
	}
	defer db.Close()
	return db.View(fn)
}

func (s *Store) get(ctx context.Context, u string) (io.ReadCloser, error) {
	req, err := newRequest(ctx, u)
	if err != nil {
		return nil, err
	}
	resp, err := s.opts.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, statusError(u, resp.StatusCode)
	}
	return resp.Body, nil
}

// fetchAll fetches and filters records with bounded concurrency. Any record it
// cannot fetch or parse turns into a fallback to a full sync.
func (s *Store) fetchAll(ctx context.Context, ids []string) ([]fetchedRecord, error) {
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	out := make([]fetchedRecord, len(ids))
	var wg sync.WaitGroup
	var once sync.Once
	var failure error
	next := make(chan int)
	for range min(fetchWorkers, len(ids)) {
		wg.Go(func() {
			for i := range next {
				rec, err := s.fetchRecord(workCtx, ids[i])
				if err != nil {
					once.Do(func() { failure = fmt.Errorf("record %s: %w", ids[i], err) })
					cancel()
					continue
				}
				out[i] = rec
			}
		})
	}
feed:
	for i := range ids {
		select {
		case next <- i:
		case <-workCtx.Done():
			break feed
		}
	}
	close(next)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if failure != nil {
		return nil, fallbackError{failure.Error()}
	}
	return out, nil
}

func (s *Store) fetchRecord(ctx context.Context, id string) (fetchedRecord, error) {
	u, err := s.url(url.PathEscape(id) + ".json")
	if err != nil {
		return fetchedRecord{}, err
	}
	var data []byte
	err = withRetry(ctx, s.opts.Download, func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
		defer cancel()
		body, err := s.get(ctx, u)
		if err != nil {
			return err
		}
		defer body.Close()
		data, err = io.ReadAll(io.LimitReader(body, maxRecordBytes))
		return err
	})
	if err != nil {
		return fetchedRecord{}, err
	}
	rec, err := parseRecord(data)
	if err != nil {
		return fetchedRecord{}, err
	}
	if rec.ID != id {
		return fetchedRecord{}, fmt.Errorf("response holds record %q", rec.ID)
	}
	f := fetchedRecord{rec: rec, keep: s.filter(rec)}
	if f.keep {
		if f.data, err = json.Marshal(rec); err != nil {
			return fetchedRecord{}, err
		}
	}
	return f, nil
}

// apply writes fetched records in one transaction. The bolt file is open
// read-write, blocking readers, only for this call.
func (s *Store) apply(fetched []fetchedRecord) (changedRecords int, packages []string, records, pkgs int, err error) {
	db, err := bolt.Open(s.Path(), 0o644, &bolt.Options{Timeout: writeOpenTimeout})
	if err != nil {
		return 0, nil, 0, 0, fmt.Errorf("open %s: %w", s.Path(), err)
	}
	defer db.Close()
	changed := map[string]struct{}{}
	note := func(names []string) {
		changedRecords++
		for _, n := range names {
			changed[n] = struct{}{}
		}
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, f := range fetched {
			if !f.keep {
				value := tx.Bucket(bucketRecords).Get([]byte(f.rec.ID))
				if value == nil {
					continue
				}
				var old Record
				if err := decodeRecord(value, &old); err != nil {
					return fmt.Errorf("index: record %s: %w", f.rec.ID, err)
				}
				note(packageNames(&old))
				if err := deleteRecord(tx, f.rec.ID); err != nil {
					return err
				}
				continue
			}
			diff, names, err := compareStored(tx, f.rec, f.data)
			if err != nil {
				return err
			}
			if diff {
				note(names)
			}
			if err := putRecord(tx, f.rec, compress(f.data)); err != nil {
				return err
			}
		}
		records, pkgs = countIndex(tx)
		return nil
	})
	if err != nil {
		return 0, nil, 0, 0, err
	}
	return changedRecords, sortedSet(changed), records, pkgs, nil
}

func sortedSet(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
