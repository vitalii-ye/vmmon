// Package state keeps what the daemon must remember across restarts in
// state.bolt: reported findings, those resolved since the last digest, schedule
// and alert state, and the persistent send queue.
//
// bbolt holds an exclusive flock while a file is open read-write, which would
// block `vmmon status`. So no database stays open between calls: each View or
// Update opens, transacts and closes. Never do network I/O inside one.
package state

import (
	"cmp"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/vitalii-ye/vmmon/internal/finding"
	"github.com/vitalii-ye/vmmon/internal/fsutil"
)

const (
	// DefaultReadTimeout bounds waiting for a writer. Writers hold the file for
	// milliseconds, so anything longer means something is wrong.
	DefaultReadTimeout = 3 * time.Second
	writeTimeout       = 30 * time.Second

	// MaxQueue caps the send queue, so a long outage cannot grow it without
	// bound. The oldest message is dropped, and the next one sent says so.
	MaxQueue = 100
)

// ErrNoState means the state file does not exist yet: the daemon has not run.
var ErrNoState = errors.New("no state file yet")

var (
	bucketMeta     = []byte("meta")
	bucketFindings = []byte("findings")
	bucketResolved = []byte("resolved")
	bucketQueue    = []byte("queue")
	keyMeta        = []byte("meta")
)

// Store is one state file. It holds no open files between calls.
type Store struct {
	path        string
	readTimeout time.Duration
	// mu keeps this process's goroutines from waiting on their own flock.
	mu sync.Mutex
}

// New returns a Store for path, which need not exist yet. A readTimeout of zero
// means DefaultReadTimeout.
func New(path string, readTimeout time.Duration) *Store {
	if readTimeout <= 0 {
		readTimeout = DefaultReadTimeout
	}
	return &Store{path: path, readTimeout: readTimeout}
}

// View runs fn in a read transaction. It gives ErrNoState when there is no state
// yet, and an error matching fs.ErrPermission when the file cannot be read.
func (s *Store) View(fn func(*Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// An empty file is a writer's first moment; bbolt cannot open it read-only.
	info, err := os.Stat(s.path)
	switch {
	case errors.Is(err, fs.ErrNotExist) || (err == nil && info.Size() == 0):
		return ErrNoState
	case err != nil:
		return err
	}
	db, err := bolt.Open(s.path, 0, &bolt.Options{ReadOnly: true, Timeout: s.readTimeout})
	if err != nil {
		return fmt.Errorf("open %s: %w", s.path, err)
	}
	defer func() { _ = db.Close() }()
	return db.View(func(tx *bolt.Tx) error { return fn(&Tx{tx: tx}) })
}

// Update runs fn in one write transaction: everything fn does commits together
// or, when it returns an error, not at all.
func (s *Store) Update(fn func(*Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := os.Stat(s.path)
	created := errors.Is(err, fs.ErrNotExist)
	if created {
		if err := ensureDir(filepath.Dir(s.path)); err != nil {
			return err
		}
	}
	db, err := bolt.Open(s.path, 0o600, &bolt.Options{Timeout: writeTimeout})
	if err != nil {
		return fmt.Errorf("open %s: %w", s.path, err)
	}
	defer func() { _ = db.Close() }()
	if created {
		// Root-run commands share this directory with the DynamicUser daemon.
		if err := fsutil.MatchDirOwner(s.path); err != nil {
			return err
		}
	}
	return db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketMeta, bucketFindings, bucketResolved, bucketQueue} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return fn(&Tx{tx: tx})
	})
}

func ensureDir(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return fsutil.MatchDirOwner(dir)
}

// Channel is the health of the notification channel.
type Channel struct {
	LastOK      time.Time `json:"last_ok,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt time.Time `json:"last_error_at,omitzero"`
	// Permanent means retrying cannot help until the user re-runs setup.
	Permanent bool `json:"permanent,omitempty"`
}

// Meta is the state that is not per finding.
type Meta struct {
	// FirstStart is when the daemon first ran on this host.
	FirstStart time.Time `json:"first_start,omitzero"`
	// Baselined means the first full scan is recorded: from then on findings are
	// new only if they were not there before.
	Baselined bool `json:"baselined,omitempty"`
	// FirstSummarySent is false while a summary is owed: no channel has had the
	// first scan's summary yet, or an alert was due while no channel was configured.
	FirstSummarySent bool `json:"first_summary_sent,omitempty"`

	Ecosystem    string    `json:"ecosystem,omitempty"`
	Packages     int       `json:"packages,omitempty"`
	LastScan     time.Time `json:"last_scan,omitzero"`
	LastFullScan time.Time `json:"last_full_scan,omitzero"`
	// RebootRequired and Warnings come from the last scan's report.
	RebootRequired bool     `json:"reboot_required,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`

	LastDigest time.Time `json:"last_digest,omitzero"`
	// SilentSinceDigest counts new findings below the alert policy, for the digest.
	SilentSinceDigest int `json:"silent_since_digest,omitempty"`
	// StaleAlerted means this stale episode has had its one alert.
	StaleAlerted bool `json:"stale_alerted,omitempty"`

	Channel Channel `json:"channel,omitzero"`
	// DroppedMessages counts queue overflows the user has not yet been told about.
	DroppedMessages int `json:"dropped_messages,omitempty"`
}

// Record is what is kept of a reported finding: enough to detect escalation,
// write digests and answer `vmmon status`.
type Record struct {
	ID             string            `json:"-"`
	Ecosystem      string            `json:"eco,omitempty"`
	Source         string            `json:"src"`
	Vuln           string            `json:"vuln"`
	Version        string            `json:"ver"`
	FixStatus      finding.FixStatus `json:"fix_status"`
	FixedVersion   string            `json:"fixed,omitempty"`
	CVSS           float64           `json:"cvss,omitempty"`
	EPSS           float64           `json:"epss,omitempty"`
	Severity       string            `json:"sev,omitempty"`
	KEV            bool              `json:"kev,omitempty"`
	Kernel         bool              `json:"kernel,omitempty"`
	RebootRequired bool              `json:"reboot,omitempty"`
	// EverKEV, EverFix and EverAlert are sticky, so a feed or record that flaps can
	// escalate a finding only once.
	EverKEV   bool      `json:"ever_kev,omitempty"`
	EverFix   bool      `json:"ever_fix,omitempty"`
	EverAlert bool      `json:"ever_alert,omitempty"`
	FirstSeen time.Time `json:"first_seen,omitzero"`
	// ResolvedAt is set on records in the resolved set.
	ResolvedAt time.Time `json:"resolved_at,omitzero"`
}

// Finding returns the record as a finding, for rendering.
func (r *Record) Finding() finding.Finding {
	return finding.Finding{
		ID:               r.ID,
		Ecosystem:        r.Ecosystem,
		SourcePackage:    r.Source,
		InstalledVersion: r.Version,
		VulnID:           r.Vuln,
		FixStatus:        r.FixStatus,
		FixedVersion:     r.FixedVersion,
		CVSSScore:        r.CVSS,
		EPSS:             r.EPSS,
		SeverityLabel:    r.Severity,
		KEV:              r.KEV,
		Kernel:           r.Kernel,
		RebootRequired:   r.RebootRequired,
	}
}

func recordOf(f *finding.Finding) Record {
	return Record{
		ID:             f.ID,
		Ecosystem:      f.Ecosystem,
		Source:         f.SourcePackage,
		Vuln:           f.VulnID,
		Version:        f.InstalledVersion,
		FixStatus:      f.FixStatus,
		FixedVersion:   f.FixedVersion,
		CVSS:           f.CVSSScore,
		EPSS:           f.EPSS,
		Severity:       f.SeverityLabel,
		KEV:            f.KEV,
		Kernel:         f.Kernel,
		RebootRequired: f.RebootRequired,
		EverKEV:        f.KEV,
		EverFix:        f.FixStatus == finding.FixAvailable,
	}
}

// Escalation is a reported finding that became more urgent.
type Escalation struct {
	Finding finding.Finding
	// NewKEV, NewFix and NewAlert say why; several can be true. NewAlert means it
	// first meets the alert policy, for example because its EPSS score rose.
	NewKEV, NewFix, NewAlert bool
}

// Diff is what one report changed.
type Diff struct {
	New       []finding.Finding
	Escalated []Escalation
	Resolved  int
}

// Item is one queued message.
type Item struct {
	Seq       uint64    `json:"-"`
	Kind      string    `json:"kind"`
	HTML      string    `json:"html"`
	CreatedAt time.Time `json:"created_at"`
}

// Tx is one transaction. Its methods that write fail inside a View.
type Tx struct{ tx *bolt.Tx }

// Meta returns the meta state; the zero value before anything was stored.
func (t *Tx) Meta() (Meta, error) {
	var m Meta
	b := t.tx.Bucket(bucketMeta)
	if b == nil {
		return m, nil
	}
	data := b.Get(keyMeta)
	if data == nil {
		return m, nil
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("decode state: %w", err)
	}
	return m, nil
}

// PutMeta stores the meta state.
func (t *Tx) PutMeta(m Meta) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return t.tx.Bucket(bucketMeta).Put(keyMeta, data)
}

// ApplyReport diffs r against the reported findings and records the outcome.
//
// When only is not nil the report is partial: a finding it lacks is resolved
// only if its source package is in only. A resolved finding that returns is new.
// alert is the alert policy, needed to notice a finding that comes to meet it.
func (t *Tx) ApplyReport(r *finding.Report, only map[string]bool, now time.Time, alert func(*finding.Finding) bool) (Diff, error) {
	var d Diff
	open := t.tx.Bucket(bucketFindings)
	resolved := t.tx.Bucket(bucketResolved)
	seen := make(map[string]struct{}, len(r.Findings))
	for i := range r.Findings {
		f := &r.Findings[i]
		seen[f.ID] = struct{}{}
		key := []byte(f.ID)
		cur := recordOf(f)
		cur.FirstSeen = now
		cur.EverAlert = alert(f)
		var prev Record
		data := open.Get(key)
		if data == nil {
			d.New = append(d.New, *f)
			if err := resolved.Delete(key); err != nil {
				return d, err
			}
		} else {
			if err := json.Unmarshal(data, &prev); err != nil {
				return d, fmt.Errorf("decode finding %s: %w", f.ID, err)
			}
			prev.ID = f.ID
			cur.FirstSeen = prev.FirstSeen
			newKEV, newFix := cur.EverKEV && !prev.EverKEV, cur.EverFix && !prev.EverFix
			newAlert := cur.EverAlert && !prev.EverAlert
			if newKEV || newFix || newAlert {
				d.Escalated = append(d.Escalated, Escalation{Finding: *f, NewKEV: newKEV, NewFix: newFix, NewAlert: newAlert})
			}
			cur.EverKEV = cur.EverKEV || prev.EverKEV
			cur.EverFix = cur.EverFix || prev.EverFix
			cur.EverAlert = cur.EverAlert || prev.EverAlert
			if cur == prev {
				continue
			}
		}
		if err := putJSON(open, key, cur); err != nil {
			return d, err
		}
	}

	var gone []Record
	c := open.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if _, ok := seen[string(k)]; ok {
			continue
		}
		var rec Record
		if err := json.Unmarshal(v, &rec); err != nil {
			return d, fmt.Errorf("decode finding %s: %w", k, err)
		}
		if only != nil && !only[rec.Source] {
			continue
		}
		rec.ID = string(k)
		gone = append(gone, rec)
	}
	for i := range gone {
		key := []byte(gone[i].ID)
		if err := open.Delete(key); err != nil {
			return d, err
		}
		gone[i].ResolvedAt = now
		if err := putJSON(resolved, key, gone[i]); err != nil {
			return d, err
		}
	}
	d.Resolved = len(gone)
	return d, nil
}

// Open calls fn for each open finding.
func (t *Tx) Open(fn func(*Record) error) error { return t.each(bucketFindings, fn) }

// ResolvedSinceDigest calls fn for each finding resolved since the last digest.
func (t *Tx) ResolvedSinceDigest(fn func(*Record) error) error { return t.each(bucketResolved, fn) }

func (t *Tx) each(bucket []byte, fn func(*Record) error) error {
	b := t.tx.Bucket(bucket)
	if b == nil {
		return nil
	}
	return b.ForEach(func(k, v []byte) error {
		var rec Record
		if err := json.Unmarshal(v, &rec); err != nil {
			return fmt.Errorf("decode finding %s: %w", k, err)
		}
		rec.ID = string(k)
		return fn(&rec)
	})
}

// ClearResolved empties the resolved set, once a digest has reported it.
func (t *Tx) ClearResolved() error {
	if err := t.tx.DeleteBucket(bucketResolved); err != nil {
		return err
	}
	_, err := t.tx.CreateBucket(bucketResolved)
	return err
}

// Overview is the open findings in brief.
type Overview struct {
	Counts finding.Counts
	// KEV holds every KEV-listed open finding, ordered by package and vulnerability.
	KEV []finding.Finding
}

// Overview tallies the open findings.
func (t *Tx) Overview() (Overview, error) {
	var o Overview
	err := t.Open(func(r *Record) error {
		o.Counts.Total++
		if r.FixStatus == finding.FixAvailable {
			o.Counts.FixAvailable++
		} else {
			o.Counts.NoFixYet++
		}
		if r.KEV {
			o.Counts.KEV++
			o.KEV = append(o.KEV, r.Finding())
		}
		return nil
	})
	slices.SortFunc(o.KEV, func(a, b finding.Finding) int {
		return cmp.Or(cmp.Compare(a.SourcePackage, b.SourcePackage), cmp.Compare(a.VulnID, b.VulnID))
	})
	return o, err
}

// Enqueue adds a message to the send queue, in the same transaction as the state
// change it reports. A full queue drops its oldest message and counts it in
// m.DroppedMessages; the caller stores m.
func (t *Tx) Enqueue(m *Meta, kind, html string, now time.Time) error {
	q := t.tx.Bucket(bucketQueue)
	seq, err := q.NextSequence()
	if err != nil {
		return err
	}
	if err := putJSON(q, seqKey(seq), Item{Kind: kind, HTML: html, CreatedAt: now}); err != nil {
		return err
	}
	for over := countKeys(q) - MaxQueue; over > 0; over-- {
		k, _ := q.Cursor().First()
		if err := q.Delete(k); err != nil {
			return err
		}
		m.DroppedMessages++
	}
	return nil
}

// QueueHead returns the oldest queued message, if any.
func (t *Tx) QueueHead() (Item, bool, error) {
	q := t.tx.Bucket(bucketQueue)
	if q == nil {
		return Item{}, false, nil
	}
	k, v := q.Cursor().First()
	if k == nil {
		return Item{}, false, nil
	}
	var it Item
	if err := json.Unmarshal(v, &it); err != nil {
		return Item{}, false, fmt.Errorf("decode queued message: %w", err)
	}
	it.Seq = binary.BigEndian.Uint64(k)
	return it, true, nil
}

// QueueLen returns how many messages wait to be sent.
func (t *Tx) QueueLen() int {
	q := t.tx.Bucket(bucketQueue)
	if q == nil {
		return 0
	}
	return countKeys(q)
}

// countKeys walks the keys: Bucket.Stats misses a write transaction's own changes.
func countKeys(b *bolt.Bucket) int {
	n := 0
	c := b.Cursor()
	for k, _ := c.First(); k != nil; k, _ = c.Next() {
		n++
	}
	return n
}

// ReplaceItem stores what is left of a message, unless it has since been dropped.
func (t *Tx) ReplaceItem(it Item) error {
	q := t.tx.Bucket(bucketQueue)
	key := seqKey(it.Seq)
	if q.Get(key) == nil {
		return nil
	}
	return putJSON(q, key, it)
}

// DeleteItem removes a delivered message.
func (t *Tx) DeleteItem(seq uint64) error { return t.tx.Bucket(bucketQueue).Delete(seqKey(seq)) }

func seqKey(seq uint64) []byte { return binary.BigEndian.AppendUint64(nil, seq) }

func putJSON(b *bolt.Bucket, key []byte, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put(key, data)
}
