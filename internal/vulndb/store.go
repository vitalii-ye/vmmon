package vulndb

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"

	"github.com/vitalii-ye/vmmon/internal/config"
	"github.com/vitalii-ye/vmmon/internal/inventory"
)

// ErrNoDB means the index for this ecosystem does not exist yet.
var ErrNoDB = errors.New("no vulnerability database: run `vmmon db sync`")

// Bolt layout: records holds id -> flate-compressed JSON; pkg holds one nested
// bucket per source package, whose keys are record ids; info holds the format
// and the filter the file was built with.
var (
	bucketRecords = []byte("records")
	bucketPkg     = []byte("pkg")
	bucketInfo    = []byte("info")
	keySchema     = []byte("schema")
	keyFilter     = []byte("filter")
)

// schemaVersion changes when stored records can no longer be decoded as is.
const schemaVersion = "1"

// viewOpenTimeout bounds waiting for a writer's transaction. Writers hold the
// file only while applying an incremental update.
const viewOpenTimeout = 10 * time.Second

// Options configures a Store.
type Options struct {
	// Ecosystem is the exact OSV ecosystem, e.g. "Ubuntu:24.04:LTS".
	Ecosystem string
	// Root is the OSV bucket directory, e.g. "Ubuntu".
	Root string
	// BaseURL is the root of the OSV bucket.
	BaseURL string
	// UbuntuPro also keeps the release's Ubuntu Pro entries.
	UbuntuPro bool
	// FullSyncThreshold is how many changed records an incremental sync may
	// fetch before falling back to a full download.
	FullSyncThreshold int
	// FullRefreshInterval is the maximum age of the last full sync.
	FullRefreshInterval time.Duration
	// HTTPClient defaults to HTTPClient().
	HTTPClient *http.Client
	// Now defaults to time.Now.
	Now func() time.Time
	// Download tunes retries and stall detection.
	Download DownloadOptions
}

// Store is the on-disk index of one ecosystem. It holds no open files between
// calls, so `status` and `scan` keep working during a sync.
type Store struct {
	dir  string
	opts Options
}

// New returns a Store for dir, which need not exist yet.
func New(dir string, opts Options) (*Store, error) {
	if opts.Ecosystem == "" || opts.Root == "" {
		return nil, errors.New("vulndb: ecosystem and root are required")
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = HTTPClient()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Store{dir: dir, opts: opts}, nil
}

// Open returns the Store for a release as configured by cfg.
func Open(cfg *config.Config, rel inventory.Release) (*Store, error) {
	return New(cfg.DBDir(), Options{
		Ecosystem:           rel.Ecosystem,
		Root:                rel.Root,
		BaseURL:             cfg.DB.OSVBaseURL,
		UbuntuPro:           cfg.DB.UbuntuPro,
		FullSyncThreshold:   cfg.DB.FullSyncThreshold,
		FullRefreshInterval: cfg.DB.FullRefreshInterval,
	})
}

// Ecosystem returns the ecosystem this store indexes.
func (s *Store) Ecosystem() string { return s.opts.Ecosystem }

// Path returns the bolt file, e.g. <dir>/Ubuntu_24.04_LTS.bolt.
func (s *Store) Path() string { return filepath.Join(s.dir, s.base()+".bolt") }

// base is the ecosystem as a file name stem.
func (s *Store) base() string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		}
		return '_'
	}, s.opts.Ecosystem)
}

// filterKey identifies which Affected entries the index holds.
func (s *Store) filterKey() string {
	return fmt.Sprintf("%s|pro=%t", s.opts.Ecosystem, s.opts.UbuntuPro)
}

// keeps reports whether an Affected entry of ecosystem eco belongs in the index.
func (s *Store) keeps(eco string) bool {
	if eco == s.opts.Ecosystem {
		return true
	}
	return s.opts.UbuntuPro && eco == proEcosystem(s.opts.Ecosystem)
}

// proEcosystem maps "Ubuntu:24.04:LTS" to "Ubuntu:Pro:24.04:LTS". Other distros
// have no equivalent, nor does a release OSV names without the prefix.
func proEcosystem(eco string) string {
	if rest, ok := strings.CutPrefix(eco, "Ubuntu:"); ok {
		return "Ubuntu:Pro:" + rest
	}
	return ""
}

// filter narrows rec to the entries this index keeps. It returns false when
// the record should not be stored at all.
func (s *Store) filter(rec *Record) bool {
	if rec.Withdrawn != nil {
		return false
	}
	rec.Affected = slices.DeleteFunc(rec.Affected, func(a Affected) bool {
		return a.Package.Name == "" || !s.keeps(a.Package.Ecosystem)
	})
	return len(rec.Affected) > 0
}

// View opens the index read-only for the duration of fn. Reader values must not
// outlive fn. A missing index gives ErrNoDB.
func (s *Store) View(ctx context.Context, fn func(Reader) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	db, err := s.openRead()
	if err != nil {
		return err
	}
	defer db.Close()
	return db.View(func(tx *bolt.Tx) error {
		if err := checkFormat(tx); err != nil {
			return fmt.Errorf("%w (%s)", ErrNoDB, err)
		}
		return fn(reader{s: s, tx: tx})
	})
}

func (s *Store) openRead() (*bolt.DB, error) {
	path := s.Path()
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w (%s)", ErrNoDB, s.opts.Ecosystem)
	}
	db, err := bolt.Open(path, 0o644, &bolt.Options{ReadOnly: true, Timeout: viewOpenTimeout})
	if errors.Is(err, berrors.ErrTimeout) {
		return nil, fmt.Errorf("open %s: busy with a write, try again: %w", path, err)
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return db, nil
}

func checkFormat(tx *bolt.Tx) error {
	info := tx.Bucket(bucketInfo)
	if info == nil || string(info.Get(keySchema)) != schemaVersion {
		return errors.New("index format is out of date")
	}
	if tx.Bucket(bucketRecords) == nil || tx.Bucket(bucketPkg) == nil {
		return errors.New("index is incomplete")
	}
	return nil
}

type reader struct {
	s  *Store
	tx *bolt.Tx
}

// RecordsFor implements Reader.
func (r reader) RecordsFor(sourcePackage string) ([]Record, error) {
	if sourcePackage == "" {
		return nil, nil
	}
	links := r.tx.Bucket(bucketPkg).Bucket([]byte(sourcePackage))
	if links == nil {
		return nil, nil
	}
	records := r.tx.Bucket(bucketRecords)
	var out []Record
	err := links.ForEach(func(id, _ []byte) error {
		value := records.Get(id)
		if value == nil {
			return fmt.Errorf("index: %s links to missing record %s", sourcePackage, id)
		}
		var rec Record
		if err := decodeRecord(value, &rec); err != nil {
			return fmt.Errorf("index: record %s: %w", id, err)
		}
		// A record can cover hundreds of packages, so returning only the entries
		// asked for matters: all of linux's records hold millions of version
		// strings for its sibling kernels. The filter can also be narrower than
		// the file until the next sync, after db.ubuntu_pro was turned off.
		if r.s.filter(&rec) {
			rec.Affected = slices.DeleteFunc(rec.Affected, func(a Affected) bool { return a.Package.Name != sourcePackage })
			if len(rec.Affected) > 0 {
				out = append(out, rec)
			}
		}
		return nil
	})
	return out, err
}

// Status describes the local state of one ecosystem's index.
type Status struct {
	Ecosystem string `json:"ecosystem"`
	// Synced is false until a sync has succeeded; times are then zero, and Age
	// is meaningless.
	Synced       bool          `json:"synced"`
	LastSync     time.Time     `json:"last_sync,omitzero"`
	LastFullSync time.Time     `json:"last_full_sync,omitzero"`
	LastAttempt  time.Time     `json:"last_attempt,omitzero"`
	LastError    string        `json:"last_error,omitempty"`
	Age          time.Duration `json:"-"`
	AgeSeconds   int64         `json:"age_seconds,omitempty"`
	Records      int           `json:"records"`
	Packages     int           `json:"packages"`
	// Size is the bolt file's size in bytes.
	Size int64 `json:"size"`
}

// Status reads the ecosystem's state from meta.json without opening the index.
func (s *Store) Status() (Status, error) {
	m, err := ReadMeta(s.dir)
	if err != nil {
		return Status{Ecosystem: s.opts.Ecosystem}, err
	}
	st := StatusOf(s.opts.Ecosystem, m.Ecosystems[s.opts.Ecosystem], s.opts.Now())
	if info, err := os.Stat(s.Path()); err == nil {
		st.Size = info.Size()
	} else {
		st.Synced = false
	}
	return st, nil
}

// StatusOf derives a Status from an ecosystem's metadata. Size stays zero.
func StatusOf(ecosystem string, em EcosystemMeta, now time.Time) Status {
	st := Status{
		Ecosystem:    ecosystem,
		Synced:       !em.LastSync.IsZero(),
		LastSync:     em.LastSync,
		LastFullSync: em.LastFullSync,
		LastAttempt:  em.LastAttempt,
		LastError:    em.LastError,
		Records:      em.Records,
		Packages:     em.Packages,
	}
	if st.Synced {
		st.Age = now.Sub(em.LastSync)
		st.AgeSeconds = int64(st.Age.Seconds())
	}
	return st
}

// Stored values are flate-compressed JSON, 3 to 6 times smaller on real data.
var (
	flateWriters = sync.Pool{New: func() any {
		w, _ := flate.NewWriter(io.Discard, flate.DefaultCompression)
		return w
	}}
	flateReaders = sync.Pool{New: func() any { return flate.NewReader(bytes.NewReader(nil)) }}
)

func compress(data []byte) []byte {
	var buf bytes.Buffer
	w := flateWriters.Get().(*flate.Writer)
	defer flateWriters.Put(w)
	w.Reset(&buf)
	w.Write(data) // Writing to a bytes.Buffer cannot fail.
	w.Close()
	return buf.Bytes()
}

func decompress(data []byte) ([]byte, error) {
	r := flateReaders.Get().(io.ReadCloser)
	defer flateReaders.Put(r)
	if err := r.(flate.Resetter).Reset(bytes.NewReader(data), nil); err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func decodeRecord(value []byte, rec *Record) error {
	data, err := decompress(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, rec)
}

// packageNames lists the distinct package names of a record.
func packageNames(rec *Record) []string {
	names := make([]string, 0, len(rec.Affected))
	for _, a := range rec.Affected {
		if !slices.Contains(names, a.Package.Name) {
			names = append(names, a.Package.Name)
		}
	}
	return names
}

// initBuckets creates the index buckets and records the format.
func initBuckets(tx *bolt.Tx, filterKey string) error {
	for _, name := range [][]byte{bucketRecords, bucketPkg, bucketInfo} {
		if _, err := tx.CreateBucketIfNotExists(name); err != nil {
			return err
		}
	}
	info := tx.Bucket(bucketInfo)
	if err := info.Put(keySchema, []byte(schemaVersion)); err != nil {
		return err
	}
	return info.Put(keyFilter, []byte(filterKey))
}

// putRecord stores a record and its package links, replacing any previous
// version of it including links the new version no longer has.
func putRecord(tx *bolt.Tx, rec *Record, value []byte) error {
	id := []byte(rec.ID)
	names := packageNames(rec)
	if err := dropStaleLinks(tx, rec.ID, names); err != nil {
		return err
	}
	if err := tx.Bucket(bucketRecords).Put(id, value); err != nil {
		return err
	}
	pkg := tx.Bucket(bucketPkg)
	for _, name := range names {
		links, err := pkg.CreateBucketIfNotExists([]byte(name))
		if err != nil {
			return fmt.Errorf("package %q: %w", name, err)
		}
		if err := links.Put(id, []byte{}); err != nil {
			return err
		}
	}
	return nil
}

// deleteRecord removes a record and all its package links.
func deleteRecord(tx *bolt.Tx, id string) error {
	if err := dropStaleLinks(tx, id, nil); err != nil {
		return err
	}
	return tx.Bucket(bucketRecords).Delete([]byte(id))
}

// dropStaleLinks removes links from the stored version of id to packages not
// in keep, and package buckets left empty by that.
func dropStaleLinks(tx *bolt.Tx, id string, keep []string) error {
	value := tx.Bucket(bucketRecords).Get([]byte(id))
	if value == nil {
		return nil
	}
	var old Record
	if err := decodeRecord(value, &old); err != nil {
		return fmt.Errorf("index: record %s: %w", id, err)
	}
	pkg := tx.Bucket(bucketPkg)
	for _, name := range packageNames(&old) {
		if slices.Contains(keep, name) {
			continue
		}
		links := pkg.Bucket([]byte(name))
		if links == nil {
			continue
		}
		if err := links.Delete([]byte(id)); err != nil {
			return err
		}
		if k, _ := links.Cursor().First(); k == nil {
			if err := pkg.DeleteBucket([]byte(name)); err != nil {
				return err
			}
		}
	}
	return nil
}

// countIndex counts records and packages.
func countIndex(tx *bolt.Tx) (records, packages int) {
	c := tx.Bucket(bucketRecords).Cursor()
	for k, _ := c.First(); k != nil; k, _ = c.Next() {
		records++
	}
	c = tx.Bucket(bucketPkg).Cursor()
	for k, _ := c.First(); k != nil; k, _ = c.Next() {
		packages++
	}
	return records, packages
}
