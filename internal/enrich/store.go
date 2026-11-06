package enrich

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/vitalii-ye/vmmon/internal/config"
	"github.com/vitalii-ye/vmmon/internal/fsutil"
	"github.com/vitalii-ye/vmmon/internal/vulndb"
)

const (
	kevFile  = "kev.json"
	epssFile = "epss.bolt"

	epssBatch       = 20000
	viewOpenTimeout = 10 * time.Second
)

var bucketEPSS = []byte("epss")

// Options configures a Store.
type Options struct {
	KEVURL  string
	EPSSURL string
	// HTTPClient defaults to vulndb.HTTPClient().
	HTTPClient *http.Client
	// Now defaults to time.Now.
	Now func() time.Time
	// Download tunes retries and stall detection.
	Download vulndb.DownloadOptions
}

// Store keeps kev.json and epss.bolt in the data directory. It holds no open
// files between calls.
type Store struct {
	dir  string
	opts Options
}

// New returns a Store for dir, which need not exist yet.
func New(dir string, opts Options) *Store {
	if opts.HTTPClient == nil {
		opts.HTTPClient = vulndb.HTTPClient()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Store{dir: dir, opts: opts}
}

// Open returns the Store configured by cfg.
func Open(cfg *config.Config) *Store {
	return New(cfg.DBDir(), Options{KEVURL: cfg.DB.KEVURL, EPSSURL: cfg.DB.EPSSURL})
}

// Changes reports what one Sync did.
type Changes struct {
	// KEVChanged is true when listed CVEs or their dates differ.
	KEVChanged bool
	// NewKEV lists CVEs newly in the catalog, sorted. On the first sync that is
	// the whole catalog.
	NewKEV []string
	// EPSSUpdated is true when a different scores file was installed.
	EPSSUpdated bool
}

// Sync refreshes both feeds. They are independent: when one fails the other
// still updates, and the failing one keeps its previous data. The Changes value
// is valid even when the error is not nil. A concurrent sync of the same
// directory fails with vulndb.ErrSyncInProgress.
func (s *Store) Sync(ctx context.Context) (Changes, error) {
	var ch Changes
	if err := vulndb.EnsureDir(s.dir); err != nil {
		return ch, err
	}
	unlock, err := vulndb.TryLock(filepath.Join(s.dir, "enrich.lock"))
	if err != nil {
		return ch, err
	}
	defer unlock()
	vulndb.RemoveTemps(s.dir, "kev.")
	vulndb.RemoveTemps(s.dir, "epss.")

	meta, err := vulndb.ReadMeta(s.dir)
	if err != nil {
		meta = vulndb.Meta{} // UpdateMeta replaces it; both feeds simply refresh.
	}

	kev := feedUpdate{attempt: s.opts.Now()}
	ch.KEVChanged, ch.NewKEV, kev.records, kev.version, kev.err = s.syncKEV(ctx)
	epss := feedUpdate{attempt: s.opts.Now()}
	ch.EPSSUpdated, epss.records, epss.version, epss.sum, epss.err = s.syncEPSS(ctx, meta.EPSS.SHA256)

	now := s.opts.Now()
	metaErr := vulndb.UpdateMeta(s.dir, func(m *vulndb.Meta) {
		kev.apply(&m.KEV, now)
		epss.apply(&m.EPSS, now)
	})
	return ch, errors.Join(wrap("KEV", kev.err), wrap("EPSS", epss.err), metaErr)
}

func wrap(feed string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", feed, err)
}

// feedUpdate is the outcome of one feed's sync, for meta.json.
type feedUpdate struct {
	attempt time.Time
	records int
	version string
	sum     string
	err     error
}

func (u feedUpdate) apply(m *vulndb.FeedMeta, now time.Time) {
	m.LastAttempt = u.attempt
	if u.err != nil {
		m.LastError = u.err.Error()
		return
	}
	m.LastError = ""
	m.LastSync = now
	m.Records = u.records
	m.Version = u.version
	m.SHA256 = u.sum
}

// download fetches url into a temp file in the data directory, never /tmp, and
// returns it rewound along with its checksum and a cleanup function.
func (s *Store) download(ctx context.Context, url, pattern string) (*os.File, string, func(), error) {
	f, err := os.CreateTemp(s.dir, pattern)
	if err != nil {
		return nil, "", nil, err
	}
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}
	sum, err := vulndb.Download(ctx, s.opts.HTTPClient, url, f, s.opts.Download)
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		cleanup()
		return nil, "", nil, err
	}
	return f, sum, cleanup, nil
}

// kevData is kev.json: what vmmon needs from CISA's catalog, without its long
// free-text fields.
type kevData struct {
	CatalogVersion string     `json:"catalogVersion"`
	Vulns          []kevEntry `json:"vulnerabilities"`
}

type kevEntry struct {
	CVE       string `json:"cveID"`
	DateAdded string `json:"dateAdded"`
}

// parseKEV reads either CISA's catalog or kev.json, which share a shape.
func parseKEV(r io.Reader) (*kevData, error) {
	var d kevData
	if err := json.NewDecoder(r).Decode(&d); err != nil {
		return nil, err
	}
	if len(d.Vulns) == 0 {
		return nil, errors.New("catalog lists no vulnerabilities")
	}
	for i := range d.Vulns {
		e := &d.Vulns[i]
		e.CVE = normalizeCVE(e.CVE)
		if !strings.HasPrefix(e.CVE, "CVE-") {
			return nil, fmt.Errorf("bad cveID %q", e.CVE)
		}
		if _, err := time.Parse(time.DateOnly, e.DateAdded); err != nil {
			return nil, fmt.Errorf("%s: bad dateAdded %q", e.CVE, e.DateAdded)
		}
	}
	slices.SortFunc(d.Vulns, func(a, b kevEntry) int { return strings.Compare(a.CVE, b.CVE) })
	return &d, nil
}

func normalizeCVE(cve string) string { return strings.ToUpper(strings.TrimSpace(cve)) }

func (s *Store) readKEV() (*kevData, error) {
	f, err := os.Open(filepath.Join(s.dir, kevFile))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return parseKEV(f)
}

func (s *Store) syncKEV(ctx context.Context) (changed bool, added []string, records int, version string, err error) {
	f, _, cleanup, err := s.download(ctx, s.opts.KEVURL, "kev.download.tmp-*")
	if err != nil {
		return false, nil, 0, "", err
	}
	defer cleanup()
	next, err := parseKEV(f)
	if err != nil {
		return false, nil, 0, "", fmt.Errorf("parse: %w", err)
	}

	prev := map[string]string{}
	if old, err := s.readKEV(); err == nil {
		for _, e := range old.Vulns {
			prev[e.CVE] = e.DateAdded
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		changed = true // Whatever was there is unusable.
	}
	for _, e := range next.Vulns {
		date, ok := prev[e.CVE]
		if !ok {
			added = append(added, e.CVE)
		}
		if !ok || date != e.DateAdded {
			changed = true
		}
	}
	if len(prev) != len(next.Vulns) {
		changed = true
	}
	data, err := json.Marshal(next)
	if err != nil {
		return false, nil, 0, "", err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(s.dir, kevFile), data, 0o644); err != nil {
		return false, nil, 0, "", err
	}
	return changed, added, len(next.Vulns), next.CatalogVersion, nil
}

func (s *Store) syncEPSS(ctx context.Context, prevSum string) (updated bool, records int, version, sum string, err error) {
	f, sum, cleanup, err := s.download(ctx, s.opts.EPSSURL, "epss.download.tmp-*")
	if err != nil {
		return false, 0, "", "", err
	}
	defer cleanup()
	tmp, err := os.CreateTemp(s.dir, "epss.bolt.tmp-*")
	if err != nil {
		return false, 0, "", "", err
	}
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmp.Name()) }()

	path := filepath.Join(s.dir, epssFile)
	if _, err := os.Stat(path); err == nil && sum == prevSum {
		meta, err := vulndb.ReadMeta(s.dir)
		if err != nil {
			return false, 0, "", "", err
		}
		return false, meta.EPSS.Records, meta.EPSS.Version, sum, nil
	}
	records, version, err = buildEPSS(f, tmp.Name())
	if err != nil {
		return false, 0, "", "", fmt.Errorf("parse: %w", err)
	}
	compacted, err := vulndb.Compact(tmp.Name())
	if err != nil {
		return false, 0, "", "", err
	}
	defer func() { _ = os.Remove(compacted) }()
	if err := vulndb.PublishFile(compacted, path); err != nil {
		return false, 0, "", "", err
	}
	return true, records, version, sum, nil
}

// buildEPSS streams the gzip CSV into a new bolt file at path. It keeps one
// batch of rows in memory.
func buildEPSS(r io.Reader, path string) (records int, version string, err error) {
	gz, err := gzip.NewReader(bufio.NewReaderSize(r, 64<<10))
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = gz.Close() }()
	br := bufio.NewReaderSize(gz, 64<<10)
	version, err = readEPSSComments(br)
	if err != nil {
		return 0, "", err
	}
	cr := csv.NewReader(br)
	cr.FieldsPerRecord = 3
	cr.ReuseRecord = true
	header, err := cr.Read()
	if err != nil {
		return 0, "", fmt.Errorf("header: %w", err)
	}
	if !strings.EqualFold(header[0], "cve") || !strings.EqualFold(header[1], "epss") || !strings.EqualFold(header[2], "percentile") {
		return 0, "", fmt.Errorf("unexpected header %q", header)
	}

	db, err := bolt.Open(path, 0o644, &bolt.Options{NoSync: true, NoFreelistSync: true, Timeout: time.Second})
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = db.Close() }()
	for done := false; !done; {
		err := db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists(bucketEPSS)
			if err != nil {
				return err
			}
			b.FillPercent = 0.9
			for range epssBatch {
				row, err := cr.Read()
				if errors.Is(err, io.EOF) {
					done = true
					return nil
				}
				if err != nil {
					return err
				}
				key, value, err := encodeEPSS(row)
				if err != nil {
					return err
				}
				if err := b.Put(key, value); err != nil {
					return err
				}
				records++
			}
			return nil
		})
		if err != nil {
			return 0, "", err
		}
	}
	if records == 0 {
		return 0, "", errors.New("file has no rows")
	}
	if err := db.Sync(); err != nil {
		return 0, "", err
	}
	return records, version, db.Close()
}

// readEPSSComments consumes leading "#" lines such as
// "#model_version:v2026.06.15,score_date:2026-11-02T12:00:30Z" and returns the
// score date when there is one.
func readEPSSComments(br *bufio.Reader) (string, error) {
	version := ""
	for {
		next, err := br.Peek(1)
		if err != nil {
			return "", fmt.Errorf("header: %w", err)
		}
		if next[0] != '#' {
			return version, nil
		}
		line, err := br.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("header: %w", err)
		}
		for _, part := range strings.Split(strings.TrimSpace(line[1:]), ",") {
			if v, ok := strings.CutPrefix(part, "score_date:"); ok {
				version = v
			}
		}
	}
}

func encodeEPSS(row []string) (key, value []byte, err error) {
	cve := normalizeCVE(row[0])
	if !strings.HasPrefix(cve, "CVE-") {
		return nil, nil, fmt.Errorf("bad cve %q", row[0])
	}
	score, err := parseProbability(row[1])
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", cve, err)
	}
	pct, err := parseProbability(row[2])
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", cve, err)
	}
	value = make([]byte, 16)
	binary.BigEndian.PutUint64(value, math.Float64bits(score))
	binary.BigEndian.PutUint64(value[8:], math.Float64bits(pct))
	return []byte(cve), value, nil
}

func parseProbability(s string) (float64, error) {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 || v > 1 {
		return 0, fmt.Errorf("bad probability %q", s)
	}
	return v, nil
}

// View makes both feeds available for the duration of fn, so matching does not
// reopen files per CVE. A feed that has never synced simply knows nothing: scans
// work offline without enrichment, and meta.json shows why it is missing.
func (s *Store) View(ctx context.Context, fn func(Lookup) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l := lookup{kev: map[string]string{}}
	data, err := s.readKEV()
	switch {
	case err == nil:
		for _, e := range data.Vulns {
			l.kev[e.CVE] = e.DateAdded
		}
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("read %s: %w", kevFile, err)
	}

	path := filepath.Join(s.dir, epssFile)
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return fn(l)
	}
	db, err := bolt.Open(path, 0o644, &bolt.Options{ReadOnly: true, Timeout: viewOpenTimeout})
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = db.Close() }()
	return db.View(func(tx *bolt.Tx) error {
		l.epss = tx.Bucket(bucketEPSS)
		return fn(l)
	})
}

type lookup struct {
	kev  map[string]string
	epss *bolt.Bucket
}

// Lookup implements Lookup; CVE IDs match case-insensitively.
func (l lookup) Lookup(cve string) (Info, error) {
	cve = normalizeCVE(cve)
	var info Info
	if date, ok := l.kev[cve]; ok {
		t, err := time.Parse(time.DateOnly, date)
		if err != nil {
			return Info{}, fmt.Errorf("%s: bad KEV date %q", cve, date)
		}
		info.KEV, info.KEVDateAdded = true, t
	}
	if l.epss != nil {
		if v := l.epss.Get([]byte(cve)); len(v) == 16 {
			info.EPSS = math.Float64frombits(binary.BigEndian.Uint64(v))
			info.EPSSPercentile = math.Float64frombits(binary.BigEndian.Uint64(v[8:]))
		}
	}
	return info, nil
}
