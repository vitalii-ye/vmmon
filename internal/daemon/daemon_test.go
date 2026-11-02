package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vitalii-ye/vmmon/internal/config"
	"github.com/vitalii-ye/vmmon/internal/enrich"
	"github.com/vitalii-ye/vmmon/internal/finding"
	"github.com/vitalii-ye/vmmon/internal/inventory"
	"github.com/vitalii-ye/vmmon/internal/notify"
	"github.com/vitalii-ye/vmmon/internal/scan"
	"github.com/vitalii-ye/vmmon/internal/scan/scantest"
	"github.com/vitalii-ye/vmmon/internal/state"
	"github.com/vitalii-ye/vmmon/internal/telegram"
	"github.com/vitalii-ye/vmmon/internal/telegram/telegramtest"
	"github.com/vitalii-ye/vmmon/internal/vulndb"
)

const eco = "Debian:12"

// Message kinds, told apart by their headings.
const (
	kindSummary  = "scan summary"
	kindAlert    = "new vulnerabilit"
	kindEscalate = "escalated"
	kindDigest   = " digest"
	kindStale    = "database is stale"
)

// fakeNotifier records deliveries and fails on demand.
type fakeNotifier struct {
	mu   sync.Mutex
	sent []string
	err  error
}

func (n *fakeNotifier) Name() string { return "fake" }

func (n *fakeNotifier) Send(_ context.Context, html string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.err != nil {
		return n.err
	}
	n.sent = append(n.sent, html)
	return nil
}

// world is everything outside the daemon, moved by hand. Daemons built from one
// world share its state file, so a second one is a restart.
type world struct {
	t   *testing.T
	cfg *config.Config
	now time.Time
	loc *time.Location
	n   *fakeNotifier

	findings []finding.Finding
	meta     vulndb.Meta
	mtime    time.Time

	syncErr error
	changed []string
	feedCh  enrich.Changes
	scanErr error
	scans   []scan.Options
}

func newWorld(t *testing.T) *world {
	t.Helper()
	cfg := config.Default()
	cfg.StateDir = t.TempDir()
	cfg.Hostname = "web-01"
	now := time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC)
	return &world{
		t: t, cfg: cfg, now: now, loc: time.UTC, n: &fakeNotifier{}, mtime: now.Add(-time.Hour),
		meta: vulndb.Meta{
			Ecosystems: map[string]vulndb.EcosystemMeta{eco: {LastSync: now}},
			KEV:        vulndb.FeedMeta{LastSync: now},
			EPSS:       vulndb.FeedMeta{LastSync: now},
		},
	}
}

func (w *world) deps() Deps {
	var notifier notify.Notifier
	if w.n != nil {
		notifier = w.n
	}
	return Deps{
		Now:      func() time.Time { return w.now },
		Location: w.loc,
		Inventory: func(context.Context) (*inventory.Host, error) {
			return &inventory.Host{Hostname: "web-01", Release: inventory.Release{Ecosystem: eco}}, nil
		},
		Scan:        w.scan,
		SyncDB:      w.syncDB,
		SyncFeeds:   w.syncFeeds,
		ReadMeta:    func() (vulndb.Meta, error) { return w.meta, nil },
		StatusMTime: func() (time.Time, error) { return w.mtime, nil },
		Notifier:    notifier,
	}
}

func (w *world) scan(_ context.Context, opts scan.Options) (*finding.Report, error) {
	w.scans = append(w.scans, opts)
	if w.scanErr != nil {
		return nil, w.scanErr
	}
	r := &finding.Report{Hostname: "web-01", Ecosystem: eco, Partial: opts.Only != nil, PackagesCount: 100}
	for _, f := range w.findings {
		if opts.Only == nil || opts.Only[f.SourcePackage] {
			r.Findings = append(r.Findings, f)
		}
	}
	r.Counts = finding.Count(r.Findings)
	return r, nil
}

func (w *world) syncDB(context.Context, inventory.Release) (vulndb.SyncResult, error) {
	em := w.meta.Ecosystems[eco]
	em.LastAttempt = w.now
	em.LastError = ""
	if w.syncErr != nil {
		em.LastError = w.syncErr.Error()
	} else {
		em.LastSync = w.now
	}
	w.meta.Ecosystems[eco] = em
	if w.syncErr != nil {
		return vulndb.SyncResult{}, w.syncErr
	}
	changed := w.changed
	w.changed = nil
	return vulndb.SyncResult{Mode: "incremental", ChangedPackages: changed}, nil
}

func (w *world) syncFeeds(context.Context) (enrich.Changes, error) {
	w.meta.KEV.LastSync, w.meta.EPSS.LastSync = w.now, w.now
	ch := w.feedCh
	w.feedCh = enrich.Changes{}
	return ch, nil
}

// start builds a daemon and runs Start: a process start, or a restart.
func (w *world) start() *Daemon {
	w.t.Helper()
	d := New(w.cfg, w.deps())
	if err := d.Start(context.Background()); err != nil {
		w.t.Fatal(err)
	}
	return d
}

// step runs both loop bodies once.
func (w *world) step(d *Daemon) {
	d.Step(context.Background())
	d.Deliver(context.Background())
}

// run advances the clock in steps and runs the daemon at each.
func (w *world) run(d *Daemon, total, every time.Duration) {
	for end := w.now.Add(total); w.now.Before(end); {
		w.now = w.now.Add(every)
		w.step(d)
	}
}

// settled returns a daemon past its first scan, with the summary taken away.
func (w *world) settled() *Daemon {
	w.t.Helper()
	d := w.start()
	w.step(d)
	if got := w.take(); len(got) != 1 || !strings.Contains(got[0], kindSummary) {
		w.t.Fatalf("first scan sent %q, want one summary", got)
	}
	return d
}

// take returns what was delivered since the last call.
func (w *world) take() []string {
	w.n.mu.Lock()
	defer w.n.mu.Unlock()
	sent := w.n.sent
	w.n.sent = nil
	return sent
}

// count returns how many messages are of a kind.
func count(msgs []string, kind string) int {
	n := 0
	for _, m := range msgs {
		if strings.Contains(m, kind) {
			n++
		}
	}
	return n
}

func (w *world) expect(kind string, want int) []string {
	w.t.Helper()
	msgs := w.take()
	if got := count(msgs, kind); got != want || (want > 0 && len(msgs) != want) {
		w.t.Fatalf("got %d %q messages, want %d; all: %q", got, kind, want, msgs)
	}
	return msgs
}

// onlyEscalation returns the one escalation sent since the last call. A run this
// long passes a digest too, which is not what the caller is checking.
func (w *world) onlyEscalation() string {
	w.t.Helper()
	var found []string
	for _, m := range w.take() {
		if strings.Contains(m, kindEscalate) {
			found = append(found, m)
		}
	}
	if len(found) != 1 {
		w.t.Fatalf("got %d escalations, want 1: %q", len(found), found)
	}
	return found[0]
}

func (w *world) expectNone() {
	w.t.Helper()
	if msgs := w.take(); len(msgs) != 0 {
		w.t.Fatalf("want no messages, got %q", msgs)
	}
}

// vuln is a finding that passes the quiet preset unless changed by mods.
func vuln(pkg, cve string, mods ...func(*finding.Finding)) finding.Finding {
	f := finding.Finding{
		ID: finding.NewID(eco, pkg, cve), Ecosystem: eco, SourcePackage: pkg, VulnID: cve,
		InstalledVersion: "1.0-1", FixStatus: finding.FixAvailable, FixedVersion: "1.1-1", CVSSScore: 7.5,
	}
	for _, m := range mods {
		m(&f)
	}
	return f
}

func noFix(f *finding.Finding)   { f.FixStatus, f.FixedVersion = finding.NoFixYet, "" }
func lowCVSS(f *finding.Finding) { f.CVSSScore = 3 }
func kev(f *finding.Finding)     { f.KEV = true }

// Digest time is 09:00, so this reaches the next one from 10:00.
const toNextDigest = 23 * time.Hour

func TestFirstScanIsOneSummaryNotAStorm(t *testing.T) {
	w := newWorld(t)
	for i := range 500 {
		w.findings = append(w.findings, vuln("foo", fmt.Sprintf("CVE-2026-%d", i)))
	}
	d := w.settled()
	w.findings = append(w.findings[:0:0], w.findings...)
	w.run(d, 12*time.Hour, 5*time.Minute)
	w.expectNone()
}

func TestNewAdvisoryAlertsOnceAndOnlyOnce(t *testing.T) {
	w := newWorld(t)
	w.findings = []finding.Finding{vuln("old", "CVE-2020-1")}
	d := w.settled()

	w.findings = append(w.findings, vuln("foo", "CVE-2026-1"), vuln("foo", "CVE-2026-2"))
	w.changed = []string{"foo"}
	w.run(d, w.cfg.DB.SyncInterval, 5*time.Minute)
	msgs := w.expect(kindAlert, 1) // All new findings of one scan in one message.
	if !strings.Contains(msgs[0], "2 new vulnerabilities") || !strings.HasPrefix(stripIcon(msgs[0]), "<b>web-01</b>") {
		t.Errorf("alert = %q", msgs[0])
	}
	if last := w.scans[len(w.scans)-1]; last.Only == nil || !last.Only["foo"] {
		t.Errorf("a sync should re-match only what changed, got %+v", last.Only)
	}

	w.changed = []string{"foo"}
	w.run(d, w.cfg.DB.SyncInterval, 5*time.Minute)
	w.expectNone()
}

func stripIcon(s string) string {
	_, rest, _ := strings.Cut(s, " ")
	return rest
}

func TestSyncWithoutChangesDoesNotScan(t *testing.T) {
	w := newWorld(t)
	d := w.settled()
	scans := len(w.scans)
	w.run(d, w.cfg.DB.SyncInterval, time.Hour)
	if len(w.scans) != scans {
		t.Errorf("ran %d scans for an empty change set", len(w.scans)-scans)
	}
}

func TestUpgradedPackageResolvesInDigest(t *testing.T) {
	w := newWorld(t)
	w.findings = []finding.Finding{vuln("openssl", "CVE-2026-1"), vuln("curl", "CVE-2026-2")}
	d := w.settled()

	w.findings = w.findings[1:]
	w.mtime = w.now
	w.run(d, 10*time.Minute, 5*time.Minute)
	w.expectNone() // Resolved is news for the digest, not an alert.

	w.run(d, toNextDigest, time.Hour)
	msgs := w.expect(kindDigest, 1)
	if !strings.Contains(msgs[0], "Resolved: 1") || !strings.Contains(msgs[0], "openssl: 1") || !strings.Contains(msgs[0], "Open: 1") {
		t.Errorf("digest = %q", msgs[0])
	}

	w.run(d, 24*time.Hour, time.Hour)
	if msgs := w.expect(kindDigest, 1); !strings.Contains(msgs[0], "Resolved: 0") {
		t.Errorf("a resolved finding must appear in one digest only: %q", msgs[0])
	}
}

func TestResolvedFindingThatReturnsIsNew(t *testing.T) {
	w := newWorld(t)
	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1")}
	d := w.settled()

	w.findings = nil
	w.mtime = w.now
	w.run(d, 5*time.Minute, 5*time.Minute)
	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1")}
	w.mtime = w.now
	w.run(d, 5*time.Minute, 5*time.Minute)
	w.expect(kindAlert, 1)
}

func TestKEVListingEscalatesOnce(t *testing.T) {
	w := newWorld(t)
	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1", lowCVSS)} // Below the policy.
	d := w.settled()

	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1", lowCVSS, kev)}
	w.feedCh = enrich.Changes{KEVChanged: true, NewKEV: []string{"CVE-2026-1"}}
	w.run(d, w.cfg.DB.EnrichInterval, time.Hour)
	if m := w.onlyEscalation(); !strings.Contains(m, "now KEV-listed") {
		t.Errorf("escalation = %q", m)
	}

	// It stays listed, and a flap off and on again is not news either.
	w.feedCh = enrich.Changes{KEVChanged: true}
	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1", lowCVSS)}
	w.run(d, w.cfg.DB.EnrichInterval, time.Hour)
	w.feedCh = enrich.Changes{KEVChanged: true}
	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1", lowCVSS, kev)}
	w.run(d, w.cfg.DB.EnrichInterval, time.Hour)
	for _, m := range w.take() {
		if strings.Contains(m, kindEscalate) {
			t.Errorf("repeated escalation: %q", m)
		}
	}
}

func TestFixBecomingAvailableEscalatesOnce(t *testing.T) {
	w := newWorld(t)
	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1", noFix)}
	d := w.settled()

	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1")}
	w.changed = []string{"foo"}
	w.run(d, w.cfg.DB.SyncInterval, time.Hour)
	if msgs := w.expect(kindEscalate, 1); !strings.Contains(msgs[0], "fix now available") {
		t.Errorf("escalation = %q", msgs[0])
	}
	w.changed = []string{"foo"}
	w.run(d, w.cfg.DB.SyncInterval, time.Hour)
	w.expectNone()
}

// The plan re-evaluates policy on a feed refresh: rising EPSS is news once.
func TestEPSSCrossingThresholdEscalatesOnce(t *testing.T) {
	w := newWorld(t)
	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1", lowCVSS)}
	d := w.settled()

	rise := func(f *finding.Finding) { f.EPSS = 0.42 }
	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1", lowCVSS, rise)}
	w.feedCh = enrich.Changes{EPSSUpdated: true}
	w.run(d, w.cfg.DB.EnrichInterval, time.Hour)
	if m := w.onlyEscalation(); !strings.Contains(m, "now meets the alert policy") {
		t.Errorf("escalation = %q", m)
	}

	// Falling and rising again is not news a second time.
	w.feedCh = enrich.Changes{EPSSUpdated: true}
	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1", lowCVSS)}
	w.run(d, w.cfg.DB.EnrichInterval, time.Hour)
	w.feedCh = enrich.Changes{EPSSUpdated: true}
	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1", lowCVSS, rise)}
	w.run(d, w.cfg.DB.EnrichInterval, time.Hour)
	for _, m := range w.take() {
		if strings.Contains(m, kindEscalate) {
			t.Errorf("repeated escalation: %q", m)
		}
	}
}

func TestSyncFailing48HoursAlertsOncePerEpisode(t *testing.T) {
	w := newWorld(t)
	d := w.settled()

	w.syncErr = errors.New("connection refused")
	w.run(d, 47*time.Hour, time.Hour)
	if n := count(w.take(), kindStale); n != 0 {
		t.Fatalf("%d staleness alerts before 48 h", n)
	}
	w.run(d, 2*time.Hour, time.Hour)
	msgs := w.take()
	if count(msgs, kindStale) != 1 {
		t.Fatalf("want one staleness alert, got %q", msgs)
	}
	w.run(d, 72*time.Hour, time.Hour)
	if n := count(w.take(), kindStale); n != 0 {
		t.Fatalf("%d repeated staleness alerts", n)
	}

	// A restart keeps the episode.
	d = w.start()
	w.run(d, 24*time.Hour, time.Hour)
	if n := count(w.take(), kindStale); n != 0 {
		t.Fatalf("%d staleness alerts after restart", n)
	}

	// A good sync ends it, and a later episode alerts again.
	w.syncErr = nil
	w.run(d, 2*time.Hour, 5*time.Minute)
	w.take()
	w.syncErr = errors.New("still broken")
	w.run(d, 50*time.Hour, time.Hour)
	if n := count(w.take(), kindStale); n != 1 {
		t.Fatalf("second episode sent %d alerts, want 1", n)
	}
}

func TestNeverSyncedDatabaseGoesStaleFromFirstStart(t *testing.T) {
	w := newWorld(t)
	w.meta = vulndb.Meta{Ecosystems: map[string]vulndb.EcosystemMeta{}}
	w.syncErr = errors.New("no network")
	w.scanErr = vulndb.ErrNoDB
	d := w.start()
	w.run(d, 50*time.Hour, time.Hour)
	msgs := w.take()
	if count(msgs, kindStale) != 1 || count(msgs, kindSummary) != 0 {
		t.Fatalf("got %q", msgs)
	}
}

func TestConcurrentSyncIsASkippedCycle(t *testing.T) {
	w := newWorld(t)
	d := w.settled()
	w.syncErr = vulndb.ErrSyncInProgress
	w.now = w.now.Add(w.cfg.DB.SyncInterval)
	w.step(d)
	if d.syncBackoff.cur != 0 {
		t.Error("a skipped cycle must not count as a failure")
	}
	if want := w.now.Add(skippedRetry); !d.nextDBSync.Equal(want) {
		t.Errorf("next sync %v, want %v", d.nextDBSync, want)
	}
}

func TestSyncOutsideTheDaemonTriggersFullRescan(t *testing.T) {
	w := newWorld(t)
	d := w.settled()
	w.now = w.now.Add(time.Minute)
	em := w.meta.Ecosystems[eco]
	em.LastSync = w.now
	w.meta.Ecosystems[eco] = em
	scans := len(w.scans)
	w.step(d)
	if len(w.scans) != scans+1 || w.scans[scans].Only != nil {
		t.Errorf("want one full scan, got %+v", w.scans[scans:])
	}
}

func TestRestartDoesNotRepeatAnything(t *testing.T) {
	w := newWorld(t)
	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1", kev), vuln("bar", "CVE-2026-2")}
	d := w.settled()
	w.findings = append(w.findings, vuln("baz", "CVE-2026-3"))
	w.mtime = w.now
	w.run(d, 5*time.Minute, 5*time.Minute)
	w.expect(kindAlert, 1)

	for range 3 {
		d = w.start()
		w.run(d, 10*time.Minute, 5*time.Minute)
		w.expectNone()
	}
}

func TestPartialScanResolvesOnlyWhatItCovered(t *testing.T) {
	w := newWorld(t)
	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1"), vuln("bar", "CVE-2026-2")}
	d := w.settled()

	// Only foo changed and bar's finding is untouched; foo's advisory is gone.
	w.findings = []finding.Finding{vuln("bar", "CVE-2026-2")}
	w.changed = []string{"foo"}
	w.run(d, w.cfg.DB.SyncInterval, time.Hour)
	o := w.overview()
	if o.Counts.Total != 1 {
		t.Errorf("open = %d, want 1", o.Counts.Total)
	}
	w.expectNone()
}

func (w *world) overview() state.Overview {
	w.t.Helper()
	var o state.Overview
	err := state.New(w.cfg.StatePath(), 0).View(func(tx *state.Tx) error {
		var err error
		o, err = tx.Overview()
		return err
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return o
}

func (w *world) queueLen() int {
	w.t.Helper()
	n := 0
	err := state.New(w.cfg.StatePath(), 0).View(func(tx *state.Tx) error {
		n = tx.QueueLen()
		return nil
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return n
}

func TestOutageDelaysAlertsAndDeliversThemOnce(t *testing.T) {
	w := newWorld(t)
	d := w.settled()

	w.n.err = errors.New("network down")
	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1")}
	w.mtime = w.now
	w.run(d, 2*time.Hour, 5*time.Minute)
	if w.queueLen() != 1 {
		t.Fatalf("queue = %d, want the alert kept", w.queueLen())
	}
	w.expectNone()

	w.n.err = nil
	w.run(d, 2*time.Hour, 5*time.Minute)
	w.expect(kindAlert, 1)
	if w.queueLen() != 0 {
		t.Errorf("queue = %d, want empty", w.queueLen())
	}
}

func TestPartialDeliveryResumesWithTheRemainder(t *testing.T) {
	w := newWorld(t)
	d := w.settled()

	w.n.err = &notify.SendError{Err: errors.New("boom"), Remaining: "the rest", Delivered: 1, Total: 2}
	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1")}
	w.mtime = w.now
	w.run(d, 5*time.Minute, 5*time.Minute)
	w.n.err = nil
	w.run(d, time.Hour, 5*time.Minute)
	if msgs := w.take(); len(msgs) != 1 || msgs[0] != "the rest" {
		t.Errorf("got %q, want only the undelivered part", msgs)
	}
}

func TestPermanentFailureKeepsMessagesAndRetriesSlowly(t *testing.T) {
	w := newWorld(t)
	d := w.settled()

	w.n.err = fmt.Errorf("revoked: %w", notify.ErrPermanent)
	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1")}
	w.mtime = w.now
	w.run(d, 5*time.Minute, 5*time.Minute)
	if got := d.nextSend.Sub(w.now); got != sendMaxBackoff {
		t.Errorf("retry in %v, want %v", got, sendMaxBackoff)
	}
	if w.queueLen() != 1 {
		t.Errorf("queue = %d, want the alert kept for after re-running setup", w.queueLen())
	}
	var ch state.Channel
	err := state.New(w.cfg.StatePath(), 0).View(func(tx *state.Tx) error {
		m, err := tx.Meta()
		ch = m.Channel
		return err
	})
	if err != nil || !ch.Permanent || ch.LastError == "" {
		t.Errorf("channel = %+v, err %v", ch, err)
	}
}

func TestCrashBetweenCommitAndSendDeliversAfterRestartOnce(t *testing.T) {
	w := newWorld(t)
	d := w.settled()

	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1")}
	w.mtime = w.now
	w.now = w.now.Add(5 * time.Minute)
	d.Step(context.Background()) // Committed, then the process dies before Deliver.
	w.expectNone()

	d = w.start()
	w.step(d)
	w.expect(kindAlert, 1)
	w.run(d, time.Hour, 5*time.Minute)
	w.expectNone()
}

func TestQueueOverflowIsReported(t *testing.T) {
	w := newWorld(t)
	d := w.settled()
	w.n.err = errors.New("network down")
	for i := range state.MaxQueue + 3 {
		w.findings = append(w.findings, vuln("foo", fmt.Sprintf("CVE-2026-%d", i)))
		w.mtime = w.now.Add(time.Duration(i) * time.Second)
		w.now = w.now.Add(5 * time.Minute)
		d.Step(context.Background())
	}
	if w.queueLen() != state.MaxQueue {
		t.Fatalf("queue = %d, want capped at %d", w.queueLen(), state.MaxQueue)
	}
	w.n.err = nil
	d = w.start()
	w.step(d)
	msgs := w.take()
	if len(msgs) != state.MaxQueue || !strings.Contains(msgs[0], "lost in a long outage") {
		t.Fatalf("got %d messages, first %q", len(msgs), msgs[0])
	}
}

func TestHugeBatchIsOneBoundedAlert(t *testing.T) {
	w := newWorld(t)
	d := w.settled()
	for i := range 12000 {
		w.findings = append(w.findings, vuln("linux", fmt.Sprintf("CVE-2026-%d", i)))
	}
	w.changed = []string{"linux"}
	w.run(d, w.cfg.DB.SyncInterval, time.Hour)
	msgs := w.expect(kindAlert, 1)
	if !strings.Contains(msgs[0], "12000 new vulnerabilities") || !strings.Contains(msgs[0], "more") {
		t.Errorf("heading or remainder missing: %.200q", msgs[0])
	}
	if len(msgs[0]) > 4096 {
		t.Errorf("alert is %d bytes, want one Telegram message", len(msgs[0]))
	}
}

func TestPresets(t *testing.T) {
	for _, tc := range []struct {
		preset string
		f      finding.Finding
		alert  bool
	}{
		{config.PresetQuiet, vuln("foo", "CVE-1"), true},
		{config.PresetQuiet, vuln("foo", "CVE-1", lowCVSS), false},
		{config.PresetQuiet, vuln("foo", "CVE-1", noFix), false},
		{config.PresetQuiet, vuln("foo", "CVE-1", noFix, kev), true},
		{config.PresetQuiet, vuln("foo", "CVE-1", func(f *finding.Finding) { f.SeverityLabel = "unimportant" }), false},
		{config.PresetCritical, vuln("foo", "CVE-1"), false},
		{config.PresetCritical, vuln("foo", "CVE-1", kev), true},
		{config.PresetEverything, vuln("foo", "CVE-1", lowCVSS, noFix), true},
	} {
		t.Run(fmt.Sprintf("%s %+v", tc.preset, tc.alert), func(t *testing.T) {
			w := newWorld(t)
			w.cfg.Policy.Preset = tc.preset
			d := w.settled()
			w.findings = []finding.Finding{tc.f}
			w.mtime = w.now
			w.run(d, 5*time.Minute, 5*time.Minute)
			want := 0
			if tc.alert {
				want = 1
			}
			if got := count(w.take(), kindAlert); got != want {
				t.Errorf("%d alerts, want %d", got, want)
			}
		})
	}
}

func TestBelowPolicyFindingsReachTheDigest(t *testing.T) {
	w := newWorld(t)
	d := w.settled()
	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1", lowCVSS)}
	w.mtime = w.now
	w.run(d, 5*time.Minute, 5*time.Minute)
	w.expectNone()
	w.run(d, toNextDigest, time.Hour)
	if msgs := w.expect(kindDigest, 1); !strings.Contains(msgs[0], "below the alert policy: 1") {
		t.Errorf("digest = %q", msgs[0])
	}
}

func TestDigestCadence(t *testing.T) {
	t.Run("daily", func(t *testing.T) {
		w := newWorld(t)
		d := w.settled()
		w.run(d, 72*time.Hour, 30*time.Minute)
		if got := count(w.take(), "daily digest"); got != 3 {
			t.Errorf("%d digests in 3 days", got)
		}
	})
	t.Run("weekly under the critical preset", func(t *testing.T) {
		w := newWorld(t)
		w.cfg.Policy.Preset = config.PresetCritical
		d := w.settled()
		w.run(d, 15*24*time.Hour, time.Hour)
		if got := count(w.take(), "weekly digest"); got != 2 {
			t.Errorf("%d digests in 15 days", got)
		}
	})
	t.Run("restart does not double-send", func(t *testing.T) {
		w := newWorld(t)
		d := w.settled()
		w.run(d, toNextDigest, time.Hour)
		w.expect(kindDigest, 1)
		d = w.start()
		w.run(d, 12*time.Hour, 30*time.Minute)
		w.expectNone()
	})
	t.Run("a digest missed while down goes out once", func(t *testing.T) {
		w := newWorld(t)
		w.settled()
		w.now = w.now.Add(72 * time.Hour)
		em := w.meta.Ecosystems[eco]
		em.LastSync = w.now
		w.meta.Ecosystems[eco] = em
		w.meta.KEV.LastSync, w.meta.EPSS.LastSync = w.now, w.now
		d := w.start()
		w.step(d)
		w.run(d, 2*time.Hour, 30*time.Minute)
		if got := count(w.take(), kindDigest); got != 1 {
			t.Errorf("%d digests", got)
		}
	})
}

func TestDigestAcrossDSTRunsOncePerDay(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Kyiv")
	if err != nil {
		t.Skip("no time zone data:", err)
	}
	for _, tc := range []struct {
		name  string
		start time.Time
	}{
		{"spring forward", time.Date(2026, 3, 27, 12, 0, 0, 0, loc)},
		{"fall back", time.Date(2026, 10, 23, 12, 0, 0, 0, loc)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.loc = loc
			w.now = tc.start
			em := w.meta.Ecosystems[eco]
			em.LastSync = w.now
			w.meta.Ecosystems[eco] = em
			w.meta.KEV.LastSync, w.meta.EPSS.LastSync = w.now, w.now
			d := w.settled()
			w.run(d, 4*24*time.Hour, 15*time.Minute)
			if got := count(w.take(), kindDigest); got != 4 {
				t.Errorf("%d digests in 4 days", got)
			}
		})
	}
}

func TestFailedScanRetriesWithBackoffAndDigestSaysSo(t *testing.T) {
	w := newWorld(t)
	d := w.settled()
	w.scanErr = errors.New("disk on fire")
	w.mtime = w.now
	w.run(d, 5*time.Minute, 5*time.Minute)
	if d.scanBackoff.cur == 0 || !d.pendingFull {
		t.Fatalf("backoff %v, pending %v", d.scanBackoff.cur, d.pendingFull)
	}
	w.run(d, toNextDigest, time.Hour)
	if msgs := w.expect(kindDigest, 1); !strings.Contains(msgs[0], "disk on fire") {
		t.Errorf("digest = %q", msgs[0])
	}
	w.scanErr = nil
	w.run(d, 2*time.Hour, 5*time.Minute)
	if d.pendingFull {
		t.Error("the rescan should have run once scans work again")
	}
}

func TestNoChannelThenConfiguredGetsASummary(t *testing.T) {
	w := newWorld(t)
	notifier := w.n
	w.n = nil
	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1", kev)}
	d := w.start()
	w.run(d, 26*time.Hour, time.Hour)
	if w.queueLen() != 0 {
		t.Fatalf("queue = %d with no channel", w.queueLen())
	}

	w.n = notifier
	d = w.start()
	w.step(d)
	w.expect(kindSummary, 1)
	w.run(d, time.Hour, 5*time.Minute)
	w.expectNone()
}

func TestStatusReadsWhileDaemonRuns(t *testing.T) {
	w := newWorld(t)
	w.findings = []finding.Finding{vuln("foo", "CVE-2026-1", kev)}
	d := w.settled()
	if got := w.overview(); got.Counts.KEV != 1 || len(got.KEV) != 1 {
		t.Errorf("overview = %+v", got)
	}
	// The daemon holds no file between operations: a reader never needs it stopped.
	r := state.New(w.cfg.StatePath(), 50*time.Millisecond)
	if err := r.View(func(*state.Tx) error { return nil }); err != nil {
		t.Errorf("view between steps: %v", err)
	}
	d.Deliver(context.Background())
}

func TestSlots(t *testing.T) {
	cfg := config.Default()
	d := New(cfg, Deps{Location: time.UTC})
	at := func(day, hour int) time.Time { return time.Date(2026, 3, day, hour, 0, 0, 0, time.UTC) }
	if got := d.digestAfter(time.Time{}, at(2, 8)); !got.Equal(at(2, 9)) {
		t.Errorf("before the slot: %v", got)
	}
	if got := d.digestAfter(time.Time{}, at(2, 10)); !got.Equal(at(3, 9)) {
		t.Errorf("after the slot: %v", got)
	}
	if got := d.digestAfter(at(3, 9), at(1, 0)); !got.Equal(at(4, 9)) {
		t.Errorf("after a digest: %v", got)
	}
}

// One path through the real scan pipeline, state file and Bot API client: a new
// advisory on a real fixture root ends as one Telegram message.
func TestEndToEndThroughRealScanAndTelegram(t *testing.T) {
	const root = "../inventory/testdata/debian12"
	now := time.Now().UTC()
	clock := now

	server := telegramtest.New(t)
	cfg := config.Default()
	cfg.StateDir = t.TempDir()
	cfg.Hostname = "web-01"
	cfg.Telegram.Token, cfg.Telegram.ChatID, cfg.Telegram.APIBaseURL = telegramtest.Token, "42", server.URL

	build := func(records map[string][]byte) {
		scantest.BuildDB(t, cfg.DBDir(), eco, "Debian", records, scantest.Feeds{
			KEV:  []byte(`{"catalogVersion":"1","vulnerabilities":[{"cveID":"CVE-1999-1","dateAdded":"2020-01-01"}]}`),
			EPSS: []byte("#model\ncve,epss,percentile\nCVE-2026-1,0.5,0.9\n"),
		}, clock)
	}
	build(map[string][]byte{"DEBIAN-CVE-2020-1.json": scantest.Record("DEBIAN-CVE-2020-1", eco, "bash", "9.9-1")})

	notifier := notify.NewTelegram(telegram.New(server.URL, telegramtest.Token, nil), "42")
	notifier.SetClock(func() time.Time { return clock }, func(context.Context, time.Duration) error { return nil })

	var changed []string
	d := New(cfg, Deps{
		Now:      func() time.Time { return clock },
		Location: time.UTC,
		Root:     root,
		SyncDB: func(context.Context, inventory.Release) (vulndb.SyncResult, error) {
			c := changed
			changed = nil
			return vulndb.SyncResult{Mode: "incremental", ChangedPackages: c}, nil
		},
		SyncFeeds: func(context.Context) (enrich.Changes, error) { return enrich.Changes{}, nil },
		Notifier:  notifier,
	})
	ctx := context.Background()
	if err := d.Start(ctx); err != nil {
		t.Fatal(err)
	}
	d.Step(ctx)
	d.Deliver(ctx)
	sent := server.Sent()
	if len(sent) != 1 || !strings.Contains(sent[0].Text, "scan summary") || !strings.Contains(sent[0].Text, "1 finding") {
		t.Fatalf("first scan sent %+v", sent)
	}

	// A new advisory arrives: the real index gains a record affecting installed bash.
	clock = clock.Add(cfg.DB.SyncInterval + time.Minute)
	record := scantest.Record("DEBIAN-CVE-2026-1", eco, "bash", "9.9-1")
	build(map[string][]byte{
		"DEBIAN-CVE-2020-1.json": scantest.Record("DEBIAN-CVE-2020-1", eco, "bash", "9.9-1"),
		"DEBIAN-CVE-2026-1.json": record,
	})
	changed = []string{"bash"}
	d.Step(ctx)
	d.Deliver(ctx)
	sent = server.Sent()
	if len(sent) != 2 || !strings.Contains(sent[1].Text, "1 new vulnerability") || !strings.Contains(sent[1].Text, "CVE-2026-1") {
		t.Fatalf("after the advisory sent %+v", sent[1:])
	}
	if !strings.Contains(sent[1].Text, "EPSS") {
		t.Errorf("alert lacks real enrichment: %q", sent[1].Text)
	}

	changed = []string{"bash"}
	clock = clock.Add(cfg.DB.SyncInterval + time.Minute)
	d.Step(ctx)
	d.Deliver(ctx)
	if got := len(server.Sent()); got != 2 {
		t.Errorf("sent %d messages, want no repeat", got)
	}
}
