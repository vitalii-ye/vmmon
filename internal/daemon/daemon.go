// Package daemon is vmmon's long-running loop: it keeps the vulnerability data
// fresh, rescans on the plan's triggers, diffs each scan against state, and
// delivers what the alert policy lets through.
//
// Two goroutines share the state file. The main loop runs Step: syncs and scans,
// one at a time, so a slow download delays a rescan by minutes at worst. The send
// loop runs Deliver, so a Telegram outage delays neither. A state change and the
// message about it commit in one transaction, then delivery happens: a crash
// loses no alert and repeats none, apart from the at-least-once case described in
// notify.Undelivered.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/vitalii-ye/vmmon/internal/config"
	"github.com/vitalii-ye/vmmon/internal/enrich"
	"github.com/vitalii-ye/vmmon/internal/finding"
	"github.com/vitalii-ye/vmmon/internal/inventory"
	"github.com/vitalii-ye/vmmon/internal/notify"
	"github.com/vitalii-ye/vmmon/internal/policy"
	"github.com/vitalii-ye/vmmon/internal/scan"
	"github.com/vitalii-ye/vmmon/internal/state"
	"github.com/vitalii-ye/vmmon/internal/vulndb"
)

const (
	dpkgInterval   = 5 * time.Minute
	skippedRetry   = 5 * time.Minute // After a concurrent `vmmon db sync`.
	syncMinBackoff = time.Minute
	syncMaxBackoff = time.Hour
	feedMaxBackoff = 6 * time.Hour
	scanMinBackoff = time.Minute
	scanMaxBackoff = time.Hour

	sendTimeout    = 2 * time.Minute
	sendMinBackoff = 30 * time.Second
	sendMaxBackoff = time.Hour
	// sendGrace is how long an in-flight send may finish after shutdown begins,
	// within systemd's stop timeout. A cut-off send stays queued.
	sendGrace = 10 * time.Second
)

// Deps are the daemon's seams to the world. New fills unset ones with the real
// thing.
type Deps struct {
	Now func() time.Time
	// After is time.After; the send and main loops wait on it.
	After func(time.Duration) <-chan time.Time
	// Location is where the digest time is read; the default is time.Local.
	Location *time.Location
	// Root is the filesystem to inventory; "" means the running host.
	Root        string
	Inventory   func(context.Context) (*inventory.Host, error)
	Scan        func(context.Context, scan.Options) (*finding.Report, error)
	SyncDB      func(context.Context, inventory.Release) (vulndb.SyncResult, error)
	SyncFeeds   func(context.Context) (enrich.Changes, error)
	ReadMeta    func() (vulndb.Meta, error)
	StatusMTime func() (time.Time, error)
	// Notifier is the channel, kept for the whole process; nil means none is
	// configured. New leaves it nil: the caller decides.
	Notifier notify.Notifier
}

// Daemon is one run. Step and Deliver are its two loops' bodies; tests drive them
// directly with a fake clock.
type Daemon struct {
	cfg    *config.Config
	deps   Deps
	st     *state.Store
	policy policy.Policy
	wake   chan struct{}

	// Used only by the main loop.
	host       *inventory.Host
	name       string
	firstStart time.Time
	meta       vulndb.Meta
	seenDB     time.Time // Newest DB sync this daemon knows of.
	seenFeeds  time.Time // Newest feed sync this daemon knows of.

	nextDBSync  time.Time
	nextFeeds   time.Time
	nextDpkg    time.Time
	nextDaily   time.Time
	nextDigest  time.Time
	nextScan    time.Time // Not before: a failed scan's backoff.
	syncBackoff backoff
	feedBackoff backoff
	scanBackoff backoff

	pendingFull bool
	pendingOnly map[string]bool
	statusMTime time.Time
	lastScanErr string

	staleAlerted bool
	staleLogged  bool

	// Used only by the send loop.
	nextSend    time.Time
	sendBackoff backoff

	// Guards name, which the send loop reads for the dropped-messages note.
	nameMu sync.Mutex
}

// New returns a daemon for cfg.
func New(cfg *config.Config, deps Deps) *Daemon {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.After == nil {
		deps.After = time.After
	}
	if deps.Location == nil {
		deps.Location = time.Local
	}
	if deps.Inventory == nil {
		deps.Inventory = func(ctx context.Context) (*inventory.Host, error) { return inventory.Collect(ctx, deps.Root) }
	}
	if deps.Scan == nil {
		deps.Scan = func(ctx context.Context, opts scan.Options) (*finding.Report, error) { return scan.Run(ctx, cfg, opts) }
	}
	if deps.SyncDB == nil {
		deps.SyncDB = func(ctx context.Context, rel inventory.Release) (vulndb.SyncResult, error) {
			store, err := vulndb.Open(cfg, rel)
			if err != nil {
				return vulndb.SyncResult{}, err
			}
			return store.Sync(ctx, vulndb.SyncOptions{})
		}
	}
	if deps.SyncFeeds == nil {
		deps.SyncFeeds = enrich.Open(cfg).Sync
	}
	if deps.ReadMeta == nil {
		deps.ReadMeta = func() (vulndb.Meta, error) { return vulndb.ReadMeta(cfg.DBDir()) }
	}
	if deps.StatusMTime == nil {
		deps.StatusMTime = func() (time.Time, error) {
			info, err := os.Stat(inventory.StatusPath(deps.Root))
			if err != nil {
				return time.Time{}, err
			}
			return info.ModTime(), nil
		}
	}
	return &Daemon{
		cfg:         cfg,
		deps:        deps,
		st:          state.New(cfg.StatePath(), 0),
		policy:      policy.New(cfg.Policy),
		wake:        make(chan struct{}, 1),
		syncBackoff: backoff{min: syncMinBackoff, max: min(syncMaxBackoff, cfg.DB.SyncInterval)},
		feedBackoff: backoff{min: syncMinBackoff, max: min(feedMaxBackoff, cfg.DB.EnrichInterval)},
		scanBackoff: backoff{min: scanMinBackoff, max: scanMaxBackoff},
		sendBackoff: backoff{min: sendMinBackoff, max: sendMaxBackoff},
		name:        notify.Hostname(cfg),
	}
}

// Run works until ctx ends, which is not an error. It fails only when the daemon
// cannot start at all: an unsupported release, or a state file it cannot write.
func (d *Daemon) Run(ctx context.Context) error {
	if err := d.Start(ctx); err != nil {
		if ctx.Err() != nil {
			return nil //nolint:nilerr // ctx ending is a clean shutdown, not a failure
		}
		return err
	}
	var wg sync.WaitGroup
	wg.Go(func() { d.sendLoop(ctx) })
	for ctx.Err() == nil {
		wait := max(d.Step(ctx).Sub(d.deps.Now()), time.Second)
		select {
		case <-d.deps.After(wait):
		case <-ctx.Done():
		}
	}
	wg.Wait()
	slog.Info("daemon stopped")
	return nil
}

func (d *Daemon) sendLoop(ctx context.Context) {
	for ctx.Err() == nil {
		var timer <-chan time.Time
		if retry := d.Deliver(ctx); !retry.IsZero() {
			timer = d.deps.After(max(retry.Sub(d.deps.Now()), time.Second))
		}
		select {
		case <-d.wake:
		case <-timer:
		case <-ctx.Done():
		}
	}
}

// Start does what must succeed before the loops begin, and sets the schedule.
func (d *Daemon) Start(ctx context.Context) error {
	host, err := d.deps.Inventory(ctx)
	if err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	d.setHost(host)

	now := d.deps.Now()
	var m state.Meta
	err = d.st.Update(func(tx *state.Tx) error {
		var err error
		if m, err = tx.Meta(); err != nil {
			return err
		}
		if !m.FirstStart.IsZero() {
			return nil
		}
		m.FirstStart = now
		return tx.PutMeta(m)
	})
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	d.firstStart = m.FirstStart
	d.staleAlerted = m.StaleAlerted
	d.nextDigest = d.digestAfter(m.LastDigest, m.FirstStart)
	d.nextDaily = slotAfter(now, d.cfg.Policy.DigestTime, d.deps.Location)
	d.nextDpkg = now.Add(dpkgInterval)

	d.readMeta()
	em := d.meta.Ecosystems[host.Release.Ecosystem]
	d.seenDB = em.LastSync
	d.seenFeeds = feedsSynced(d.meta)
	d.nextDBSync = dueAfter(em.LastSync, d.cfg.DB.SyncInterval, now)
	d.nextFeeds = dueAfter(oldestFeed(d.meta), d.cfg.DB.EnrichInterval, now)
	d.pendingFull = true
	return nil
}

// Step does everything due now and returns when it next needs to run. It stops
// early once ctx ends, leaving unfinished work pending.
func (d *Daemon) Step(ctx context.Context) time.Time {
	d.readMeta()
	d.noticeOutsideSync()

	// A usable database scans before any sync: a weekly refresh can take minutes.
	// Without the KEV catalog the first summary would be wrong, so that one waits
	// for the feed sync below.
	if !d.meta.Ecosystems[d.host.Release.Ecosystem].LastSync.IsZero() && !d.meta.KEV.LastSync.IsZero() {
		d.runScan(ctx)
	}
	d.syncDB(ctx)
	d.syncFeeds(ctx)
	d.checkDpkg()

	now := d.deps.Now()
	if !now.Before(d.nextDaily) {
		d.pendingFull = true
		d.nextDaily = slotAfter(now, d.cfg.Policy.DigestTime, d.deps.Location)
	}
	if !now.Before(d.nextDigest) {
		d.pendingFull = true
	}
	d.runScan(ctx)
	d.digest(ctx)
	d.checkStale(ctx)
	return d.nextWake()
}

func (d *Daemon) nextWake() time.Time {
	next := d.nextDpkg
	for _, t := range []time.Time{d.nextDBSync, d.nextFeeds, d.nextDaily, d.nextDigest} {
		if t.Before(next) {
			next = t
		}
	}
	if (d.pendingFull || len(d.pendingOnly) > 0) && d.nextScan.Before(next) {
		next = d.nextScan
	}
	return next
}

func (d *Daemon) setHost(host *inventory.Host) {
	d.host = host
	name := d.cfg.Hostname
	if name == "" {
		name = host.Hostname
	}
	if name == "" {
		return
	}
	d.nameMu.Lock()
	d.name = name
	d.nameMu.Unlock()
}

func (d *Daemon) hostname() string {
	d.nameMu.Lock()
	defer d.nameMu.Unlock()
	return d.name
}

func (d *Daemon) readMeta() {
	m, err := d.deps.ReadMeta()
	if err != nil {
		slog.Warn("cannot read database metadata", "err", err)
		return
	}
	d.meta = m
}

// noticeOutsideSync catches a `sudo vmmon db sync`: it tells nobody what changed,
// so the only safe recheck is a full one, and it pushes back the next sync.
func (d *Daemon) noticeOutsideSync() {
	if last := d.meta.Ecosystems[d.host.Release.Ecosystem].LastSync; last.After(d.seenDB) {
		slog.Info("database synced outside the daemon", "last_sync", last)
		d.seenDB = last
		d.pendingFull = true
		d.syncBackoff.reset()
		d.nextDBSync = last.Add(d.cfg.DB.SyncInterval)
	}
	if last := feedsSynced(d.meta); last.After(d.seenFeeds) {
		slog.Info("feeds synced outside the daemon", "last_sync", last)
		d.seenFeeds = last
		d.pendingFull = true
	}
}

func (d *Daemon) syncDB(ctx context.Context) {
	now := d.deps.Now()
	if ctx.Err() != nil || now.Before(d.nextDBSync) {
		return
	}
	eco := d.host.Release.Ecosystem
	slog.Info("syncing vulnerability database", "ecosystem", eco)
	res, err := d.deps.SyncDB(ctx, d.host.Release)
	switch {
	case ctx.Err() != nil:
		return
	case errors.Is(err, vulndb.ErrSyncInProgress):
		// Not a failure. Whatever it achieves shows up in meta.json.
		slog.Info("another sync is running, skipping this cycle")
		d.nextDBSync = now.Add(skippedRetry)
		return
	case err != nil:
		wait := d.syncBackoff.next()
		slog.Error("database sync failed", "err", err, "retry_in", wait)
		d.nextDBSync = d.deps.Now().Add(wait)
		return
	}
	d.syncBackoff.reset()
	d.nextDBSync = d.deps.Now().Add(d.cfg.DB.SyncInterval)
	slog.Info("database synced", "mode", res.Mode, "records_changed", res.RecordsChanged, "packages_changed", len(res.ChangedPackages))
	d.readMeta()
	d.seenDB = d.meta.Ecosystems[eco].LastSync
	if len(res.ChangedPackages) > 0 {
		if d.pendingOnly == nil {
			d.pendingOnly = make(map[string]bool, len(res.ChangedPackages))
		}
		for _, p := range res.ChangedPackages {
			d.pendingOnly[p] = true
		}
	}
	// A sync may be what a scan that failed for lack of a database was waiting for.
	d.nextScan = time.Time{}
	d.scanBackoff.reset()
	debug.FreeOSMemory()
}

func (d *Daemon) syncFeeds(ctx context.Context) {
	now := d.deps.Now()
	if ctx.Err() != nil || now.Before(d.nextFeeds) {
		return
	}
	slog.Info("syncing KEV and EPSS")
	ch, err := d.deps.SyncFeeds(ctx)
	if ctx.Err() != nil {
		return
	}
	// The findings diff is the only source of alerts. ch.NewKEV lists the whole
	// catalog on a first sync, so it only ever triggers a rematch.
	if ch.KEVChanged || ch.EPSSUpdated {
		d.pendingFull = true
	}
	d.readMeta()
	d.seenFeeds = feedsSynced(d.meta)
	switch {
	case errors.Is(err, vulndb.ErrSyncInProgress):
		slog.Info("another feed sync is running, skipping this cycle")
		d.nextFeeds = now.Add(skippedRetry)
	case err != nil:
		wait := d.feedBackoff.next()
		slog.Error("feed sync failed", "err", err, "retry_in", wait)
		d.nextFeeds = d.deps.Now().Add(wait)
	default:
		d.feedBackoff.reset()
		d.nextFeeds = d.deps.Now().Add(d.cfg.DB.EnrichInterval)
		slog.Info("feeds synced", "kev_changed", ch.KEVChanged, "new_kev", len(ch.NewKEV), "epss_updated", ch.EPSSUpdated)
	}
	debug.FreeOSMemory()
}

func (d *Daemon) checkDpkg() {
	now := d.deps.Now()
	if now.Before(d.nextDpkg) {
		return
	}
	d.nextDpkg = now.Add(dpkgInterval)
	mtime, err := d.deps.StatusMTime()
	if err != nil {
		slog.Warn("cannot check the dpkg database", "err", err)
		return
	}
	if !mtime.Equal(d.statusMTime) {
		slog.Info("dpkg database changed", "mtime", mtime)
		d.pendingFull = true
	}
}

// runScan runs what is pending: a full scan subsumes a partial one. Pending work
// is cleared only once its outcome has committed, so a failure repeats it.
func (d *Daemon) runScan(ctx context.Context) {
	now := d.deps.Now()
	if ctx.Err() != nil || (!d.pendingFull && len(d.pendingOnly) == 0) || now.Before(d.nextScan) {
		return
	}
	full := d.pendingFull
	opts := scan.Options{Now: d.deps.Now}
	var mtime time.Time
	if full {
		// Read before the inventory, so a change during the scan is seen next check.
		var err error
		if mtime, err = d.deps.StatusMTime(); err != nil {
			slog.Warn("cannot check the dpkg database", "err", err)
		}
		host, err := d.deps.Inventory(ctx)
		if err != nil {
			d.scanFailed(ctx, fmt.Errorf("inventory: %w", err))
			return
		}
		d.setHost(host)
	} else {
		opts.Only = maps.Clone(d.pendingOnly)
	}
	opts.Host = d.host

	r, err := d.deps.Scan(ctx, opts)
	if err != nil {
		d.scanFailed(ctx, err)
		return
	}
	if err := d.commitScan(r, opts.Only); err != nil {
		d.scanFailed(ctx, fmt.Errorf("record scan: %w", err))
		return
	}
	d.scanBackoff.reset()
	d.nextScan = time.Time{}
	d.lastScanErr = ""
	d.pendingOnly = nil
	if full {
		d.pendingFull = false
		d.statusMTime = mtime
	}
	debug.FreeOSMemory()
}

func (d *Daemon) scanFailed(ctx context.Context, err error) {
	if ctx.Err() != nil {
		return
	}
	wait := d.scanBackoff.next()
	d.nextScan = d.deps.Now().Add(wait)
	d.lastScanErr = err.Error()
	if errors.Is(err, vulndb.ErrNoDB) {
		slog.Info("no vulnerability database yet", "retry_in", wait)
		// Whatever removed it, only a sync brings it back.
		if d.syncBackoff.cur == 0 && d.nextScan.Before(d.nextDBSync) {
			d.nextDBSync = d.nextScan
		}
		return
	}
	slog.Error("scan failed", "err", err, "retry_in", wait)
}

// commitScan records a report and, in the same transaction, queues the messages
// it calls for. The first scan is the baseline: one summary, no per-finding alerts.
// While no channel is configured nothing queues; a summary is owed instead.
func (d *Daemon) commitScan(r *finding.Report, only map[string]bool) error {
	now := d.deps.Now()
	var diff state.Diff
	var alerts []finding.Finding
	var escalations []notify.Escalation
	queued := false
	err := d.st.Update(func(tx *state.Tx) error {
		alerts, escalations, queued = nil, nil, false
		m, err := tx.Meta()
		if err != nil {
			return err
		}
		if diff, err = tx.ApplyReport(r, only, now, d.policy.Alert); err != nil {
			return err
		}
		first := !m.Baselined
		m.Baselined = true
		m.LastScan = now
		m.Ecosystem = r.Ecosystem
		m.RebootRequired = r.RebootRequired
		m.Packages = r.PackagesCount
		if only == nil {
			m.LastFullScan = now
			m.Warnings = r.Warnings
		}
		for i := range diff.New {
			if d.policy.Alert(&diff.New[i]) {
				alerts = append(alerts, diff.New[i])
			} else if !first {
				m.SilentSinceDigest++
			}
		}
		for _, e := range diff.Escalated {
			if d.policy.Alert(&e.Finding) {
				escalations = append(escalations, notify.Escalation{Finding: e.Finding, NewKEV: e.NewKEV, NewFix: e.NewFix, NewAlert: e.NewAlert})
			}
		}
		notable := len(alerts) > 0 || len(escalations) > 0

		switch {
		case d.deps.Notifier == nil:
			if notable {
				m.FirstSummarySent = false
			}
		case !m.FirstSummarySent:
			// A summary covers everything so far, so it needs the whole picture.
			if only == nil {
				var kev []finding.Finding
				for i := range r.Findings {
					if r.Findings[i].KEV {
						kev = append(kev, r.Findings[i])
					}
				}
				html := notify.RenderSummary(d.hostname(), notify.Summary{
					Packages:       r.PackagesCount,
					Counts:         r.Counts,
					KEV:            kev,
					RebootRequired: r.RebootRequired,
					Warnings:       r.Warnings,
				})
				if err := tx.Enqueue(&m, "summary", html, now); err != nil {
					return err
				}
				m.FirstSummarySent = true
				queued = true
			}
		default:
			if len(alerts) > 0 {
				if err := tx.Enqueue(&m, "alert", notify.RenderAlert(d.hostname(), alerts), now); err != nil {
					return err
				}
				queued = true
			}
			if len(escalations) > 0 {
				if err := tx.Enqueue(&m, "escalation", notify.RenderEscalation(d.hostname(), escalations), now); err != nil {
					return err
				}
				queued = true
			}
		}
		return tx.PutMeta(m)
	})
	if err != nil {
		return err
	}
	slog.Info("scan recorded", "findings", len(r.Findings), "partial", only != nil,
		"new", len(diff.New), "alerting", len(alerts), "escalated", len(escalations), "resolved", diff.Resolved)
	if queued {
		d.wakeSender()
	} else if d.deps.Notifier == nil && (len(alerts) > 0 || len(escalations) > 0) {
		slog.Warn("no notification channel configured: a summary is owed once one is", "alerting", len(alerts), "escalated", len(escalations))
	}
	return nil
}

// digest sends the digest when due. A failed scan does not hold it back: a digest
// that says so is worth more than silence.
func (d *Daemon) digest(ctx context.Context) {
	now := d.deps.Now()
	if ctx.Err() != nil || now.Before(d.nextDigest) {
		return
	}
	var m state.Meta
	queued := false
	err := d.st.Update(func(tx *state.Tx) error {
		queued = false
		var err error
		if m, err = tx.Meta(); err != nil {
			return err
		}
		if !m.Baselined {
			return nil
		}
		m.LastDigest = now
		// Without a channel, what the digest would say keeps until there is one.
		if d.deps.Notifier == nil {
			return tx.PutMeta(m)
		}
		o, err := tx.Overview()
		if err != nil {
			return err
		}
		var resolved []finding.Finding
		err = tx.ResolvedSinceDigest(func(r *state.Record) error {
			resolved = append(resolved, r.Finding())
			return nil
		})
		if err != nil {
			return err
		}
		warnings := m.Warnings
		if d.lastScanErr != "" {
			warnings = append([]string{"last scan failed: " + d.lastScanErr}, warnings...)
		}
		html := notify.RenderDigest(d.hostname(), notify.Digest{
			Weekly:         d.policy.WeeklyDigest(),
			Open:           o.Counts,
			KEV:            o.KEV,
			Resolved:       resolved,
			Silent:         m.SilentSinceDigest,
			DBSyncedAt:     d.meta.Ecosystems[d.host.Release.Ecosystem].LastSync,
			Now:            now,
			RebootRequired: m.RebootRequired,
			Warnings:       warnings,
		})
		if err := tx.Enqueue(&m, "digest", html, now); err != nil {
			return err
		}
		if err := tx.ClearResolved(); err != nil {
			return err
		}
		m.SilentSinceDigest = 0
		queued = true
		return tx.PutMeta(m)
	})
	if err != nil {
		slog.Error("cannot record digest", "err", err)
		d.nextDigest = now.Add(dpkgInterval)
		return
	}
	if !m.Baselined {
		d.nextDigest = now.Add(dpkgInterval) // Nothing to report until the first scan.
		return
	}
	d.nextDigest = d.digestAfter(now, m.FirstStart)
	slog.Info("digest due", "queued", queued, "next", d.nextDigest)
	if queued {
		d.wakeSender()
	}
}

// checkStale sends one alert per stale episode. The episode ends when a sync, by
// anyone, succeeds. It is derived from LastSync alone, so a skipped cycle or a
// restart changes nothing.
func (d *Daemon) checkStale(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	now := d.deps.Now()
	em := d.meta.Ecosystems[d.host.Release.Ecosystem]
	since := em.LastSync
	if since.IsZero() {
		since = d.firstStart
	}
	stale := now.Sub(since) > d.cfg.DB.StaleAfter
	if !stale {
		d.staleLogged = false
	}
	if stale == d.staleAlerted {
		return
	}
	if stale && d.deps.Notifier == nil {
		if !d.staleLogged {
			slog.Warn("vulnerability database is stale and no notification channel is configured", "since", since)
			d.staleLogged = true
		}
		return
	}
	err := d.st.Update(func(tx *state.Tx) error {
		m, err := tx.Meta()
		if err != nil {
			return err
		}
		if stale {
			html := notify.RenderStale(d.hostname(), notify.Stale{LastSync: em.LastSync, Since: d.firstStart, Now: now, LastError: em.LastError})
			if err := tx.Enqueue(&m, "stale", html, now); err != nil {
				return err
			}
		}
		m.StaleAlerted = stale
		return tx.PutMeta(m)
	})
	if err != nil {
		slog.Error("cannot record staleness", "err", err)
		return
	}
	d.staleAlerted = stale
	if stale {
		slog.Warn("vulnerability database is stale", "since", since)
		d.wakeSender()
	}
}

// Deliver sends queued messages, oldest first, until the queue is empty or a send
// fails. It returns when to try again; zero means the queue is empty.
func (d *Daemon) Deliver(ctx context.Context) time.Time {
	if d.deps.Notifier == nil {
		return time.Time{}
	}
	if d.deps.Now().Before(d.nextSend) {
		return d.nextSend
	}
	for ctx.Err() == nil {
		item, ok, err := d.head()
		if err != nil {
			slog.Error("cannot read the send queue", "err", err)
			d.nextSend = d.deps.Now().Add(d.sendBackoff.next())
			return d.nextSend
		}
		if !ok {
			return time.Time{}
		}
		if err := d.sendOne(ctx, item); err != nil {
			if ctx.Err() == nil {
				wait := d.retryWait(err)
				d.nextSend = d.deps.Now().Add(wait)
				slog.Error("send failed, message stays queued", "kind", item.Kind, "err", err, "retry_in", wait)
			}
			return d.nextSend
		}
		d.sendBackoff.reset()
	}
	return time.Time{}
}

// head returns the next message, first folding in the note about any dropped ones
// so it is delivered, or kept, along with that message.
func (d *Daemon) head() (state.Item, bool, error) {
	var it state.Item
	var ok bool
	dropped := 0
	err := d.st.View(func(tx *state.Tx) error {
		m, err := tx.Meta()
		if err != nil {
			return err
		}
		dropped = m.DroppedMessages
		it, ok, err = tx.QueueHead()
		return err
	})
	if errors.Is(err, state.ErrNoState) {
		return it, false, nil
	}
	if err != nil || !ok || dropped == 0 {
		return it, ok, err
	}
	err = d.st.Update(func(tx *state.Tx) error {
		m, err := tx.Meta()
		if err != nil {
			return err
		}
		if it, ok, err = tx.QueueHead(); err != nil || !ok {
			return err
		}
		it.HTML = notify.RenderDropped(d.hostname(), m.DroppedMessages) + it.HTML
		if err := tx.ReplaceItem(it); err != nil {
			return err
		}
		m.DroppedMessages = 0
		return tx.PutMeta(m)
	})
	return it, ok, err
}

// sendOne delivers one message and records the outcome. The state file is not
// open during the send.
func (d *Daemon) sendOne(ctx context.Context, item state.Item) error {
	// The send has its own deadline, and a short grace after shutdown begins.
	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sendTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { time.AfterFunc(sendGrace, cancel) })
	defer stop()

	sendErr := d.deps.Notifier.Send(sendCtx, item.HTML)
	now := d.deps.Now()
	err := d.st.Update(func(tx *state.Tx) error {
		m, err := tx.Meta()
		if err != nil {
			return err
		}
		remaining := notify.Undelivered(item.HTML, sendErr)
		if remaining == "" {
			if err := tx.DeleteItem(item.Seq); err != nil {
				return err
			}
		} else {
			item.HTML = remaining
			if err := tx.ReplaceItem(item); err != nil {
				return err
			}
		}
		switch {
		case sendErr == nil:
			m.Channel.LastOK = now
			m.Channel.LastError = ""
			m.Channel.Permanent = false
		case ctx.Err() == nil:
			m.Channel.LastError = sendErr.Error()
			m.Channel.LastErrorAt = now
			m.Channel.Permanent = errors.Is(sendErr, notify.ErrPermanent)
		}
		return tx.PutMeta(m)
	})
	if err != nil {
		if sendErr == nil {
			return fmt.Errorf("delivered, but could not record it, so it will repeat: %w", err)
		}
		return errors.Join(sendErr, err)
	}
	if sendErr == nil {
		slog.Info("message delivered", "kind", item.Kind)
	}
	return sendErr
}

// retryWait backs off exponentially, honours a 429's wait, and retries a permanent
// failure slowly: a revoked token is fixable by re-running setup.
func (d *Daemon) retryWait(err error) time.Duration {
	wait := d.sendBackoff.next()
	if errors.Is(err, notify.ErrPermanent) {
		return sendMaxBackoff
	}
	var se *notify.SendError
	if errors.As(err, &se) && se.RetryAfter > wait {
		return se.RetryAfter
	}
	return wait
}

func (d *Daemon) wakeSender() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// backoff is an exponential delay: min, doubling up to max.
type backoff struct {
	min, max, cur time.Duration
}

func (b *backoff) next() time.Duration {
	if b.cur == 0 {
		b.cur = min(b.min, b.max)
	} else {
		b.cur = min(b.cur*2, b.max)
	}
	return b.cur
}

func (b *backoff) reset() { b.cur = 0 }

func dueAfter(last time.Time, interval time.Duration, now time.Time) time.Time {
	if last.IsZero() {
		return now
	}
	return last.Add(interval)
}

func oldestFeed(m vulndb.Meta) time.Time {
	if m.KEV.LastSync.IsZero() || m.EPSS.LastSync.IsZero() {
		return time.Time{}
	}
	if m.KEV.LastSync.Before(m.EPSS.LastSync) {
		return m.KEV.LastSync
	}
	return m.EPSS.LastSync
}

func feedsSynced(m vulndb.Meta) time.Time {
	if m.KEV.LastSync.After(m.EPSS.LastSync) {
		return m.KEV.LastSync
	}
	return m.EPSS.LastSync
}

// digestAfter is the digest slot following the last digest, or, with none yet, the
// daemon's first start: the first slot after it, a week out for a weekly digest.
//
// Slots are computed on calendar dates, not by adding hours, so a DST change
// neither moves one nor runs one twice: the date advances even when the clock
// shows the same time again.
func (d *Daemon) digestAfter(last, firstStart time.Time) time.Time {
	hhmm, loc := d.cfg.Policy.DigestTime, d.deps.Location
	days := 1
	if d.policy.WeeklyDigest() {
		days = 7
	}
	switch {
	case !last.IsZero():
		return slotOn(last, days, hhmm, loc)
	case days > 1:
		return slotOn(firstStart, days, hhmm, loc)
	}
	return slotAfter(firstStart, hhmm, loc)
}

// slotAfter is the first time after t that the clock shows hhmm.
func slotAfter(t time.Time, hhmm string, loc *time.Location) time.Time {
	if slot := slotOn(t, 0, hhmm, loc); slot.After(t) {
		return slot
	}
	return slotOn(t, 1, hhmm, loc)
}

// slotOn is hhmm on the date addDays after t's.
func slotOn(t time.Time, addDays int, hhmm string, loc *time.Location) time.Time {
	clock, err := time.Parse("15:04", hhmm)
	if err != nil { // config.Validate rejects this before the daemon starts.
		clock = time.Date(0, 1, 1, 9, 0, 0, 0, time.UTC)
	}
	y, m, day := t.In(loc).Date()
	return time.Date(y, m, day+addDays, clock.Hour(), clock.Minute(), 0, 0, loc)
}
