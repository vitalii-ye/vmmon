package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vitalii-ye/vmmon/internal/finding"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	return New(filepath.Join(t.TempDir(), "state.bolt"), 0)
}

func report(fs ...finding.Finding) *finding.Report { return &finding.Report{Findings: fs} }

func vuln(pkg, cve string) finding.Finding {
	return finding.Finding{ID: finding.NewID("e", pkg, cve), SourcePackage: pkg, VulnID: cve, FixStatus: finding.NoFixYet}
}

func never(*finding.Finding) bool { return false }

func apply(t *testing.T, s *Store, r *finding.Report, only map[string]bool, alert func(*finding.Finding) bool) Diff {
	t.Helper()
	var d Diff
	err := s.Update(func(tx *Tx) error {
		var err error
		d, err = tx.ApplyReport(r, only, time.Unix(1000, 0), alert)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestViewBeforeAnyStateIsErrNoState(t *testing.T) {
	s := newStore(t)
	if err := s.View(func(*Tx) error { return nil }); !errors.Is(err, ErrNoState) {
		t.Errorf("err = %v", err)
	}
}

func TestViewOnAnEmptyFileIsErrNoState(t *testing.T) {
	s := newStore(t)
	if err := os.WriteFile(s.path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.View(func(*Tx) error { return nil }); !errors.Is(err, ErrNoState) {
		t.Errorf("err = %v", err)
	}
}

func TestStoreHoldsNoFileBetweenCalls(t *testing.T) {
	s := newStore(t)
	if err := s.Update(func(*Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	// A second store is another process: a held flock would time out.
	other := New(s.path, 50*time.Millisecond)
	if err := other.View(func(*Tx) error { return nil }); err != nil {
		t.Errorf("view: %v", err)
	}
	if err := other.Update(func(*Tx) error { return nil }); err != nil {
		t.Errorf("update: %v", err)
	}
}

func TestStateFileIsPrivate(t *testing.T) {
	s := newStore(t)
	if err := s.Update(func(*Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode %o", perm)
	}
}

func TestUpdateIsAtomic(t *testing.T) {
	s := newStore(t)
	boom := errors.New("boom")
	err := s.Update(func(tx *Tx) error {
		m, _ := tx.Meta()
		m.Baselined = true
		if err := tx.PutMeta(m); err != nil {
			return err
		}
		if err := tx.Enqueue(&m, "alert", "x", time.Unix(1, 0)); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	err = s.View(func(tx *Tx) error {
		m, err := tx.Meta()
		if m.Baselined || tx.QueueLen() != 0 {
			t.Errorf("a failed update left state: %+v, queue %d", m, tx.QueueLen())
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestApplyReportDiffs(t *testing.T) {
	s := newStore(t)
	a, b := vuln("a", "CVE-1"), vuln("b", "CVE-2")

	if d := apply(t, s, report(a, b), nil, never); len(d.New) != 2 || d.Resolved != 0 {
		t.Fatalf("first = %+v", d)
	}
	if d := apply(t, s, report(a, b), nil, never); len(d.New)+len(d.Escalated)+d.Resolved != 0 {
		t.Fatalf("unchanged = %+v", d)
	}
	if d := apply(t, s, report(a), nil, never); d.Resolved != 1 {
		t.Fatalf("gone = %+v", d)
	}
	if d := apply(t, s, report(a, b), nil, never); len(d.New) != 1 || d.New[0].ID != b.ID {
		t.Fatalf("returned = %+v", d)
	}
	// Returning takes it back out of the resolved set: it did not stay resolved.
	err := s.View(func(tx *Tx) error {
		return tx.ResolvedSinceDigest(func(r *Record) error {
			t.Errorf("still resolved: %s", r.Vuln)
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPartialReportResolvesOnlyListedSources(t *testing.T) {
	s := newStore(t)
	a, b := vuln("a", "CVE-1"), vuln("b", "CVE-2")
	apply(t, s, report(a, b), nil, never)

	if d := apply(t, s, report(), map[string]bool{"zzz": true}, never); d.Resolved != 0 {
		t.Errorf("resolved outside only: %+v", d)
	}
	if d := apply(t, s, report(), map[string]bool{"a": true}, never); d.Resolved != 1 {
		t.Errorf("did not resolve within only: %+v", d)
	}
	err := s.View(func(tx *Tx) error {
		o, err := tx.Overview()
		if o.Counts.Total != 1 {
			t.Errorf("open = %d", o.Counts.Total)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestEscalationsAreStickyAndOnce(t *testing.T) {
	s := newStore(t)
	f := vuln("a", "CVE-1")
	apply(t, s, report(f), nil, never)

	f.KEV = true
	d := apply(t, s, report(f), nil, never)
	if len(d.Escalated) != 1 || !d.Escalated[0].NewKEV || d.Escalated[0].NewFix {
		t.Fatalf("KEV: %+v", d)
	}
	f.KEV = false
	if d := apply(t, s, report(f), nil, never); len(d.Escalated) != 0 {
		t.Errorf("delisting: %+v", d)
	}
	f.KEV = true
	if d := apply(t, s, report(f), nil, never); len(d.Escalated) != 0 {
		t.Errorf("relisting: %+v", d)
	}

	f.FixStatus, f.FixedVersion = finding.FixAvailable, "2"
	d = apply(t, s, report(f), nil, never)
	if len(d.Escalated) != 1 || !d.Escalated[0].NewFix || d.Escalated[0].NewKEV {
		t.Fatalf("fix: %+v", d)
	}

	always := func(*finding.Finding) bool { return true }
	d = apply(t, s, report(f), nil, always)
	if len(d.Escalated) != 1 || !d.Escalated[0].NewAlert {
		t.Fatalf("policy: %+v", d)
	}
	if d := apply(t, s, report(f), nil, always); len(d.Escalated) != 0 {
		t.Errorf("policy again: %+v", d)
	}
	if d := apply(t, s, report(f), nil, never); len(d.Escalated) != 0 {
		t.Errorf("policy off: %+v", d)
	}
}

func TestNewFindingMeetingPolicyDoesNotEscalateLater(t *testing.T) {
	s := newStore(t)
	f := vuln("a", "CVE-1")
	always := func(*finding.Finding) bool { return true }
	apply(t, s, report(f), nil, always)
	if d := apply(t, s, report(f), nil, always); len(d.Escalated) != 0 {
		t.Errorf("got %+v", d)
	}
}

func TestResolvedSetClearsAfterDigest(t *testing.T) {
	s := newStore(t)
	apply(t, s, report(vuln("a", "CVE-1")), nil, never)
	apply(t, s, report(), nil, never)

	count := func() int {
		n := 0
		err := s.View(func(tx *Tx) error {
			return tx.ResolvedSinceDigest(func(*Record) error { n++; return nil })
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count() != 1 {
		t.Fatalf("resolved = %d", count())
	}
	if err := s.Update(func(tx *Tx) error { return tx.ClearResolved() }); err != nil {
		t.Fatal(err)
	}
	if count() != 0 {
		t.Errorf("resolved = %d after clearing", count())
	}
}

func TestQueueOrderAndCap(t *testing.T) {
	s := newStore(t)
	now := time.Unix(1, 0)
	err := s.Update(func(tx *Tx) error {
		m, err := tx.Meta()
		if err != nil {
			return err
		}
		for i := range MaxQueue + 2 {
			if err := tx.Enqueue(&m, "alert", fmt.Sprint("m", i), now); err != nil {
				return err
			}
		}
		return tx.PutMeta(m)
	})
	if err != nil {
		t.Fatal(err)
	}
	var head Item
	err = s.View(func(tx *Tx) error {
		m, err := tx.Meta()
		if err != nil {
			return err
		}
		if m.DroppedMessages != 2 || tx.QueueLen() != MaxQueue {
			t.Errorf("dropped %d, len %d", m.DroppedMessages, tx.QueueLen())
		}
		head, _, err = tx.QueueHead()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if head.HTML != "m2" {
		t.Errorf("head = %q, want the oldest kept", head.HTML)
	}

	head.HTML = "rest"
	err = s.Update(func(tx *Tx) error {
		if err := tx.ReplaceItem(head); err != nil {
			return err
		}
		got, _, err := tx.QueueHead()
		if got.HTML != "rest" || got.Seq != head.Seq {
			t.Errorf("replaced = %+v", got)
		}
		if err != nil {
			return err
		}
		return tx.DeleteItem(head.Seq)
	})
	if err != nil {
		t.Fatal(err)
	}
	err = s.View(func(tx *Tx) error {
		got, _, err := tx.QueueHead()
		if !strings.HasPrefix(got.HTML, "m3") {
			t.Errorf("next head = %q", got.HTML)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestReplacingADroppedItemDoesNotResurrectIt(t *testing.T) {
	s := newStore(t)
	err := s.Update(func(tx *Tx) error {
		if err := tx.ReplaceItem(Item{Seq: 99, HTML: "ghost"}); err != nil {
			return err
		}
		if tx.QueueLen() != 0 {
			t.Errorf("queue = %d", tx.QueueLen())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
