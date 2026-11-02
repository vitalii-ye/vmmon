package vulndb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vitalii-ye/vmmon/internal/buildinfo"
)

// Download defaults.
const (
	defaultRetries     = 5
	defaultRetryDelay  = time.Second
	defaultIdleTimeout = 60 * time.Second
)

var errStalled = errors.New("download stalled")

// HTTPClient returns a client for large downloads. It bounds connecting and
// waiting for headers but not the body, since an 800 MB file takes as long as
// it takes; Download detects stalls instead.
func HTTPClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	t.TLSHandshakeTimeout = 30 * time.Second
	t.ResponseHeaderTimeout = 60 * time.Second
	return &http.Client{Transport: t}
}

// DownloadOptions tunes Download. Zero values give the defaults.
type DownloadOptions struct {
	// Retries is how many consecutive failures without progress are tolerated.
	Retries int
	// RetryDelay is the first backoff; it doubles on each consecutive failure.
	RetryDelay time.Duration
	// IdleTimeout aborts and retries an attempt that received no data this long.
	IdleTimeout time.Duration
	// Preflight, if set, runs once with the body size when the server states it.
	Preflight func(size int64) error
}

func (o DownloadOptions) withDefaults() DownloadOptions {
	if o.Retries == 0 {
		o.Retries = defaultRetries
	}
	if o.RetryDelay == 0 {
		o.RetryDelay = defaultRetryDelay
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = defaultIdleTimeout
	}
	return o
}

// permanentError marks a failure that retrying cannot fix.
type permanentError struct{ error }

func (e permanentError) Unwrap() error { return e.error }

func newRequest(ctx context.Context, url string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, permanentError{err}
	}
	req.Header.Set("User-Agent", "vmmon/"+buildinfo.Version)
	return req, nil
}

func statusError(url string, code int) error {
	err := fmt.Errorf("GET %s: HTTP %d", url, code)
	if code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || code >= 500 {
		return err
	}
	return permanentError{err}
}

// sleep waits for the nth backoff, or until ctx ends.
func sleep(ctx context.Context, first time.Duration, n int) error {
	t := time.NewTimer(first << (n - 1))
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Download fetches url into the empty file f and returns the SHA-256 of the
// content. Transient failures retry and, when the server allows it, resume from
// the bytes already on disk with an HTTP Range request.
func Download(ctx context.Context, client *http.Client, url string, f *os.File, opts DownloadOptions) (string, error) {
	opts = opts.withDefaults()
	d := download{client: client, url: url, f: f, opts: opts, sum: sha256.New()}
	for failures := 0; ; {
		before := d.offset
		err := d.attempt(ctx)
		if err == nil {
			return hex.EncodeToString(d.sum.Sum(nil)), nil
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if _, permanent := errors.AsType[permanentError](err); permanent {
			return "", err
		}
		if d.offset > before {
			failures = 0
		}
		failures++
		if failures > opts.Retries {
			return "", fmt.Errorf("giving up after %d attempts: %w", failures, err)
		}
		if err := sleep(ctx, opts.RetryDelay, failures); err != nil {
			return "", err
		}
	}
}

type download struct {
	client    *http.Client
	url       string
	f         *os.File
	opts      DownloadOptions
	sum       hash.Hash
	offset    int64
	etag      string
	preflight bool
}

func (d *download) reset() error {
	d.offset = 0
	d.sum.Reset()
	if err := d.f.Truncate(0); err != nil {
		return permanentError{err}
	}
	if _, err := d.f.Seek(0, io.SeekStart); err != nil {
		return permanentError{err}
	}
	return nil
}

func (d *download) attempt(ctx context.Context) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	// The idle timer covers the whole attempt, so a stalled body aborts too.
	idle := time.AfterFunc(d.opts.IdleTimeout, func() { cancel(errStalled) })
	defer idle.Stop()

	req, err := newRequest(ctx, d.url)
	if err != nil {
		return err
	}
	// Offsets must refer to the stored bytes, so no transparent compression.
	req.Header.Set("Accept-Encoding", "identity")
	if d.offset > 0 {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(d.offset, 10)+"-")
		if d.etag != "" && !strings.HasPrefix(d.etag, "W/") {
			req.Header.Set("If-Range", d.etag)
		}
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return attemptError(ctx, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		if err := d.reset(); err != nil {
			return err
		}
	case http.StatusPartialContent:
		if !strings.HasPrefix(resp.Header.Get("Content-Range"), "bytes "+strconv.FormatInt(d.offset, 10)+"-") {
			if err := d.reset(); err != nil {
				return err
			}
			return fmt.Errorf("GET %s: unexpected Content-Range %q", d.url, resp.Header.Get("Content-Range"))
		}
	case http.StatusRequestedRangeNotSatisfiable:
		if err := d.reset(); err != nil {
			return err
		}
		return fmt.Errorf("GET %s: range rejected", d.url)
	default:
		return statusError(d.url, resp.StatusCode)
	}
	d.etag = resp.Header.Get("ETag")
	if !d.preflight && resp.StatusCode == http.StatusOK && resp.ContentLength > 0 && d.opts.Preflight != nil {
		d.preflight = true
		if err := d.opts.Preflight(resp.ContentLength); err != nil {
			return permanentError{err}
		}
	}

	buf := make([]byte, 128<<10)
	for {
		idle.Reset(d.opts.IdleTimeout)
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, err := d.f.Write(buf[:n]); err != nil {
				return permanentError{fmt.Errorf("write %s: %w", d.f.Name(), err)}
			}
			d.sum.Write(buf[:n])
			d.offset += int64(n)
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return attemptError(ctx, rerr)
		}
	}
}

func attemptError(ctx context.Context, err error) error {
	if cause := context.Cause(ctx); errors.Is(cause, errStalled) {
		return cause
	}
	return err
}

// withRetry runs fn, a short request, retrying transient failures.
func withRetry(ctx context.Context, opts DownloadOptions, fn func(context.Context) error) error {
	opts = opts.withDefaults()
	for failures := 1; ; failures++ {
		err := fn(ctx)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, permanent := errors.AsType[permanentError](err); permanent || failures > opts.Retries {
			return err
		}
		if err := sleep(ctx, opts.RetryDelay, failures); err != nil {
			return err
		}
	}
}

// checkDiskSpace fails when dir's filesystem has less than need bytes available.
func checkDiskSpace(dir string, need int64) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return nil // Not knowing is no reason to refuse; writes fail clearly anyway.
	}
	free := uint64(st.Bavail) * uint64(st.Bsize)
	if free < uint64(need) {
		return fmt.Errorf("not enough disk space in %s: need about %d MB, have %d MB", dir, need>>20, free>>20)
	}
	return nil
}
