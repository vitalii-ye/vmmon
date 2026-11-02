package notify

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vitalii-ye/vmmon/internal/config"
	"github.com/vitalii-ye/vmmon/internal/telegram"
)

const (
	// minSendInterval keeps sends at or under one message per second per chat.
	minSendInterval = time.Second
	// defaultRetryAfter applies to a 429 that does not say how long to wait.
	defaultRetryAfter = 5 * time.Second
)

// ErrNotConfigured means no channel has the token and chat it needs.
var ErrNotConfigured = errors.New("no notification channel configured")

// New returns the notifier the config selects, or an error wrapping
// ErrNotConfigured.
func New(cfg *config.Config) (Notifier, error) {
	if !cfg.Telegram.Configured() {
		return nil, fmt.Errorf("telegram needs a token and a chat ID: %w", ErrNotConfigured)
	}
	return NewTelegram(telegram.New(cfg.Telegram.APIBaseURL, cfg.Telegram.Token, nil), cfg.Telegram.ChatID), nil
}

// SendError is the only error type Telegram.Send returns. It says how far a
// message got, so a retry does not repeat what was already delivered.
type SendError struct {
	// Remaining is valid HTML for what is still undelivered, including the part
	// that failed. Pass it to Send to resume.
	Remaining string
	// Delivered and Total count the parts of the split message.
	Delivered, Total int
	// RetryAfter is how long Telegram asked to wait, if it was rate limiting.
	RetryAfter time.Duration
	// Err is the cause; it wraps ErrPermanent when a retry cannot succeed.
	Err error
}

func (e *SendError) Error() string {
	return fmt.Sprintf("delivered %d of %d parts: %v", e.Delivered, e.Total, e.Err)
}

func (e *SendError) Unwrap() error { return e.Err }

// Undelivered returns what is left to send after Send(ctx, html) returned err:
// nothing for a nil error, the undelivered parts after a partial failure, and
// html itself for any other error. A queue stores this in place of html.
//
// Delivery is at least once: if a response is lost after Telegram accepted a
// part, that part is sent again.
func Undelivered(html string, err error) string {
	if err == nil {
		return ""
	}
	var se *SendError
	if errors.As(err, &se) {
		return se.Remaining
	}
	return html
}

// Telegram sends to one chat. Use one per chat: the rate limit lives here.
// Concurrent Sends are serialised, so parts of two messages do not interleave.
type Telegram struct {
	client *telegram.Client
	chatID string
	now    func() time.Time
	sleep  func(context.Context, time.Duration) error

	sem  chan struct{}
	next time.Time // Earliest allowed send. Guarded by sem.
}

// NewTelegram returns a notifier for one chat.
func NewTelegram(client *telegram.Client, chatID string) *Telegram {
	return &Telegram{
		client: client,
		chatID: chatID,
		now:    time.Now,
		sleep:  Sleep,
		sem:    make(chan struct{}, 1),
	}
}

// SetClock replaces the clock and sleeper, for tests.
func (t *Telegram) SetClock(now func() time.Time, sleep func(context.Context, time.Duration) error) {
	t.now, t.sleep = now, sleep
}

// Name implements Notifier.
func (t *Telegram) Name() string { return "telegram" }

// Send implements Notifier. It waits out a 429's retry_after and retries the
// same part for as long as ctx allows, so callers should pass a deadline. Any
// other failure returns at once. Every error is a *SendError.
func (t *Telegram) Send(ctx context.Context, html string) error {
	chunks := splitHTML(html, maxMessageLen)
	if len(chunks) == 0 {
		return &SendError{Err: fmt.Errorf("message has no visible text: %w", ErrPermanent)}
	}
	select {
	case t.sem <- struct{}{}:
		defer func() { <-t.sem }()
	case <-ctx.Done():
		return &SendError{Remaining: html, Total: len(chunks), Err: ctx.Err()}
	}
	for i, chunk := range chunks {
		retryAfter, err := t.sendChunk(ctx, chunk)
		if err == nil {
			continue
		}
		remaining := html
		if i > 0 {
			remaining = strings.Join(chunks[i:], "")
		}
		if telegram.IsPermanent(err) {
			err = fmt.Errorf("%w: %w", ErrPermanent, err)
		}
		return &SendError{Remaining: remaining, Delivered: i, Total: len(chunks), RetryAfter: retryAfter, Err: err}
	}
	return nil
}

// sendChunk delivers one part, waiting for its turn and through any 429s. On
// failure it also returns the wait a 429 asked for.
func (t *Telegram) sendChunk(ctx context.Context, chunk string) (time.Duration, error) {
	var limited *telegram.APIError
	for {
		if wait := t.next.Sub(t.now()); wait > 0 {
			if err := t.sleep(ctx, wait); err != nil {
				if limited != nil {
					return limited.RetryAfter, fmt.Errorf("%w while waiting out: %w", err, limited)
				}
				return 0, err
			}
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		_, err := t.client.SendMessage(ctx, t.chatID, chunk)
		t.next = t.now().Add(minSendInterval)
		if err == nil {
			return 0, nil
		}
		var apiErr *telegram.APIError
		if !errors.As(err, &apiErr) || apiErr.Code != 429 {
			return 0, err
		}
		if apiErr.RetryAfter <= 0 {
			apiErr.RetryAfter = defaultRetryAfter
		}
		if at := t.now().Add(apiErr.RetryAfter); at.After(t.next) {
			t.next = at
		}
		limited = apiErr
	}
}

// Sleep waits for d or until ctx ends.
func Sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var htmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")

// EscapeHTML makes text safe inside Telegram HTML, in text and attribute values.
func EscapeHTML(s string) string { return htmlEscaper.Replace(s) }

// Hostname is the name messages start with: the configured override, else the
// system hostname.
func Hostname(cfg *config.Config) string {
	if cfg.Hostname != "" {
		return cfg.Hostname
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown-host"
}

// TestMessage is what `vmmon setup` and `vmmon notify test` send.
func TestMessage(hostname string) string {
	return "<b>" + EscapeHTML(hostname) + "</b> · vmmon test message. Notifications work."
}
