// Package telegram is a minimal Telegram Bot API client: just what pairing and
// alerts need.
//
// The bot token is part of every request URL, and Go's *url.Error quotes the
// URL. So every error this package returns has the token removed, and transport
// errors do not expose their cause through Unwrap.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBaseURL is the public Bot API endpoint.
const DefaultBaseURL = "https://api.telegram.org"

const (
	// UpdatesLimit is the page size of GetUpdates, the Bot API maximum.
	UpdatesLimit = 100

	requestTimeout = 30 * time.Second
	maxResponse    = 16 << 20
	redacted       = "<redacted>"
)

// User is a Telegram user or bot.
type User struct {
	ID        int64  `json:"id"`
	IsBot     bool   `json:"is_bot"`
	FirstName string `json:"first_name"`
	Username  string `json:"username"`
}

// Chat is a private chat, group, supergroup or channel.
type Chat struct {
	ID        int64  `json:"id"`
	Type      string `json:"type"`
	Title     string `json:"title,omitempty"`
	Username  string `json:"username,omitempty"`
	FirstName string `json:"first_name,omitempty"`
}

// Message is the part of a message vmmon reads.
type Message struct {
	MessageID int64  `json:"message_id"`
	From      *User  `json:"from,omitempty"`
	Chat      Chat   `json:"chat"`
	Text      string `json:"text,omitempty"`
}

// Update is one incoming event. Only plain new messages are decoded.
type Update struct {
	UpdateID int64    `json:"update_id"`
	Message  *Message `json:"message,omitempty"`
}

// WebhookInfo describes the bot's webhook. URL is empty when none is set.
type WebhookInfo struct {
	URL                string `json:"url"`
	PendingUpdateCount int    `json:"pending_update_count"`
	LastErrorMessage   string `json:"last_error_message,omitempty"`
}

// APIError is a failure reported by the Bot API or an HTTP error status.
type APIError struct {
	Method      string
	Code        int
	Description string
	// RetryAfter is how long Telegram asked to wait, on a 429.
	RetryAfter time.Duration
	// MigrateToChatID is the new ID of a group upgraded to a supergroup.
	MigrateToChatID int64
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("telegram %s: %d %s", e.Method, e.Code, e.Description)
	if e.RetryAfter > 0 {
		msg += fmt.Sprintf(" (retry after %s)", e.RetryAfter)
	}
	return msg
}

// Permanent reports whether repeating the same request cannot succeed: a bad
// token (401, or 404 for a malformed one), a bot blocked or removed (403), a bad
// chat or message (400). Rate limits, timeouts and server errors are transient.
func (e *APIError) Permanent() bool {
	if e.Code == http.StatusTooManyRequests || e.Code == http.StatusRequestTimeout {
		return false
	}
	return e.Code >= 400 && e.Code < 500
}

// IsPermanent reports whether err is a permanent API failure. Network failures
// and context errors are not.
func IsPermanent(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Permanent()
}

// NetworkError is a request that got no usable response. It is always
// transient. errors.Is sees through it to context errors and the like, but it
// has no Unwrap: the underlying error is exactly what may quote the token.
type NetworkError struct {
	Method string
	msg    string
	cause  error
}

func (e *NetworkError) Error() string { return "telegram " + e.Method + ": " + e.msg }

// Is matches the underlying cause.
func (e *NetworkError) Is(target error) bool { return errors.Is(e.cause, target) }

// Client calls the Bot API. It is safe for concurrent use.
type Client struct {
	token   string
	baseURL string
	http    *http.Client
}

// New returns a client. An empty baseURL means DefaultBaseURL; a nil hc means a
// default client. Redirects are never followed: they would carry the token to
// wherever the response points.
func New(baseURL, token string, hc *http.Client) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if hc == nil {
		hc = &http.Client{}
	}
	noRedirect := *hc
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{token: token, baseURL: strings.TrimRight(baseURL, "/"), http: &noRedirect}
}

// GetMe returns the bot's own user, which validates the token.
func (c *Client) GetMe(ctx context.Context) (*User, error) {
	var u User
	if err := c.call(ctx, "getMe", nil, &u, requestTimeout); err != nil {
		return nil, err
	}
	return &u, nil
}

// GetUpdates long-polls for up to timeout. Passing offset N acknowledges every
// update below N, deleting it from Telegram's side for good, so callers should
// advance it only when they must. allowed_updates is deliberately not sent:
// Telegram remembers it for the bot's other consumers.
func (c *Client) GetUpdates(ctx context.Context, offset int64, timeout time.Duration) ([]Update, error) {
	req := struct {
		Offset  int64 `json:"offset,omitempty"`
		Limit   int   `json:"limit"`
		Timeout int   `json:"timeout"`
	}{offset, UpdatesLimit, int(timeout.Seconds())}
	var ups []Update
	if err := c.call(ctx, "getUpdates", req, &ups, timeout+requestTimeout); err != nil {
		return nil, err
	}
	return ups, nil
}

// SendMessage sends one HTML-formatted message without link previews. The text
// must already fit Telegram's limit; see the notify package.
func (c *Client) SendMessage(ctx context.Context, chatID, html string) (*Message, error) {
	req := struct {
		ChatID         string `json:"chat_id"`
		Text           string `json:"text"`
		ParseMode      string `json:"parse_mode"`
		DisablePreview bool   `json:"disable_web_page_preview"`
	}{chatID, html, "HTML", true}
	var m Message
	if err := c.call(ctx, "sendMessage", req, &m, requestTimeout); err != nil {
		return nil, err
	}
	return &m, nil
}

// GetWebhookInfo returns the bot's webhook state.
func (c *Client) GetWebhookInfo(ctx context.Context) (*WebhookInfo, error) {
	var w WebhookInfo
	if err := c.call(ctx, "getWebhookInfo", nil, &w, requestTimeout); err != nil {
		return nil, err
	}
	return &w, nil
}

func (c *Client) call(ctx context.Context, method string, in, out any, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	body := []byte("{}")
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return fmt.Errorf("telegram %s: %w", method, err)
		}
	}
	endpoint := c.baseURL + "/bot" + url.PathEscape(c.token) + "/" + method
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return c.networkError(method, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return c.networkError(method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return c.networkError(method, err)
	}

	var env struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		ErrorCode   int             `json:"error_code"`
		Description string          `json:"description"`
		Parameters  struct {
			RetryAfter      int   `json:"retry_after"`
			MigrateToChatID int64 `json:"migrate_to_chat_id"`
		} `json:"parameters"`
	}
	jsonErr := json.Unmarshal(data, &env)
	if resp.StatusCode != http.StatusOK || (jsonErr == nil && !env.OK) {
		apiErr := &APIError{
			Method:          method,
			Code:            env.ErrorCode,
			Description:     c.redact(env.Description),
			RetryAfter:      time.Duration(env.Parameters.RetryAfter) * time.Second,
			MigrateToChatID: env.Parameters.MigrateToChatID,
		}
		if apiErr.Code == 0 {
			apiErr.Code = resp.StatusCode
		}
		if apiErr.Description == "" {
			apiErr.Description = http.StatusText(resp.StatusCode)
		}
		return apiErr
	}
	if jsonErr == nil {
		jsonErr = json.Unmarshal(env.Result, out)
	}
	if jsonErr != nil {
		return c.networkError(method, fmt.Errorf("bad response: %w", jsonErr))
	}
	return nil
}

// networkError builds a NetworkError whose message cannot contain the token.
func (c *Client) networkError(method string, err error) error {
	cause := err
	var uerr *url.Error
	if errors.As(err, &uerr) {
		cause = uerr.Err // Drops the quoted URL.
	}
	return &NetworkError{Method: method, msg: c.redact(cause.Error()), cause: cause}
}

// redact removes the token from s in every form a URL or message may carry it.
func (c *Client) redact(s string) string {
	if c.token == "" {
		return s
	}
	for _, form := range []string{c.token, url.PathEscape(c.token), url.QueryEscape(c.token)} {
		s = strings.ReplaceAll(s, form, redacted)
	}
	return s
}
