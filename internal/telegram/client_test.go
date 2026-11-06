package telegram_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vitalii-ye/vmmon/internal/telegram"
	"github.com/vitalii-ye/vmmon/internal/telegram/telegramtest"
)

func TestCalls(t *testing.T) {
	srv := telegramtest.New(t)
	srv.WebhookURL = "https://example.com/hook"
	c := telegram.New(srv.URL, telegramtest.Token, nil)
	ctx := context.Background()

	me, err := c.GetMe(ctx)
	if err != nil || me.Username != srv.BotUsername {
		t.Fatalf("GetMe = %+v, %v", me, err)
	}
	info, err := c.GetWebhookInfo(ctx)
	if err != nil || info.URL != srv.WebhookURL {
		t.Fatalf("GetWebhookInfo = %+v, %v", info, err)
	}
	if _, err := c.SendMessage(ctx, "7", "<b>hi</b>"); err != nil {
		t.Fatal(err)
	}
	s := srv.Sent()[0]
	if s.ChatID != "7" || s.ParseMode != "HTML" || !s.DisablePreview {
		t.Fatalf("sent %+v", s)
	}
}

func TestGetUpdatesOffset(t *testing.T) {
	srv := telegramtest.New(t)
	c := telegram.New(srv.URL, telegramtest.Token, nil)
	ctx := context.Background()
	first := srv.AddMessage(1, "one")
	srv.AddMessage(1, "two")

	ups, err := c.GetUpdates(ctx, 0, time.Second)
	if err != nil || len(ups) != 2 {
		t.Fatalf("GetUpdates = %+v, %v", ups, err)
	}
	if ups[0].Message.Text != "one" {
		t.Fatalf("first = %+v", ups[0].Message)
	}
	ups, err = c.GetUpdates(ctx, first+1, 0)
	if err != nil || len(ups) != 1 || ups[0].Message.Text != "two" {
		t.Fatalf("after offset: %+v, %v", ups, err)
	}
	if p := srv.Polls()[0]; p.Timeout != time.Second {
		t.Fatalf("poll = %+v", p)
	}
}

func TestClassification(t *testing.T) {
	tests := []struct {
		code      int
		desc      string
		permanent bool
	}{
		{401, "Unauthorized", true},
		{403, "Forbidden: bot was blocked by the user", true},
		{400, "Bad Request: chat not found", true},
		{404, "Not Found", true},
		{429, "Too Many Requests", false},
		{408, "Request Timeout", false},
		{500, "Internal Server Error", false},
		{502, "Bad Gateway", false},
	}
	for _, tc := range tests {
		srv := telegramtest.New(t)
		srv.Fail(telegramtest.Failure{Code: tc.code, Description: tc.desc})
		_, err := telegram.New(srv.URL, telegramtest.Token, nil).SendMessage(context.Background(), "1", "x")
		var apiErr *telegram.APIError
		if !errors.As(err, &apiErr) || apiErr.Code != tc.code || apiErr.Description != tc.desc {
			t.Errorf("%d: err = %v", tc.code, err)
		}
		if telegram.IsPermanent(err) != tc.permanent {
			t.Errorf("%d: permanent = %v", tc.code, !tc.permanent)
		}
	}
}

func TestRetryAfterParsed(t *testing.T) {
	srv := telegramtest.New(t)
	srv.Fail(telegramtest.Failure{Code: 429, Description: "Too Many Requests", RetryAfter: 7})
	_, err := telegram.New(srv.URL, telegramtest.Token, nil).SendMessage(context.Background(), "1", "x")
	var apiErr *telegram.APIError
	if !errors.As(err, &apiErr) || apiErr.RetryAfter != 7*time.Second {
		t.Fatalf("err = %v", err)
	}
}

func TestNonJSONErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "<html>bad gateway</html>", http.StatusBadGateway)
	}))
	defer srv.Close()
	_, err := telegram.New(srv.URL, telegramtest.Token, nil).GetMe(context.Background())
	var apiErr *telegram.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != 502 || telegram.IsPermanent(err) {
		t.Fatalf("err = %v", err)
	}
}

// assertClean walks the whole error chain, not only the top message.
func assertClean(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("want an error")
	}
	for e := err; e != nil; e = errors.Unwrap(e) {
		for _, s := range secrets {
			if strings.Contains(e.Error(), s) {
				t.Fatalf("token leaked in %T: %q", e, e.Error())
			}
		}
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		t.Fatalf("*url.Error reachable through the chain: %v", uerr)
	}
}

func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return "http://" + l.Addr().String()
}

func TestTokenNeverInErrors(t *testing.T) {
	const token = telegramtest.Token
	ctx := context.Background()

	t.Run("connection refused", func(t *testing.T) {
		_, err := telegram.New(closedPort(t), token, nil).GetMe(ctx)
		assertClean(t, err, token)
		if telegram.IsPermanent(err) {
			t.Fatal("a network failure must be transient")
		}
		var netErr *telegram.NetworkError
		if !errors.As(err, &netErr) {
			t.Fatalf("got %T", err)
		}
	})
	t.Run("every method", func(t *testing.T) {
		c := telegram.New(closedPort(t), token, nil)
		_, e1 := c.GetUpdates(ctx, 0, 0)
		_, e2 := c.SendMessage(ctx, "1", "x")
		_, e3 := c.GetWebhookInfo(ctx)
		for _, err := range []error{e1, e2, e3} {
			assertClean(t, err, token)
		}
	})
	t.Run("bad base url", func(t *testing.T) {
		_, err := telegram.New("http://[bad", token, nil).GetMe(ctx)
		assertClean(t, err, token)
	})
	t.Run("token needing escaping", func(t *testing.T) {
		odd := "12:a/b c?d"
		_, err := telegram.New(closedPort(t), odd, nil).GetMe(ctx)
		assertClean(t, err, odd, url.PathEscape(odd), url.QueryEscape(odd))
	})
	t.Run("description quotes token", func(t *testing.T) {
		srv := telegramtest.New(t)
		srv.Fail(telegramtest.Failure{Code: 400, Description: "bad url /bot" + token + "/sendMessage"})
		_, err := telegram.New(srv.URL, token, nil).SendMessage(ctx, "1", "x")
		assertClean(t, err, token)
	})
	t.Run("transport error quoting url", func(t *testing.T) {
		hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("proxy said no to " + r.URL.String())
		})}
		_, err := telegram.New("http://x.test", token, hc).GetMe(ctx)
		assertClean(t, err, token)
	})
	t.Run("invalid token", func(t *testing.T) {
		srv := telegramtest.New(t)
		wrong := "999:wrong-token"
		_, err := telegram.New(srv.URL, wrong, nil).GetMe(ctx)
		assertClean(t, err, wrong)
		if !telegram.IsPermanent(err) {
			t.Fatal("want permanent")
		}
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRedirectNotFollowed(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect) //nolint:gosec // test server redirecting to its own fixture
	}))
	defer srv.Close()

	_, err := telegram.New(srv.URL, telegramtest.Token, nil).GetMe(context.Background())
	assertClean(t, err, telegramtest.Token)
	if hits != 0 {
		t.Fatal("redirect carried the token to another host")
	}
}

func TestContextErrorsVisible(t *testing.T) {
	srv := telegramtest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := telegram.New(srv.URL, telegramtest.Token, nil).GetMe(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	assertClean(t, err, telegramtest.Token)
}

func TestWebhookBlocksGetUpdates(t *testing.T) {
	srv := telegramtest.New(t)
	srv.WebhookURL = "https://example.com/hook"
	_, err := telegram.New(srv.URL, telegramtest.Token, nil).GetUpdates(context.Background(), 0, 0)
	var apiErr *telegram.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != 409 {
		t.Fatalf("err = %v", err)
	}
}
