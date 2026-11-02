package notify

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/vitalii-ye/vmmon/internal/config"
	"github.com/vitalii-ye/vmmon/internal/telegram"
	"github.com/vitalii-ye/vmmon/internal/telegram/telegramtest"
)

// fakeClock advances only when slept on.
type fakeClock struct {
	t      time.Time
	sleeps []time.Duration
}

func (c *fakeClock) now() time.Time { return c.t }

func (c *fakeClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.sleeps = append(c.sleeps, d)
	c.t = c.t.Add(d)
	return nil
}

func newNotifier(t *testing.T) (*Telegram, *telegramtest.Server, *fakeClock) {
	t.Helper()
	srv := telegramtest.New(t)
	n := NewTelegram(telegram.New(srv.URL, telegramtest.Token, nil), "7")
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	n.SetClock(clock.now, clock.sleep)
	return n, srv, clock
}

// visible strips tags and leaves entities as written.
func visible(t *testing.T, html string) string {
	t.Helper()
	var b strings.Builder
	for _, tok := range tokenize(html) {
		if tok.kind == tokenText {
			b.WriteString(tok.raw)
		}
	}
	return b.String()
}

func TestSplitShortMessageUntouched(t *testing.T) {
	in := "<b>web-01</b> · <code>a &amp; b</code>\nline"
	if got := splitHTML(in, maxMessageLen); !reflect.DeepEqual(got, []string{in}) {
		t.Fatalf("got %q", got)
	}
}

func TestSplitTable(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		limit int
		want  []string
	}{
		{"prefers newline", "aaa bbb\nccc ddd", 12, []string{"aaa bbb\n", "ccc ddd"}},
		{"space when no newline", "aaaa bbbb cccc", 11, []string{"aaaa bbbb ", "cccc"}},
		{"hard cut", "abcdefgh", 3, []string{"abc", "def", "gh"}},
		{"reopens tags", "<b>aaaa\nbbbb</b>", 6, []string{"<b>aaaa\n</b>", "<b>bbbb</b>"}},
		{"nested reopens in order", "<b><i>aaaa\nbbbb</i></b>", 6, []string{"<b><i>aaaa\n</i></b>", "<b><i>bbbb</i></b>"}},
		{"keeps attributes", `<a href="https://x/?a=1&amp;b=2">aaaa bbbb</a>`, 6,
			[]string{`<a href="https://x/?a=1&amp;b=2">aaaa </a>`, `<a href="https://x/?a=1&amp;b=2">bbbb</a>`}},
		{"entity is one unit and whole", "&lt;&lt;&lt;&lt;", 2, []string{"&lt;&lt;", "&lt;&lt;"}},
		{"gt in attribute", `<a href="a>b">xx yy</a>`, 3, []string{`<a href="a>b">xx </a>`, `<a href="a>b">yy</a>`}},
		{"numeric entity counts two", "&#128512;&#128512;", 2, []string{"&#128512;", "&#128512;"}},
		{"emoji is two units", "😀😀😀", 4, []string{"😀😀", "😀"}},
		{"no surrogate split", "a😀", 2, []string{"a", "😀"}},
		{"no empty tag pair at start", "<b>aaa\n</b>bbb", 4, []string{"<b>aaa\n</b>", "bbb"}},
		{"whitespace-only part dropped", "aaa\n\n\n\n\n\n", 3, []string{"aaa"}},
		{"stray lt survives", "a < b", 100, []string{"a < b"}},
		{"nothing visible", "<b> \n </b>", 100, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := splitHTML(tc.in, tc.limit); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSplitLongMessagesAcceptedAndComplete(t *testing.T) {
	line := "• <b>openssl</b> 3.0 → <code>fix &lt;3.1&gt;</code> 🔴 привет\n"
	tests := map[string]string{
		"lines":          strings.Repeat(line, 500),
		"single pre":     "<pre>" + strings.Repeat("line of text in pre\n", 800) + "</pre>",
		"no breaks":      "<code>" + strings.Repeat("x", 9000) + "</code>",
		"emoji only":     strings.Repeat("😀", 5000),
		"cyrillic":       strings.Repeat("щ", 10000),
		"entities":       strings.Repeat("&amp;", 5000),
		"multi-byte end": strings.Repeat("a", 4095) + "😀" + strings.Repeat("b", 10),
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			n, srv, _ := newNotifier(t)
			if err := n.Send(context.Background(), in); err != nil {
				t.Fatal(err)
			}
			sent := srv.Sent()
			if len(sent) < 2 {
				t.Fatalf("not split: %d", len(sent))
			}
			var joined strings.Builder
			for i, s := range sent {
				if !utf8.ValidString(s.Text) {
					t.Fatalf("part %d: invalid UTF-8", i)
				}
				size, err := telegramtest.ParsedLen(s.Text)
				if err != nil || size > 4096 {
					t.Fatalf("part %d: len %d, err %v", i, size, err)
				}
				joined.WriteString(visible(t, s.Text))
			}
			if joined.String() != visible(t, in) {
				t.Fatal("text lost or changed by splitting")
			}
		})
	}
}

func TestSplitUsesTheWholeLimit(t *testing.T) {
	first := strings.Repeat("😀", 2047) + "aa" // Exactly 4096 units.
	got := splitHTML(first+"\nsecond", maxMessageLen)
	if !reflect.DeepEqual(got, []string{first, "\nsecond"}) {
		t.Fatalf("got %d parts", len(got))
	}
}

func TestSendRateLimit(t *testing.T) {
	n, srv, clock := newNotifier(t)
	ctx := context.Background()
	for range 3 {
		if err := n.Send(ctx, "hello"); err != nil {
			t.Fatal(err)
		}
	}
	if len(srv.Sent()) != 3 {
		t.Fatalf("sent %d", len(srv.Sent()))
	}
	if want := []time.Duration{time.Second, time.Second}; !reflect.DeepEqual(clock.sleeps, want) {
		t.Fatalf("sleeps = %v, want %v", clock.sleeps, want)
	}
}

func TestSendRateLimitBetweenParts(t *testing.T) {
	n, srv, clock := newNotifier(t)
	if err := n.Send(context.Background(), strings.Repeat("x", 9000)); err != nil {
		t.Fatal(err)
	}
	if len(srv.Sent()) != 3 || len(clock.sleeps) != 2 {
		t.Fatalf("sent %d, sleeps %v", len(srv.Sent()), clock.sleeps)
	}
}

func TestSendHonoursRetryAfter(t *testing.T) {
	n, srv, clock := newNotifier(t)
	srv.Fail(telegramtest.Failure{Code: 429, Description: "Too Many Requests", RetryAfter: 7})
	if err := n.Send(context.Background(), "hello"); err != nil {
		t.Fatal(err)
	}
	if want := []time.Duration{7 * time.Second}; !reflect.DeepEqual(clock.sleeps, want) {
		t.Fatalf("sleeps = %v, want %v", clock.sleeps, want)
	}
	if len(srv.Sent()) != 1 {
		t.Fatalf("sent %d", len(srv.Sent()))
	}
}

func TestSend429StopsAtContextEnd(t *testing.T) {
	n, srv, _ := newNotifier(t)
	srv.Fail(telegramtest.Failure{Code: 429, Description: "Too Many Requests", RetryAfter: 60})
	ctx, cancel := context.WithCancel(context.Background())
	n.SetClock(time.Now, func(context.Context, time.Duration) error {
		cancel()
		return ctx.Err()
	})
	err := n.Send(ctx, "hello")
	var se *SendError
	if !errors.As(err, &se) || se.RetryAfter != 60*time.Second || se.Remaining != "hello" {
		t.Fatalf("err = %#v", err)
	}
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrPermanent) {
		t.Fatalf("classification: %v", err)
	}
}

func TestPartialFailureResumes(t *testing.T) {
	n, srv, clock := newNotifier(t)
	in := "<b>" + strings.Repeat("line of text here\n", 600) + "</b>"
	total := len(splitHTML(in, maxMessageLen))
	if total < 3 {
		t.Fatalf("test needs at least 3 parts, got %d", total)
	}
	ctx := context.Background()

	// The sleeper runs just before the second part: fail that request, once.
	armed := false
	n.SetClock(clock.now, func(ctx context.Context, d time.Duration) error {
		if !armed {
			armed = true
			srv.Fail(telegramtest.Failure{Code: 500, Description: "Internal Server Error"})
		}
		return clock.sleep(ctx, d)
	})
	err := n.Send(ctx, in)

	var se *SendError
	if !errors.As(err, &se) || se.Delivered != 1 || se.Total != total {
		t.Fatalf("err = %v, want 1 of %d delivered", err, total)
	}
	if errors.Is(err, ErrPermanent) {
		t.Fatal("a 5xx must not be permanent")
	}
	if len(srv.Sent()) != 1 {
		t.Fatalf("sent %d", len(srv.Sent()))
	}

	// Resume with what the error says is left: nothing repeated, nothing lost.
	if err := n.Send(ctx, Undelivered(in, err)); err != nil {
		t.Fatal(err)
	}
	var joined strings.Builder
	for _, s := range srv.Sent() {
		joined.WriteString(visible(t, s.Text))
	}
	if joined.String() != visible(t, in) {
		t.Fatal("resume repeated or lost text")
	}
	if len(srv.Sent()) != total {
		t.Fatalf("sent %d parts in all, want %d", len(srv.Sent()), total)
	}
}

func TestUndelivered(t *testing.T) {
	if got := Undelivered("x", nil); got != "" {
		t.Fatalf("nil error: %q", got)
	}
	if got := Undelivered("x", errors.New("boom")); got != "x" {
		t.Fatalf("plain error: %q", got)
	}
	if got := Undelivered("x", &SendError{Remaining: "y"}); got != "y" {
		t.Fatalf("send error: %q", got)
	}
}

func TestPermanentFailure(t *testing.T) {
	for _, f := range []telegramtest.Failure{
		{Code: 403, Description: "Forbidden: bot was kicked"},
		{Code: 400, Description: "Bad Request: chat not found"},
		{Code: 401, Description: "Unauthorized"},
	} {
		n, srv, _ := newNotifier(t)
		srv.Fail(f)
		err := n.Send(context.Background(), "hello")
		if !errors.Is(err, ErrPermanent) {
			t.Errorf("%d: not permanent: %v", f.Code, err)
		}
		var apiErr *telegram.APIError
		if !errors.As(err, &apiErr) || apiErr.Code != f.Code {
			t.Errorf("%d: no APIError: %v", f.Code, err)
		}
	}
}

func TestEmptyMessageIsPermanent(t *testing.T) {
	n, srv, _ := newNotifier(t)
	if err := n.Send(context.Background(), " \n"); !errors.Is(err, ErrPermanent) {
		t.Fatalf("err = %v", err)
	}
	if srv.Calls("sendMessage") != 0 {
		t.Fatal("sent an empty message")
	}
}

func TestNetworkFailureIsQueueable(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := "http://" + l.Addr().String()
	l.Close()

	n := NewTelegram(telegram.New(addr, telegramtest.Token, nil), "7")
	err = n.Send(context.Background(), "hello")
	if err == nil || errors.Is(err, ErrPermanent) {
		t.Fatalf("want a transient error, got %v", err)
	}
	if strings.Contains(err.Error(), telegramtest.Token) {
		t.Fatalf("token in error: %v", err)
	}
	if got := Undelivered("hello", err); got != "hello" {
		t.Fatalf("Undelivered = %q", got)
	}
}

func TestNewRequiresConfig(t *testing.T) {
	cfg := config.Default()
	if _, err := New(cfg); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v", err)
	}
	cfg.Telegram.Token, cfg.Telegram.ChatID = "t", "1"
	n, err := New(cfg)
	if err != nil || n.Name() != "telegram" {
		t.Fatalf("New = %v, %v", n, err)
	}
}

func TestEscapeHTML(t *testing.T) {
	if got := EscapeHTML(`a<b> & "c"`); got != "a&lt;b&gt; &amp; &quot;c&quot;" {
		t.Fatalf("got %q", got)
	}
	if n, err := telegramtest.ParsedLen(EscapeHTML(`<script>&"`)); err != nil || n != 10 {
		t.Fatalf("ParsedLen = %d, %v", n, err)
	}
}

func TestMessagesStartWithHostname(t *testing.T) {
	msg := TestMessage("web<1>")
	if !strings.HasPrefix(msg, "<b>web&lt;1&gt;</b>") {
		t.Fatalf("msg = %q", msg)
	}
	if h := Hostname(&config.Config{Hostname: "h1"}); h != "h1" {
		t.Fatalf("Hostname = %q", h)
	}
}
