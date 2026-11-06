package setup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vitalii-ye/vmmon/internal/config"
	"github.com/vitalii-ye/vmmon/internal/notify"
	"github.com/vitalii-ye/vmmon/internal/telegram/telegramtest"
)

const (
	testCode = "pairing_CODE-123"
	testChat = int64(-1001234)
	chatStr  = "-1001234"
)

// clock is safe to share with the fake server's handler goroutines.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *clock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.advance(d)
	return nil
}

type fakeSystem struct {
	euid            int
	noSystemd       bool
	noUnit          bool
	active, enabled bool
	failStart       bool
	calls           []string
}

func (s *fakeSystem) Geteuid() int     { return s.euid }
func (s *fakeSystem) HasSystemd() bool { return !s.noSystemd }

func (s *fakeSystem) Systemctl(_ context.Context, args ...string) error {
	call := strings.Join(args, " ")
	s.calls = append(s.calls, call)
	no := errors.New("exit status 1")
	switch call {
	case "cat vmmon.service":
		if s.noUnit {
			return no
		}
	case "is-active --quiet vmmon":
		if !s.active {
			return no
		}
	case "is-enabled --quiet vmmon":
		if !s.enabled {
			return no
		}
	case "enable --now vmmon":
		if s.failStart {
			return no
		}
		s.active, s.enabled = true, true
	case "enable vmmon":
		s.enabled = true
	case "restart vmmon":
		if s.failStart {
			return no
		}
	}
	return nil
}

// actions drops the read-only queries.
func (s *fakeSystem) actions() []string {
	var out []string
	for _, c := range s.calls {
		if strings.HasPrefix(c, "enable") || strings.HasPrefix(c, "restart") {
			out = append(out, c)
		}
	}
	return out
}

type harness struct {
	srv   *telegramtest.Server
	dir   string
	path  string
	sys   *fakeSystem
	clock *clock
	out   bytes.Buffer
	opts  Options
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	for _, k := range []string{"VMMON_CONFIG", "VMMON_TELEGRAM_TOKEN", "VMMON_TELEGRAM_CHAT_ID", "VMMON_POLICY", "VMMON_STATE_DIR"} {
		t.Setenv(k, "")
		_ = os.Unsetenv(k) // config treats a set-but-empty variable as an override.
	}
	srv := telegramtest.New(t)
	t.Setenv("VMMON_TELEGRAM_API_BASE_URL", srv.URL)
	t.Setenv("VMMON_HOSTNAME", "web-01")
	dir := filepath.Join(t.TempDir(), "etc", "vmmon")
	h := &harness{
		srv:   srv,
		dir:   dir,
		path:  filepath.Join(dir, "config.yaml"),
		sys:   &fakeSystem{},
		clock: &clock{t: time.Unix(1_700_000_000, 0)},
	}
	h.opts = Options{ConfigPath: h.path}
	return h
}

// run runs the wizard with the given answers and checks the token stayed out of
// everything the user sees.
func (h *harness) run(ctx context.Context, t *testing.T, opts Options, input string) error {
	t.Helper()
	err := Run(ctx, opts, Deps{
		In:      strings.NewReader(input),
		Out:     &h.out,
		Now:     h.clock.now,
		Sleep:   h.clock.sleep,
		NewCode: func() (string, error) { return testCode, nil },
		System:  h.sys,
	})
	secret := h.srv.Token
	if strings.Contains(h.out.String(), secret) {
		t.Fatalf("token in output:\n%s", h.out.String())
	}
	if err != nil && strings.Contains(err.Error(), secret) {
		t.Fatalf("token in error: %v", err)
	}
	return err
}

func (h *harness) writeTokenFile(t *testing.T, token string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// seed gives the harness a completed first setup, through the real code.
func (h *harness) seed(t *testing.T, policy string) {
	t.Helper()
	opts := h.opts
	opts.TokenFile = h.writeTokenFile(t, telegramtest.Token)
	opts.ChatID = chatStr
	opts.Policy = policy
	opts.Yes = true
	opts.NoStart = true
	if err := h.run(context.Background(), t, opts, ""); err != nil {
		t.Fatal(err)
	}
	h.out.Reset()
}

func (h *harness) assertNothingWritten(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(h.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s exists: %v", h.dir, err)
	}
	if len(h.sys.actions()) != 0 {
		t.Fatalf("service touched: %v", h.sys.calls)
	}
}

func (h *harness) load(t *testing.T) *config.Config {
	t.Helper()
	c, err := config.Load(h.path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeFile(t *testing.T, path, data string, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), perm); err != nil {
		t.Fatal(err)
	}
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestPairingRightCode(t *testing.T) {
	h := newHarness(t)
	h.srv.OnPoll = func(n int, _ telegramtest.Poll) {
		if n == 0 {
			h.srv.AddMessage(testChat, "/start "+testCode)
		}
	}
	if err := h.run(context.Background(), t, h.opts, telegramtest.Token+"\n\n"); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}

	out := h.out.String()
	for _, want := range []string{
		"vmmon test (@vmmon_test_bot)",
		"https://t.me/vmmon_test_bot?start=" + testCode,
		"/start@vmmon_test_bot " + testCode,
		"▀", // The QR code.
		"quiet", "critical", "everything",
		"800 MB",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	sent := h.srv.Sent()
	if len(sent) != 1 || sent[0].ChatID != chatStr || !strings.HasPrefix(sent[0].Text, "<b>web-01</b>") {
		t.Fatalf("sent = %+v", sent)
	}

	if mode(t, h.dir) != 0o755 || mode(t, h.path) != 0o644 || mode(t, filepath.Join(h.dir, "secrets.env")) != 0o600 {
		t.Fatalf("modes: dir %o config %o secrets %o", mode(t, h.dir), mode(t, h.path), mode(t, filepath.Join(h.dir, "secrets.env")))
	}
	if got := read(t, filepath.Join(h.dir, "secrets.env")); got != "VMMON_TELEGRAM_TOKEN="+telegramtest.Token+"\n" {
		t.Fatalf("secrets.env = %q", got)
	}
	conf := read(t, h.path)
	if strings.Contains(conf, telegramtest.Token) {
		t.Fatal("token in config.yaml")
	}
	if strings.Contains(conf, h.srv.URL) || strings.Contains(conf, "web-01") {
		t.Fatalf("environment overrides baked into config:\n%s", conf)
	}
	c := h.load(t)
	if c.Telegram.ChatID != chatStr || c.Telegram.Token != telegramtest.Token || c.Policy.Preset != config.PresetQuiet {
		t.Fatalf("loaded %+v", c.Telegram)
	}
	if want := []string{"enable --now vmmon"}; !reflect.DeepEqual(h.sys.actions(), want) {
		t.Fatalf("actions = %v", h.sys.actions())
	}

	// Pairing used no acknowledgement at all: the bot's update queue is intact.
	if h.srv.Pending() != 1 {
		t.Fatalf("pending = %d", h.srv.Pending())
	}
	for _, p := range h.srv.Polls() {
		if p.Offset != 0 {
			t.Fatalf("acknowledged updates needlessly: %+v", p)
		}
	}
	entries, _ := os.ReadDir(h.dir)
	if len(entries) != 2 {
		t.Fatalf("leftover files: %v", entries)
	}
}

func TestPairingWrongCodeThenRight(t *testing.T) {
	wrong := []string{
		"/start wrong",
		"hello",
		"",
		"/start",
		testCode,
		"/start  " + testCode,
		"/start " + testCode + " extra",
		" /start " + testCode,
		"/startx " + testCode,
		"/start@other_bot " + testCode,
	}
	h := newHarness(t)
	h.srv.OnPoll = func(n int, _ telegramtest.Poll) {
		switch n {
		case 0:
			for i, text := range wrong {
				h.srv.AddMessage(int64(100+i), text)
			}
		case 1:
			h.srv.AddMessage(testChat, "/start@VMMON_test_bot "+testCode)
		}
	}
	if err := h.run(context.Background(), t, h.opts, telegramtest.Token+"\n\n"); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	if got := h.load(t).Telegram.ChatID; got != chatStr {
		t.Fatalf("chat = %q", got)
	}
	if h.srv.Pending() != len(wrong)+1 {
		t.Fatalf("acknowledged other people's updates: pending %d", h.srv.Pending())
	}
}

func TestPairingAdvancesOffsetOnlyPastAFullPage(t *testing.T) {
	h := newHarness(t)
	var last int64
	h.srv.OnPoll = func(n int, _ telegramtest.Poll) {
		if n == 0 {
			for range 150 {
				last = h.srv.AddMessage(1, "noise")
			}
			h.srv.AddMessage(testChat, "/start "+testCode)
		}
	}
	if err := h.run(context.Background(), t, h.opts, telegramtest.Token+"\n\n"); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	polls := h.srv.Polls()
	if polls[0].Offset != 0 || polls[1].Offset != last-49 {
		t.Fatalf("offsets %d, %d; last %d", polls[0].Offset, polls[1].Offset, last)
	}
	if got := h.load(t).Telegram.ChatID; got != chatStr {
		t.Fatalf("chat = %q", got)
	}
}

func TestPairingTimeout(t *testing.T) {
	h := newHarness(t)
	h.srv.OnPoll = func(_ int, p telegramtest.Poll) { h.clock.advance(p.Timeout) }
	start := time.Now()
	err := h.run(context.Background(), t, h.opts, telegramtest.Token+"\n\n")
	if err == nil || !strings.Contains(err.Error(), "within 3m0s") || !strings.Contains(err.Error(), "setup again") {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 30*time.Second {
		t.Fatal("test used real time")
	}
	polls := h.srv.Polls()
	if len(polls) < 7 || polls[0].Timeout != 25*time.Second {
		t.Fatalf("polls = %+v", polls)
	}
	if total := time.Duration(len(polls)) * 25 * time.Second; total < 3*time.Minute-25*time.Second {
		t.Fatalf("gave up early after %s", total)
	}
	h.assertNothingWritten(t)
	if len(h.srv.Sent()) != 0 {
		t.Fatal("sent a message")
	}
}

func TestPairingContextCancel(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.srv.OnPoll = func(int, telegramtest.Poll) { cancel() }
	err := h.run(ctx, t, h.opts, telegramtest.Token+"\n\n")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	h.assertNothingWritten(t)
}

func TestPairingSurvivesTransientFailures(t *testing.T) {
	h := newHarness(t)
	h.srv.Fail(
		telegramtest.Failure{Code: 500, Description: "Internal Server Error"},
		telegramtest.Failure{Code: 429, Description: "Too Many Requests", RetryAfter: 9},
	)
	h.srv.OnPoll = func(n int, _ telegramtest.Poll) {
		if n == 2 {
			h.srv.AddMessage(testChat, "/start "+testCode)
		}
	}
	if err := h.run(context.Background(), t, h.opts, telegramtest.Token+"\n\n"); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	if got := h.clock.now().Sub(time.Unix(1_700_000_000, 0)); got < 11*time.Second {
		t.Fatalf("waited %s, want the 2s pause plus retry_after", got)
	}
}

func TestPairingStopsOnPermanentFailure(t *testing.T) {
	h := newHarness(t)
	h.srv.Fail(telegramtest.Failure{Code: 401, Description: "Unauthorized"})
	err := h.run(context.Background(), t, h.opts, telegramtest.Token+"\n\n")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v", err)
	}
	h.assertNothingWritten(t)
}

func TestPairingConflictExplained(t *testing.T) {
	h := newHarness(t)
	h.srv.Fail(telegramtest.Failure{Code: 409, Description: "Conflict: terminated by other getUpdates request"})
	err := h.run(context.Background(), t, h.opts, telegramtest.Token+"\n\n")
	if err == nil || !strings.Contains(err.Error(), "--chat-id") {
		t.Fatalf("err = %v", err)
	}
}

func TestWebhookManualChatID(t *testing.T) {
	h := newHarness(t)
	h.srv.WebhookURL = "https://example.com/hook"
	err := h.run(context.Background(), t, h.opts, telegramtest.Token+"\nnot-an-id\n"+chatStr+"\n\n")
	if err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	out := h.out.String()
	for _, want := range []string{"https://example.com/hook", "deleteWebhook", "<TOKEN>", "That is not a chat ID"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if h.srv.Calls("getUpdates") != 0 || h.srv.Calls("deleteWebhook") != 0 {
		t.Fatalf("getUpdates %d, deleteWebhook %d", h.srv.Calls("getUpdates"), h.srv.Calls("deleteWebhook"))
	}
	if got := h.load(t).Telegram.ChatID; got != chatStr {
		t.Fatalf("chat = %q", got)
	}
}

func TestWebhookURLQuotingTokenIsRedacted(t *testing.T) {
	// Many bots use the token as the webhook's secret path; run checks the output.
	for _, opts := range []Options{{}, {Yes: true, ChatID: chatStr}} {
		h := newHarness(t)
		h.srv.WebhookURL = "https://example.com/" + telegramtest.Token
		opts.ConfigPath = h.path
		opts.TokenFile = h.writeTokenFile(t, telegramtest.Token)
		if err := h.run(context.Background(), t, opts, "\n"); err != nil && opts.Yes {
			t.Fatal(err)
		}
		if !strings.Contains(h.out.String(), "https://example.com/<TOKEN>") {
			t.Fatalf("output:\n%s", h.out.String())
		}
	}
}

func TestWebhookExit(t *testing.T) {
	h := newHarness(t)
	h.srv.WebhookURL = "https://example.com/hook"
	err := h.run(context.Background(), t, h.opts, telegramtest.Token+"\n\n")
	if err == nil || !strings.Contains(err.Error(), "webhook") {
		t.Fatalf("err = %v", err)
	}
	h.assertNothingWritten(t)
	if h.srv.Calls("deleteWebhook") != 0 {
		t.Fatal("deleted the webhook")
	}
}

func TestWebhookDoesNotBlockKnownChat(t *testing.T) {
	h := newHarness(t)
	h.srv.WebhookURL = "https://example.com/hook"
	opts := h.opts
	opts.TokenFile = h.writeTokenFile(t, telegramtest.Token)
	opts.ChatID, opts.Yes = chatStr, true
	if err := h.run(context.Background(), t, opts, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.out.String(), "webhook set") {
		t.Fatalf("no notice:\n%s", h.out.String())
	}
}

func TestInvalidTokenReprompts(t *testing.T) {
	h := newHarness(t)
	h.srv.OnPoll = func(n int, _ telegramtest.Poll) {
		if n == 0 {
			h.srv.AddMessage(testChat, "/start "+testCode)
		}
	}
	input := "999:wrong\nbad'quote\n" + telegramtest.Token + "\n\n"
	if err := h.run(context.Background(), t, h.opts, input); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	out := h.out.String()
	if strings.Count(out, "That token does not work") != 2 {
		t.Fatalf("output:\n%s", out)
	}
	if strings.Contains(out, "999:wrong") || strings.Contains(out, "bad'quote") {
		t.Fatalf("rejected token echoed:\n%s", out)
	}
	if got := h.load(t).Telegram.Token; got != telegramtest.Token {
		t.Fatal("wrong token saved")
	}
}

func TestInvalidTokenNonInteractive(t *testing.T) {
	h := newHarness(t)
	opts := h.opts
	opts.TokenFile = h.writeTokenFile(t, "999:wrong")
	opts.ChatID, opts.Yes = chatStr, true
	err := h.run(context.Background(), t, opts, "")
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "999:wrong") {
		t.Fatalf("err = %v", err)
	}
	h.assertNothingWritten(t)
}

func TestTestMessageFailureWritesNothing(t *testing.T) {
	for _, f := range []telegramtest.Failure{
		{Code: 403, Description: "Forbidden: bot was blocked by the user"},
		{Code: 500, Description: "Internal Server Error"},
	} {
		h := newHarness(t)
		h.srv.Fail(f)
		opts := h.opts
		opts.TokenFile = h.writeTokenFile(t, telegramtest.Token)
		opts.ChatID, opts.Yes = chatStr, true
		err := h.run(context.Background(), t, opts, "")
		if err == nil || !strings.Contains(err.Error(), "test message not delivered") || !strings.Contains(err.Error(), "nothing was saved") {
			t.Fatalf("err = %v", err)
		}
		h.assertNothingWritten(t)
	}
}

func TestRerunKeepsEverything(t *testing.T) {
	h := newHarness(t)
	h.seed(t, config.PresetCritical)
	custom := "# my note\nhostname: custom-host\npolicy:\n  preset: critical\n  digest_time: \"07:30\" # early\ntelegram:\n  chat_id: \"" + chatStr + "\"\n"
	writeFile(t, h.path, custom, 0o644)
	secrets := "# keep me\nOTHER=1\nVMMON_TELEGRAM_TOKEN=" + telegramtest.Token + "\n"
	writeFile(t, filepath.Join(h.dir, "secrets.env"), secrets, 0o600)
	sentBefore := len(h.srv.Sent())

	opts := h.opts
	opts.NoStart = true
	if err := h.run(context.Background(), t, opts, "\n\n\n"); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	if h.srv.Calls("getUpdates") != 0 {
		t.Fatal("paired although the chat was kept")
	}
	if len(h.srv.Sent()) != sentBefore+1 {
		t.Fatal("no test message on re-run")
	}
	if got := read(t, h.path); got != custom {
		t.Fatalf("config rewritten:\n%s", got)
	}
	if got := read(t, filepath.Join(h.dir, "secrets.env")); got != secrets {
		t.Fatalf("secrets rewritten:\n%s", got)
	}
	out := h.out.String()
	if !strings.Contains(out, chatStr) || !strings.Contains(out, "policy critical") || !strings.Contains(out, "Settings unchanged") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestRerunChangesOnlyWhatIsEdited(t *testing.T) {
	h := newHarness(t)
	h.seed(t, config.PresetQuiet)
	writeFile(t, h.path, "# my note\npolicy:\n  preset: quiet\n  digest_time: \"07:30\"\ndb:\n  sync_interval: 2h\ntelegram:\n  chat_id: \""+chatStr+"\"\n", 0o644)
	secretsPath := filepath.Join(h.dir, "secrets.env")
	secretsBefore := read(t, secretsPath)

	opts := h.opts
	opts.NoStart = true
	if err := h.run(context.Background(), t, opts, "\n\neverything\n"); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	got := read(t, h.path)
	if !strings.Contains(got, "# my note") {
		t.Fatalf("comment lost:\n%s", got)
	}
	c := h.load(t)
	if c.Policy.Preset != config.PresetEverything || c.Policy.DigestTime != "07:30" ||
		c.DB.SyncInterval != 2*time.Hour || c.Telegram.ChatID != chatStr {
		t.Fatalf("loaded %+v", c)
	}
	if read(t, secretsPath) != secretsBefore {
		t.Fatal("secrets changed")
	}
}

func TestRerunNewTokenAndRepairing(t *testing.T) {
	h := newHarness(t)
	h.seed(t, config.PresetQuiet)
	h.srv.Lock()
	h.srv.Token = "777:new-token"
	h.srv.Unlock()
	h.srv.OnPoll = func(n int, _ telegramtest.Poll) {
		if n == 0 {
			h.srv.AddMessage(555, "/start "+testCode)
		}
	}
	opts := h.opts
	opts.NoStart = true
	// The old token no longer works, so Enter is refused before the new one.
	if err := h.run(context.Background(), t, opts, "\n777:new-token\npair\n\n"); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	c := h.load(t)
	if c.Telegram.Token != "777:new-token" || c.Telegram.ChatID != "555" {
		t.Fatalf("loaded token ok=%v chat %q", c.Telegram.Token == "777:new-token", c.Telegram.ChatID)
	}
}

func TestNonInteractive(t *testing.T) {
	h := newHarness(t)
	opts := h.opts
	opts.TokenFile = h.writeTokenFile(t, "  "+telegramtest.Token+"  ")
	opts.ChatID, opts.Policy, opts.Yes = chatStr, config.PresetCritical, true
	if err := h.run(context.Background(), t, opts, ""); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	if h.srv.Calls("getUpdates") != 0 {
		t.Fatal("paired")
	}
	if len(h.srv.Sent()) != 1 {
		t.Fatal("no test message")
	}
	c := h.load(t)
	if !c.Telegram.Configured() || c.Policy.Preset != config.PresetCritical {
		t.Fatalf("loaded %+v", c.Policy)
	}
}

func TestNonInteractiveMissingValues(t *testing.T) {
	tests := []struct {
		name   string
		opts   func(*Options, string)
		wanted string
	}{
		{"no token", func(o *Options, _ string) { o.ChatID = chatStr }, "--token-file"},
		{"no chat", func(o *Options, f string) { o.TokenFile = f }, "--chat-id"},
		{"missing file", func(o *Options, _ string) { o.TokenFile = "/nonexistent/token"; o.ChatID = chatStr }, "--token-file"},
		{"bad policy", func(o *Options, f string) { o.TokenFile = f; o.ChatID = chatStr; o.Policy = "loud" }, "--policy"},
		{"bad chat", func(o *Options, f string) { o.TokenFile = f; o.ChatID = "abc" }, "--chat-id"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			opts := h.opts
			opts.Yes = true
			tc.opts(&opts, h.writeTokenFile(t, telegramtest.Token))
			err := h.run(context.Background(), t, opts, "")
			if err == nil || !strings.Contains(err.Error(), tc.wanted) {
				t.Fatalf("err = %v", err)
			}
			h.assertNothingWritten(t)
		})
	}
}

func TestEmptyTokenFile(t *testing.T) {
	h := newHarness(t)
	opts := h.opts
	opts.TokenFile = h.writeTokenFile(t, "   ")
	if err := h.run(context.Background(), t, opts, ""); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err = %v", err)
	}
}

func TestInputEndedExplainsScripts(t *testing.T) {
	h := newHarness(t)
	err := h.run(context.Background(), t, h.opts, "")
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("err = %v", err)
	}
}

func TestHiddenTokenPromptUsed(t *testing.T) {
	h := newHarness(t)
	h.srv.OnPoll = func(n int, _ telegramtest.Poll) {
		if n == 0 {
			h.srv.AddMessage(testChat, "/start "+testCode)
		}
	}
	err := Run(context.Background(), Options{ConfigPath: h.path, NoStart: true}, Deps{
		In:         strings.NewReader("\n"), // The policy answer only.
		Out:        &h.out,
		ReadSecret: func() (string, error) { return telegramtest.Token, nil },
		Now:        h.clock.now,
		Sleep:      h.clock.sleep,
		NewCode:    func() (string, error) { return testCode, nil },
		System:     h.sys,
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
}

func TestIdempotent(t *testing.T) {
	h := newHarness(t)
	opts := h.opts
	opts.TokenFile = h.writeTokenFile(t, telegramtest.Token)
	opts.ChatID, opts.Policy, opts.Yes = chatStr, config.PresetQuiet, true
	if err := h.run(context.Background(), t, opts, ""); err != nil {
		t.Fatal(err)
	}
	type snapshot struct {
		data  string
		mtime time.Time
	}
	snap := func(p string) snapshot {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return snapshot{read(t, p), info.ModTime()}
	}
	secrets := filepath.Join(h.dir, "secrets.env")
	c1, s1 := snap(h.path), snap(secrets)
	if want := []string{"enable --now vmmon"}; !reflect.DeepEqual(h.sys.actions(), want) {
		t.Fatalf("first run actions = %v", h.sys.actions())
	}
	time.Sleep(10 * time.Millisecond) // Let a rewrite show in the mtime.

	h.out.Reset()
	if err := h.run(context.Background(), t, opts, ""); err != nil {
		t.Fatal(err)
	}
	if snap(h.path) != c1 || snap(secrets) != s1 {
		t.Fatal("second run rewrote files")
	}
	if want := []string{"enable --now vmmon"}; !reflect.DeepEqual(h.sys.actions(), want) {
		t.Fatalf("second run added actions: %v", h.sys.actions())
	}
	if !strings.Contains(h.out.String(), "already running") {
		t.Fatalf("output:\n%s", h.out.String())
	}
	if len(h.srv.Sent()) != 2 {
		t.Fatalf("test messages = %d", len(h.srv.Sent()))
	}
}

func TestServiceStates(t *testing.T) {
	const manual = "sudo systemctl enable --now vmmon"
	tests := []struct {
		name    string
		sys     fakeSystem
		preset  string
		actions []string
		output  string
		wantErr bool
	}{
		{name: "active and changed restarts", sys: fakeSystem{active: true, enabled: true}, preset: config.PresetEverything,
			actions: []string{"restart vmmon"}, output: "800 MB"},
		{name: "active but disabled gets enabled", sys: fakeSystem{active: true}, preset: config.PresetEverything,
			actions: []string{"restart vmmon", "enable vmmon"}},
		{name: "inactive starts", sys: fakeSystem{}, preset: config.PresetEverything,
			actions: []string{"enable --now vmmon"}, output: "800 MB"},
		{name: "no systemd", sys: fakeSystem{noSystemd: true}, preset: config.PresetEverything, output: "systemd was not found"},
		{name: "no unit", sys: fakeSystem{noUnit: true}, preset: config.PresetEverything, output: manual},
		{name: "not root", sys: fakeSystem{euid: 1000}, preset: config.PresetEverything, output: manual},
		{name: "start fails", sys: fakeSystem{failStart: true}, preset: config.PresetEverything,
			actions: []string{"enable --now vmmon"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.seed(t, config.PresetQuiet)
			sys := tc.sys
			h.sys = &sys
			opts := h.opts
			opts.Policy, opts.Yes = tc.preset, true
			err := h.run(context.Background(), t, opts, "")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v", err)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "journalctl") {
				t.Fatalf("err = %v", err)
			}
			if !reflect.DeepEqual(sys.actions(), tc.actions) {
				t.Fatalf("actions = %v, want %v", sys.actions(), tc.actions)
			}
			if !strings.Contains(h.out.String(), tc.output) {
				t.Fatalf("output lacks %q:\n%s", tc.output, h.out.String())
			}
			if got := h.load(t).Policy.Preset; got != tc.preset {
				t.Fatalf("settings not saved: %s", got)
			}
		})
	}
}

func TestNoStartLeavesServiceAlone(t *testing.T) {
	h := newHarness(t)
	opts := h.opts
	opts.TokenFile = h.writeTokenFile(t, telegramtest.Token)
	opts.ChatID, opts.Yes, opts.NoStart = chatStr, true, true
	if err := h.run(context.Background(), t, opts, ""); err != nil {
		t.Fatal(err)
	}
	if len(h.sys.calls) != 0 {
		t.Fatalf("systemctl called: %v", h.sys.calls)
	}
}

func TestMustBeRootForDefaultPath(t *testing.T) {
	h := newHarness(t)
	h.sys.euid = 1000
	err := h.run(context.Background(), t, Options{ConfigPath: config.DefaultPath}, "")
	if err == nil || !strings.Contains(err.Error(), "sudo vmmon setup") {
		t.Fatalf("err = %v", err)
	}
	if h.srv.Calls("getMe") != 0 {
		t.Fatal("called Telegram before the permission check")
	}
}

func TestUnwritableDirectoryFailsEarly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory modes")
	}
	h := newHarness(t)
	h.sys.euid = 1000
	locked := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(locked, 0o555); err != nil {
		t.Fatal(err)
	}
	opts := Options{ConfigPath: filepath.Join(locked, "vmmon", "config.yaml"), NoStart: true}
	err := h.run(context.Background(), t, opts, "")
	if err == nil || !strings.Contains(err.Error(), "VMMON_CONFIG") {
		t.Fatalf("err = %v", err)
	}
	if h.srv.Calls("getMe") != 0 {
		t.Fatal("called Telegram before the permission check")
	}
}

func TestDirectoryModeIgnoresUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	h := newHarness(t)
	h.seed(t, config.PresetQuiet)
	if mode(t, h.dir) != 0o755 || mode(t, h.path) != 0o644 {
		t.Fatalf("dir %o, config %o", mode(t, h.dir), mode(t, h.path))
	}
}

func TestWidePermissionsRepaired(t *testing.T) {
	h := newHarness(t)
	h.seed(t, config.PresetQuiet)
	secrets := filepath.Join(h.dir, "secrets.env")
	if err := os.Chmod(secrets, 0o644); err != nil {
		t.Fatal(err)
	}
	opts := h.opts
	opts.Yes, opts.NoStart = true, true
	if err := h.run(context.Background(), t, opts, ""); err != nil {
		t.Fatal(err)
	}
	if mode(t, secrets) != 0o600 {
		t.Fatalf("secrets mode %o", mode(t, secrets))
	}
}

func TestOddTokensRoundTrip(t *testing.T) {
	tests := []struct{ token, line string }{
		{"123456:AAE-abc_DEF", "VMMON_TELEGRAM_TOKEN=123456:AAE-abc_DEF"},
		{"12:a=b", "VMMON_TELEGRAM_TOKEN=12:a=b"},
		{"12:a b", "VMMON_TELEGRAM_TOKEN='12:a b'"},
		{"12:a#b", "VMMON_TELEGRAM_TOKEN='12:a#b'"},
		{"12:a$b", "VMMON_TELEGRAM_TOKEN='12:a$b'"},
		{`12:a\b`, `VMMON_TELEGRAM_TOKEN='12:a\b'`},
		{"#12", "VMMON_TELEGRAM_TOKEN='#12'"},
		{"12:é", "VMMON_TELEGRAM_TOKEN='12:é'"},
	}
	for _, tc := range tests {
		t.Run(tc.token, func(t *testing.T) {
			t.Setenv("VMMON_TELEGRAM_TOKEN", "")
			_ = os.Unsetenv("VMMON_TELEGRAM_TOKEN")
			path := filepath.Join(t.TempDir(), "config.yaml")
			if _, err := writeFiles(path, tc.token, "1", config.PresetQuiet, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			secrets := filepath.Join(filepath.Dir(path), "secrets.env")
			if got := read(t, secrets); got != tc.line+"\n" {
				t.Fatalf("file = %q", got)
			}
			c, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if c.Telegram.Token != tc.token {
				t.Fatalf("read back %q", c.Telegram.Token)
			}
		})
	}
}

func TestUnstorableTokensRefused(t *testing.T) {
	for _, token := range []string{"a'b", `a"b`, "a\nb", "a\x00b", "a\tb", "\xff"} {
		_, err := envLine(token)
		if err == nil {
			t.Errorf("%q accepted", token)
			continue
		}
		if strings.Contains(err.Error(), token) {
			t.Errorf("error quotes the token: %v", err)
		}
	}
}

func TestSecretsKeepOtherLinesAndDropDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.env")
	writeFile(t, path, "# c\nA=1\nVMMON_TELEGRAM_TOKEN=old\n\nVMMON_TELEGRAM_TOKEN=older\nB=2\n", 0o600)
	changed, err := writeSecrets(path, "new")
	if err != nil || !changed {
		t.Fatalf("changed %v, err %v", changed, err)
	}
	if got, want := read(t, path), "# c\nA=1\nVMMON_TELEGRAM_TOKEN=new\n\nB=2\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestConfigEdgeCases(t *testing.T) {
	tests := map[string]string{
		"empty file":       "",
		"bare section":     "telegram:\npolicy:\n",
		"numeric chat":     "telegram:\n  chat_id: -5\n",
		"only other value": "hostname: h\n",
	}
	for name, seed := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			writeFile(t, path, seed, 0o644)
			if _, err := writeConfig(path, chatStr, config.PresetCritical); err != nil {
				t.Fatal(err)
			}
			c, err := config.Load(path)
			if err != nil {
				t.Fatalf("%v\n%s", err, read(t, path))
			}
			if c.Telegram.ChatID != chatStr || c.Policy.Preset != config.PresetCritical {
				t.Fatalf("got %+v\n%s", c.Telegram, read(t, path))
			}
			changed, err := writeConfig(path, chatStr, config.PresetCritical)
			if err != nil || changed {
				t.Fatalf("second write changed=%v err=%v", changed, err)
			}
		})
	}
	t.Run("not a mapping", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		writeFile(t, path, "- a\n", 0o644)
		if _, err := writeConfig(path, "1", config.PresetQuiet); err == nil {
			t.Fatal("want an error")
		}
	})
}

func TestIsPairingMessage(t *testing.T) {
	tests := []struct {
		text string
		want bool
	}{
		{"/start abc", true},
		{"/start@bot abc", true},
		{"/start@BOT abc", true},
		{"/start@other abc", false},
		{"/start abcd", false},
		{"/start", false},
		{"/start@bot", false},
		{"abc", false},
		{"/start abc ", false},
		{"/START abc", false},
	}
	for _, tc := range tests {
		if got := isPairingMessage(tc.text, "bot", "abc"); got != tc.want {
			t.Errorf("%q = %v", tc.text, got)
		}
	}
}

func TestPairingCodeAlphabet(t *testing.T) {
	re := regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
	seen := map[string]bool{}
	for range 50 {
		code, err := newPairingCode()
		if err != nil || !re.MatchString(code) || seen[code] {
			t.Fatalf("code %q, err %v", code, err)
		}
		seen[code] = true
	}
}

func testConfig(t *testing.T, h *harness, token, chat string) *config.Config {
	t.Helper()
	c := config.Default()
	c.Path = filepath.Join(t.TempDir(), "config.yaml")
	c.Hostname = "web-01"
	c.Telegram.APIBaseURL = h.srv.URL
	c.Telegram.Token, c.Telegram.ChatID = token, chat
	return c
}

func TestSendTest(t *testing.T) {
	ctx := context.Background()
	t.Run("delivered", func(t *testing.T) {
		h := newHarness(t)
		var out bytes.Buffer
		if err := SendTest(ctx, testConfig(t, h, telegramtest.Token, "7"), &out); err != nil {
			t.Fatal(err)
		}
		if s := h.srv.Sent(); len(s) != 1 || !strings.HasPrefix(s[0].Text, "<b>web-01</b>") {
			t.Fatalf("sent %+v", s)
		}
	})
	t.Run("not configured", func(t *testing.T) {
		h := newHarness(t)
		for _, c := range []*config.Config{testConfig(t, h, "", ""), testConfig(t, h, telegramtest.Token, ""), testConfig(t, h, "", "7")} {
			err := SendTest(ctx, c, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), "sudo vmmon setup") {
				t.Fatalf("err = %v", err)
			}
		}
	})
	t.Run("secrets unreadable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores file modes")
		}
		h := newHarness(t)
		c := testConfig(t, h, "", "7")
		writeFile(t, c.SecretsPath(), "VMMON_TELEGRAM_TOKEN=x\n", 0o000)
		err := SendTest(ctx, c, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "sudo vmmon notify test") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("permanent failure", func(t *testing.T) {
		h := newHarness(t)
		h.srv.Fail(telegramtest.Failure{Code: 403, Description: "Forbidden: bot was kicked"})
		err := SendTest(ctx, testConfig(t, h, telegramtest.Token, "7"), &bytes.Buffer{})
		if !errors.Is(err, notify.ErrPermanent) || !strings.Contains(err.Error(), "sudo vmmon setup") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("transient failure", func(t *testing.T) {
		h := newHarness(t)
		h.srv.Fail(telegramtest.Failure{Code: 500, Description: "oops"})
		err := SendTest(ctx, testConfig(t, h, telegramtest.Token, "7"), &bytes.Buffer{})
		if err == nil || errors.Is(err, notify.ErrPermanent) {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(fmt.Sprint(err), telegramtest.Token) {
			t.Fatal("token in error")
		}
	})
}
