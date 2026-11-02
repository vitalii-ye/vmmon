// Package setup is the `vmmon setup` wizard: it validates a bot token, pairs a
// chat, proves delivery with a test message, and only then writes the config and
// starts the service. A failure before that point changes nothing on disk.
//
// Re-running is safe: every step starts from the current values, Enter keeps
// them, and a run that changes nothing writes nothing.
package setup

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/vitalii-ye/vmmon/internal/config"
	"github.com/vitalii-ye/vmmon/internal/notify"
	"github.com/vitalii-ye/vmmon/internal/telegram"
)

const (
	sudoHint = "sudo vmmon setup"
	unitName = "vmmon"
	// sendTimeout bounds a test message, including waiting out a 429.
	sendTimeout = time.Minute
)

var chatIDRe = regexp.MustCompile(`^(-?[0-9]+|@[A-Za-z0-9_]{5,})$`)

// Options are the command-line choices. A set value answers its prompt; Yes
// turns any remaining prompt into an error or the current value.
type Options struct {
	ConfigPath string
	TokenFile  string
	ChatID     string
	Policy     string
	Yes        bool
	NoStart    bool
}

// System is what setup needs from the host.
type System interface {
	Geteuid() int
	// HasSystemd reports whether systemd is running this host.
	HasSystemd() bool
	Systemctl(ctx context.Context, args ...string) error
}

// Deps are the wizard's connections to the outside world. In, Out and System are
// required; the rest default to the real thing.
type Deps struct {
	In  io.Reader
	Out io.Writer
	// ReadSecret reads the token without echoing it. Nil reads a line from In.
	ReadSecret func() (string, error)
	Now        func() time.Time
	Sleep      func(context.Context, time.Duration) error
	NewCode    func() (string, error)
	System     System
}

type wizard struct {
	Deps
	opts Options
	cfg  *config.Config
	in   *bufio.Reader
}

// Run runs the wizard to completion.
func Run(ctx context.Context, opts Options, deps Deps) error {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Sleep == nil {
		deps.Sleep = notify.Sleep
	}
	if deps.NewCode == nil {
		deps.NewCode = newPairingCode
	}
	w := &wizard{Deps: deps, opts: opts, in: bufio.NewReader(deps.In)}
	return w.run(ctx)
}

func (w *wizard) run(ctx context.Context) error {
	if p := w.opts.Policy; p != "" && !validPreset(p) {
		return fmt.Errorf("--policy: unknown preset %q (want quiet, critical or everything)", p)
	}
	if id := w.opts.ChatID; id != "" && !chatIDRe.MatchString(id) {
		return fmt.Errorf("--chat-id: %q is not a chat ID", id)
	}
	cfg, err := config.Load(w.opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("load existing config: %w", err)
	}
	w.cfg = cfg
	if err := w.preflight(); err != nil {
		return err
	}
	if t := cfg.Telegram; !w.opts.Yes && (t.Token != "" || t.ChatID != "") {
		w.printf("Current settings: token %s, chat %s, policy %s. Enter keeps a value.\n",
			t.Redacted(), orNotSet(t.ChatID), cfg.Policy.Preset)
	}

	token, client, me, err := w.chooseToken(ctx)
	if err != nil {
		return err
	}
	w.printf("Bot: %s (@%s)\n", me.FirstName, me.Username)

	hook, err := client.GetWebhookInfo(ctx)
	if err != nil {
		return err
	}
	// Bots often use their token as the webhook's secret path.
	hook.URL = strings.ReplaceAll(hook.URL, token, "<TOKEN>")
	chatID, err := w.chooseChat(ctx, client, me, hook)
	if err != nil {
		return err
	}

	if err := w.sendTest(ctx, client, chatID); err != nil {
		return fmt.Errorf("test message not delivered to chat %s, so nothing was saved: %w\nCheck that the bot is in that chat, then run setup again", chatID, err)
	}
	w.printf("Test message sent to chat %s.\n", chatID)

	preset, err := w.choosePolicy(ctx)
	if err != nil {
		return err
	}
	changed, err := writeFiles(w.cfg.Path, token, chatID, preset, w.Out)
	if err != nil {
		return fmt.Errorf("save settings: %w", err)
	}
	if changed {
		w.printf("Saved %s and %s.\n", w.cfg.Path, w.cfg.SecretsPath())
	} else {
		w.printf("Settings unchanged.\n")
	}
	return w.start(ctx, changed)
}

// preflight fails early, before anyone pairs a chat only to hit a write error.
func (w *wizard) preflight() error {
	if w.System.Geteuid() != 0 && w.cfg.Path == config.DefaultPath && !w.opts.NoStart {
		return fmt.Errorf("setup writes %s and starts the service, so it must run as root: %s\n(To try it without root, set VMMON_CONFIG to a writable path.)", filepath.Dir(w.cfg.Path), sudoHint)
	}
	if err := checkWritable(filepath.Dir(w.cfg.Path)); err != nil {
		return fmt.Errorf("cannot write the config: %w\nRun as root (%s) or set VMMON_CONFIG to a writable path", err, sudoHint)
	}
	if _, err := os.ReadFile(w.cfg.SecretsPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("cannot read existing secrets: %w\nRun as root: %s", err, sudoHint)
	}
	return nil
}

// checkWritable tries a temp file in dir, or in its nearest existing parent if
// dir does not exist yet, so that the check itself creates nothing lasting.
func checkWritable(dir string) error {
	for {
		info, err := os.Stat(dir)
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("%s is not a directory", dir)
			}
			break
		}
		if !errors.Is(err, fs.ErrNotExist) || filepath.Dir(dir) == dir {
			return err
		}
		dir = filepath.Dir(dir)
	}
	f, err := os.CreateTemp(dir, ".vmmon-setup-*")
	if err != nil {
		return err
	}
	f.Close()
	return os.Remove(f.Name())
}

func (w *wizard) chooseToken(ctx context.Context) (string, *telegram.Client, *telegram.User, error) {
	validate := func(token string) (*telegram.Client, *telegram.User, error) {
		if _, err := envLine(token); err != nil {
			return nil, nil, err
		}
		client := telegram.New(w.cfg.Telegram.APIBaseURL, token, nil)
		me, err := client.GetMe(ctx)
		return client, me, err
	}

	current := w.cfg.Telegram.Token
	if w.opts.TokenFile != "" || w.opts.Yes {
		token := current
		if w.opts.TokenFile != "" {
			data, err := os.ReadFile(w.opts.TokenFile)
			if err != nil {
				return "", nil, nil, fmt.Errorf("--token-file: %w", err)
			}
			if token = strings.TrimSpace(string(data)); token == "" {
				return "", nil, nil, fmt.Errorf("--token-file: %s is empty", w.opts.TokenFile)
			}
		}
		if token == "" {
			return "", nil, nil, errors.New("--yes needs --token-file: no bot token is configured yet")
		}
		client, me, err := validate(token)
		if err != nil {
			return "", nil, nil, fmt.Errorf("check bot token: %w", err)
		}
		return token, client, me, nil
	}

	for {
		if current == "" {
			w.printf("Create a bot with @BotFather and paste its token.\nBot token: ")
		} else {
			w.printf("Bot token (Enter keeps the current one): ")
		}
		token, err := w.readSecret(ctx)
		if err != nil {
			return "", nil, nil, err
		}
		if token == "" {
			if current == "" {
				continue
			}
			token = current
		}
		client, me, err := validate(token)
		if err == nil {
			return token, client, me, nil
		}
		// A transient failure says nothing about the token, so stop here.
		var syntax *tokenSyntaxError
		if !telegram.IsPermanent(err) && !errors.As(err, &syntax) {
			return "", nil, nil, fmt.Errorf("check bot token: %w", err)
		}
		w.printf("That token does not work: %v\n", err)
	}
}

func (w *wizard) chooseChat(ctx context.Context, client *telegram.Client, me *telegram.User, hook *telegram.WebhookInfo) (string, error) {
	current := w.cfg.Telegram.ChatID
	if hook.URL != "" && (w.opts.ChatID != "" || w.opts.Yes || current != "") {
		w.printf("Note: this bot has a webhook set (%s). Alerts are unaffected, but pairing is blocked while it is set.\n", hook.URL)
	}
	if w.opts.ChatID != "" {
		return w.opts.ChatID, nil
	}
	if w.opts.Yes {
		if current == "" {
			return "", errors.New("--yes needs --chat-id: no chat is configured yet")
		}
		return current, nil
	}
	if current != "" {
		for {
			w.printf("Chat ID [%s] (Enter keeps it, \"pair\" pairs a new chat, or type an ID): ", current)
			answer, err := w.readLine(ctx)
			if err != nil {
				return "", err
			}
			switch {
			case answer == "":
				return current, nil
			case answer == "pair":
				return w.pairOrManual(ctx, client, me, hook.URL)
			case chatIDRe.MatchString(answer):
				return answer, nil
			}
			w.printf("That is not a chat ID.\n")
		}
	}
	return w.pairOrManual(ctx, client, me, hook.URL)
}

func (w *wizard) pairOrManual(ctx context.Context, client *telegram.Client, me *telegram.User, hookURL string) (string, error) {
	if hookURL == "" {
		return w.pair(ctx, client, me)
	}
	w.printf(`This bot has a webhook set (%s), so pairing cannot read its messages.
vmmon will not remove it. Either type the chat ID below, or press Enter to exit,
remove the webhook yourself and run setup again. Whatever uses that webhook stops
receiving updates:
  curl -X POST 'https://api.telegram.org/bot<TOKEN>/deleteWebhook'
`, hookURL)
	for {
		w.printf("Chat ID: ")
		answer, err := w.readLine(ctx)
		if err != nil {
			return "", err
		}
		if answer == "" {
			return "", errors.New("the bot has a webhook set and no chat ID was given, so nothing was saved")
		}
		if chatIDRe.MatchString(answer) {
			return answer, nil
		}
		w.printf("That is not a chat ID.\n")
	}
}

func (w *wizard) sendTest(ctx context.Context, client *telegram.Client, chatID string) error {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	n := notify.NewTelegram(client, chatID)
	n.SetClock(w.Now, w.Sleep)
	return n.Send(ctx, notify.TestMessage(notify.Hostname(w.cfg)))
}

func (w *wizard) choosePolicy(ctx context.Context) (string, error) {
	if w.opts.Policy != "" {
		return w.opts.Policy, nil
	}
	current := w.cfg.Policy.Preset
	if w.opts.Yes {
		return current, nil
	}
	p := w.cfg.Policy
	w.printf(`Alert policy:
  1. quiet       alert on KEV-listed findings, or a fix with CVSS >= %g or EPSS >= %g; daily digest at %s
  2. critical    alert on KEV-listed findings only; weekly digest
  3. everything  alert on any new finding; daily digest
`, p.MinCVSS, p.MinEPSS, p.DigestTime)
	for {
		w.printf("Policy [%s]: ", current)
		answer, err := w.readLine(ctx)
		if err != nil {
			return "", err
		}
		switch answer {
		case "":
			return current, nil
		case "1", config.PresetQuiet:
			return config.PresetQuiet, nil
		case "2", config.PresetCritical:
			return config.PresetCritical, nil
		case "3", config.PresetEverything:
			return config.PresetEverything, nil
		}
		w.printf("Choose 1, 2 or 3.\n")
	}
}

// start brings the service in line with the saved settings. Once the settings
// are saved, a host without the unit gets next steps rather than a failure.
func (w *wizard) start(ctx context.Context, changed bool) error {
	const manual = "sudo systemctl enable --now " + unitName
	switch {
	case w.opts.NoStart:
		w.printf("Not starting the service (--no-start). To start it: %s\n", manual)
		return nil
	case w.System.Geteuid() != 0:
		w.printf("Not root, so the service was not started. To start it: %s\n", manual)
		return nil
	case !w.System.HasSystemd():
		w.printf("systemd was not found, so the service was not started. Run `vmmon daemon` under your init system, with the variables from %s in its environment.\n", w.cfg.SecretsPath())
		return nil
	}
	if err := w.System.Systemctl(ctx, "cat", unitName+".service"); err != nil {
		w.printf("The %s service is not installed, so it was not started. Install the vmmon package, then run: %s\n", unitName, manual)
		return nil
	}
	if w.cfg.Path != config.DefaultPath {
		w.printf("Note: the service must have VMMON_CONFIG=%s to use these settings.\n", w.cfg.Path)
	}

	var err error
	active := w.System.Systemctl(ctx, "is-active", "--quiet", unitName) == nil
	switch {
	case !active:
		err = w.System.Systemctl(ctx, "enable", "--now", unitName)
	case changed:
		err = w.System.Systemctl(ctx, "restart", unitName)
	}
	if err == nil && active && w.System.Systemctl(ctx, "is-enabled", "--quiet", unitName) != nil {
		err = w.System.Systemctl(ctx, "enable", unitName)
	}
	if err != nil {
		return fmt.Errorf("settings are saved, but the service did not start: %w\nCheck: journalctl -u %s", err, unitName)
	}
	if active && !changed {
		w.printf("The service is already running with these settings.\n")
		return nil
	}
	w.printf("The service is running. A summary will arrive in Telegram after the first database sync. On Ubuntu that can take a few minutes: it downloads about 800 MB.\n")
	return nil
}

// SendTest is `vmmon notify test`.
func SendTest(ctx context.Context, cfg *config.Config, out io.Writer) error {
	if cfg.Telegram.Token == "" {
		if f, err := os.Open(cfg.SecretsPath()); errors.Is(err, fs.ErrPermission) {
			return fmt.Errorf("cannot read %s, which holds the bot token. Try: sudo vmmon notify test", cfg.SecretsPath())
		} else if err == nil {
			f.Close()
		}
	}
	n, err := notify.New(cfg)
	if err != nil {
		return fmt.Errorf("Telegram is not set up. Run: %s", sudoHint)
	}
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	if err := n.Send(ctx, notify.TestMessage(notify.Hostname(cfg))); err != nil {
		if errors.Is(err, notify.ErrPermanent) {
			return fmt.Errorf("test message not delivered: %w\nTo fix the token or chat, run: %s", err, sudoHint)
		}
		return fmt.Errorf("test message not delivered: %w", err)
	}
	fmt.Fprintf(out, "Test message sent to chat %s.\n", cfg.Telegram.ChatID)
	return nil
}

func (w *wizard) printf(format string, args ...any) { fmt.Fprintf(w.Out, format, args...) }

func (w *wizard) readSecret(ctx context.Context) (string, error) {
	if w.ReadSecret == nil {
		return w.readLine(ctx)
	}
	return readCtx(ctx, w.ReadSecret)
}

func (w *wizard) readLine(ctx context.Context) (string, error) {
	return readCtx(ctx, func() (string, error) {
		line, err := w.in.ReadString('\n')
		if errors.Is(err, io.EOF) && line != "" {
			return line, nil
		}
		return line, err
	})
}

// readCtx runs a blocking read that Ctrl-C can abandon.
func readCtx(ctx context.Context, read func() (string, error)) (string, error) {
	type result struct {
		s   string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		s, err := read()
		ch <- result{s, err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case r := <-ch:
		if errors.Is(r.err, io.EOF) {
			return "", errors.New("input ended before setup finished; for scripts, use --token-file, --chat-id and --yes")
		}
		return strings.TrimSpace(r.s), r.err
	}
}

func validPreset(p string) bool {
	return p == config.PresetQuiet || p == config.PresetCritical || p == config.PresetEverything
}

func orNotSet(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}
