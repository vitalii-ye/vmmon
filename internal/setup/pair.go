package setup

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mdp/qrterminal/v3"

	"github.com/vitalii-ye/vmmon/internal/telegram"
)

const (
	pairTimeout = 3 * time.Minute
	longPoll    = 25 * time.Second
	// pollPause spaces polls while unacknowledged updates make getUpdates return
	// at once instead of long-polling.
	pollPause  = time.Second
	retryPause = 2 * time.Second
)

// newPairingCode returns a single-use code in the alphabet a Telegram start
// payload allows: 22 characters, 128 bits.
func newPairingCode() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (w *wizard) pair(ctx context.Context, client *telegram.Client, me *telegram.User) (string, error) {
	code, err := w.NewCode()
	if err != nil {
		return "", fmt.Errorf("generate pairing code: %w", err)
	}
	link := "https://t.me/" + me.Username + "?start=" + code
	w.printf("\nOpen this link and press Start, or scan the code:\n  %s\n\n", link)
	qrterminal.GenerateHalfBlock(link, qrterminal.L, w.Out)
	w.printf("\nFor a group, add the bot to it and send:\n  /start@%s %s\n\nWaiting up to %s...\n", me.Username, code, pairTimeout)

	chatID, err := w.pollForCode(ctx, client, me.Username, code)
	if err != nil {
		return "", err
	}
	w.printf("Paired with chat %s.\n", chatID)
	return chatID, nil
}

// pollForCode waits for the message carrying code and returns its chat ID.
//
// Acknowledging an update deletes it for anyone else who reads this bot, so
// offset stays put while the code can still appear in the page Telegram returns,
// and already-seen updates are skipped locally. It advances only past a full
// page, which is the one case where the code could otherwise stay out of sight.
func (w *wizard) pollForCode(ctx context.Context, client *telegram.Client, bot, code string) (string, error) {
	deadline := w.Now().Add(pairTimeout)
	var offset, seen int64
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		remaining := deadline.Sub(w.Now())
		if remaining <= 0 {
			return "", fmt.Errorf("no message with the pairing code arrived within %s, so nothing was saved. Run setup again to get a new code", pairTimeout)
		}
		updates, err := client.GetUpdates(ctx, offset, min(remaining, longPoll).Truncate(time.Second))
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			pause, err := pollFailure(err)
			if err != nil {
				return "", err
			}
			if err := w.Sleep(ctx, pause); err != nil {
				return "", err
			}
			continue
		}
		for _, u := range updates {
			if u.UpdateID <= seen {
				continue
			}
			seen = u.UpdateID
			if u.Message != nil && isPairingMessage(u.Message.Text, bot, code) {
				return strconv.FormatInt(u.Message.Chat.ID, 10), nil
			}
		}
		if len(updates) >= telegram.UpdatesLimit {
			offset = seen + 1
			continue
		}
		if len(updates) > 0 {
			if err := w.Sleep(ctx, pollPause); err != nil {
				return "", err
			}
		}
	}
}

// pollFailure decides whether polling can continue after err, and how soon.
func pollFailure(err error) (time.Duration, error) {
	var apiErr *telegram.APIError
	if errors.As(err, &apiErr) {
		if apiErr.Code == 409 {
			return 0, fmt.Errorf("something else is reading this bot's updates, so pairing cannot: %w\nStop it and retry, or pass the chat ID with --chat-id", err)
		}
		if apiErr.Permanent() {
			return 0, fmt.Errorf("pairing failed: %w", err)
		}
		if apiErr.RetryAfter > 0 {
			return apiErr.RetryAfter, nil
		}
	}
	return retryPause, nil
}

// isPairingMessage accepts exactly "/start <code>" or "/start@bot <code>".
func isPairingMessage(text, bot, code string) bool {
	command, payload, ok := strings.Cut(text, " ")
	if !ok || payload != code {
		return false
	}
	if command == "/start" {
		return true
	}
	target, ok := strings.CutPrefix(command, "/start@")
	return ok && strings.EqualFold(target, bot)
}
