// Package notify sends messages to the user's configured channels.
package notify

import (
	"context"
	"errors"
)

// ErrPermanent marks a failure retrying will not fix, such as a revoked token
// or a chat the bot was removed from. Wrap it so callers can use errors.Is.
var ErrPermanent = errors.New("permanent notification failure")

// Notifier delivers one HTML-formatted message. It handles splitting and rate
// limiting itself. A returned error means the message was not fully delivered,
// and unless it wraps ErrPermanent the caller should queue and retry it.
type Notifier interface {
	Name() string
	Send(ctx context.Context, html string) error
}
