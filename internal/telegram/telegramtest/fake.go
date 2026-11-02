// Package telegramtest is a fake Telegram Bot API for tests. It enforces the
// parts of the real API that vmmon relies on: token checks, the 4096-unit limit
// measured in UTF-16 after HTML parsing, balanced HTML, a webhook blocking
// getUpdates, and offset acknowledging updates.
package telegramtest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/vitalii-ye/vmmon/internal/telegram"
)

// Token is the token a default fake accepts.
const Token = "123456:TEST-secret_TOKEN"

// Failure is a canned error response.
type Failure struct {
	Code        int
	Description string
	RetryAfter  int
}

// Poll is one getUpdates request.
type Poll struct {
	Offset  int64
	Timeout time.Duration
}

// Sent is one accepted sendMessage request.
type Sent struct {
	ChatID         string
	Text           string
	ParseMode      string
	DisablePreview bool
}

// Server is the fake. Set fields before use or under Lock.
type Server struct {
	*httptest.Server
	sync.Mutex

	Token       string
	BotUsername string
	WebhookURL  string

	// OnPoll runs at the start of each getUpdates, with the 0-based call
	// number, without the lock held. Tests use it to inject updates and advance
	// a fake clock.
	OnPoll func(n int, p Poll)

	updates  []telegram.Update
	nextID   int64
	failures []Failure
	polls    []Poll
	sent     []Sent
	calls    map[string]int
}

// New starts a fake and stops it when the test ends.
func New(t interface{ Cleanup(func()) }) *Server {
	s := &Server{Token: Token, BotUsername: "vmmon_test_bot", nextID: 1000, calls: map[string]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	return s
}

// AddMessage queues an incoming message update and returns its update ID.
func (s *Server) AddMessage(chatID int64, text string) int64 {
	s.Lock()
	defer s.Unlock()
	s.nextID++
	s.updates = append(s.updates, telegram.Update{
		UpdateID: s.nextID,
		Message:  &telegram.Message{MessageID: s.nextID, Chat: telegram.Chat{ID: chatID, Type: "private"}, Text: text},
	})
	return s.nextID
}

// Fail makes the next sendMessage or getUpdates requests fail, in order.
func (s *Server) Fail(f ...Failure) {
	s.Lock()
	defer s.Unlock()
	s.failures = append(s.failures, f...)
}

// Sent returns the accepted messages.
func (s *Server) Sent() []Sent {
	s.Lock()
	defer s.Unlock()
	return append([]Sent(nil), s.sent...)
}

// Polls returns every getUpdates request seen.
func (s *Server) Polls() []Poll {
	s.Lock()
	defer s.Unlock()
	return append([]Poll(nil), s.polls...)
}

// Pending returns how many updates Telegram would still deliver.
func (s *Server) Pending() int {
	s.Lock()
	defer s.Unlock()
	return len(s.updates)
}

// Calls returns how many times a method was called.
func (s *Server) Calls(method string) int {
	s.Lock()
	defer s.Unlock()
	return s.calls[method]
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	token, method, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/bot"), "/")
	if !ok || !strings.HasPrefix(r.URL.Path, "/bot") {
		writeErr(w, Failure{Code: 404, Description: "Not Found"})
		return
	}
	s.Lock()
	s.calls[method]++
	wantToken := s.Token
	s.Unlock()
	if token != wantToken {
		writeErr(w, Failure{Code: 401, Description: "Unauthorized"})
		return
	}
	switch method {
	case "getMe":
		writeOK(w, telegram.User{ID: 42, IsBot: true, FirstName: "vmmon test", Username: s.BotUsername})
	case "getWebhookInfo":
		s.Lock()
		info := telegram.WebhookInfo{URL: s.WebhookURL}
		s.Unlock()
		writeOK(w, info)
	case "getUpdates":
		s.getUpdates(w, r)
	case "sendMessage":
		s.sendMessage(w, r)
	default:
		writeErr(w, Failure{Code: 404, Description: "Not Found"})
	}
}

func (s *Server) nextFailure() (Failure, bool) {
	if len(s.failures) == 0 {
		return Failure{}, false
	}
	f := s.failures[0]
	s.failures = s.failures[1:]
	return f, true
}

func (s *Server) getUpdates(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Offset  int64 `json:"offset"`
		Limit   int   `json:"limit"`
		Timeout int   `json:"timeout"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, Failure{Code: 400, Description: "Bad Request: " + err.Error()})
		return
	}
	poll := Poll{Offset: req.Offset, Timeout: time.Duration(req.Timeout) * time.Second}
	s.Lock()
	n := len(s.polls)
	s.polls = append(s.polls, poll)
	hook := s.OnPoll
	s.Unlock()
	if hook != nil {
		hook(n, poll)
	}

	s.Lock()
	defer s.Unlock()
	if s.WebhookURL != "" {
		writeErr(w, Failure{Code: 409, Description: "Conflict: can't use getUpdates method while webhook is active; use deleteWebhook to delete the webhook first"})
		return
	}
	if f, ok := s.nextFailure(); ok {
		writeErr(w, f)
		return
	}
	// A positive offset acknowledges everything below it, for good.
	if req.Offset > 0 {
		kept := s.updates[:0]
		for _, u := range s.updates {
			if u.UpdateID >= req.Offset {
				kept = append(kept, u)
			}
		}
		s.updates = kept
	}
	page := s.updates
	if req.Limit > 0 && len(page) > req.Limit {
		page = page[:req.Limit]
	}
	writeOK(w, append([]telegram.Update{}, page...))
}

func (s *Server) sendMessage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChatID         string `json:"chat_id"`
		Text           string `json:"text"`
		ParseMode      string `json:"parse_mode"`
		DisablePreview bool   `json:"disable_web_page_preview"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, Failure{Code: 400, Description: "Bad Request: " + err.Error()})
		return
	}
	s.Lock()
	defer s.Unlock()
	if f, ok := s.nextFailure(); ok {
		writeErr(w, f)
		return
	}
	n, err := ParsedLen(req.Text)
	switch {
	case err != nil:
		writeErr(w, Failure{Code: 400, Description: "Bad Request: can't parse entities: " + err.Error()})
		return
	case n == 0:
		writeErr(w, Failure{Code: 400, Description: "Bad Request: message text is empty"})
		return
	case n > 4096:
		writeErr(w, Failure{Code: 400, Description: "Bad Request: message is too long"})
		return
	}
	s.sent = append(s.sent, Sent{req.ChatID, req.Text, req.ParseMode, req.DisablePreview})
	writeOK(w, telegram.Message{MessageID: int64(len(s.sent))})
}

var (
	tagRe    = regexp.MustCompile(`^<(/?)([a-zA-Z][a-zA-Z0-9-]*)((?:\s+[a-zA-Z-]+(?:="[^"]*")?)*)\s*>`)
	entityRe = regexp.MustCompile(`^&(lt|gt|amp|quot|#[0-9]+|#x[0-9a-fA-F]+);`)
)

// ParsedLen validates HTML the way Telegram does and returns the text length in
// UTF-16 code units, after trimming surrounding whitespace.
func ParsedLen(html string) (int, error) {
	var stack []string
	var text strings.Builder
	for i := 0; i < len(html); {
		switch html[i] {
		case '<':
			m := tagRe.FindStringSubmatch(html[i:])
			if m == nil {
				return 0, fmt.Errorf("bad tag at byte %d", i)
			}
			if m[1] == "/" {
				if len(stack) == 0 || stack[len(stack)-1] != m[2] {
					return 0, fmt.Errorf("unmatched </%s> at byte %d", m[2], i)
				}
				stack = stack[:len(stack)-1]
			} else {
				stack = append(stack, m[2])
			}
			i += len(m[0])
		case '&':
			m := entityRe.FindString(html[i:])
			if m == "" {
				return 0, fmt.Errorf("bad entity at byte %d", i)
			}
			text.WriteByte('x')
			i += len(m)
		default:
			text.WriteByte(html[i])
			i++
		}
	}
	if len(stack) > 0 {
		return 0, fmt.Errorf("unclosed <%s>", stack[len(stack)-1])
	}
	return len(utf16.Encode([]rune(strings.TrimSpace(text.String())))), nil
}

func writeOK(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
}

func writeErr(w http.ResponseWriter, f Failure) {
	body := map[string]any{"ok": false, "error_code": f.Code, "description": f.Description}
	if f.RetryAfter > 0 {
		body["parameters"] = map[string]int{"retry_after": f.RetryAfter}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.Code)
	_ = json.NewEncoder(w).Encode(body)
}
