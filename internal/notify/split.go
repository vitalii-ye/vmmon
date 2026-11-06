package notify

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxMessageLen is Telegram's limit, in UTF-16 code units after HTML parsing:
// tags count for nothing, an entity for what it stands for, an emoji for two.
const maxMessageLen = 4096

type tokenKind int

const (
	tokenText  tokenKind = iota // one rune or one entity
	tokenOpen                   // <b>, <a href="...">
	tokenClose                  // </b>
)

type token struct {
	kind  tokenKind
	raw   string
	name  string // tag name, for open and close
	units int    // UTF-16 code units, for text
}

// tokenize cuts HTML into pieces that must never be split. Text that is not
// valid markup, such as a stray "<", stays text; Telegram will reject it, but
// splitting loses nothing.
func tokenize(html string) []token {
	toks := make([]token, 0, len(html))
	for i := 0; i < len(html); {
		switch rest := html[i:]; rest[0] {
		case '<':
			if n := tagLen(rest); n > 0 {
				toks = append(toks, newTag(rest[:n]))
				i += n
				continue
			}
		case '&':
			if n := entityLen(rest); n > 0 {
				units := 1
				if rest[1] == '#' {
					units = 2 // It may decode to a character outside the BMP.
				}
				toks = append(toks, token{raw: rest[:n], units: units})
				i += n
				continue
			}
		}
		r, n := utf8.DecodeRuneInString(html[i:])
		units := 1
		if r > 0xFFFF {
			units = 2
		}
		toks = append(toks, token{raw: html[i : i+n], units: units})
		i += n
	}
	return toks
}

// tagLen returns the length of the tag s starts with, or 0. A ">" inside a
// quoted attribute does not end the tag.
func tagLen(s string) int {
	if len(s) < 3 || (!isTagNameByte(s[1]) && (s[1] != '/' || !isTagNameByte(s[2]))) {
		return 0
	}
	var quote byte
	for i := 1; i < len(s); i++ {
		switch c := s[i]; {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '<':
			return 0
		case c == '>':
			return i + 1
		}
	}
	return 0
}

func isTagNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
}

func newTag(raw string) token {
	t := token{kind: tokenOpen, raw: raw}
	name := raw[1 : len(raw)-1]
	if name[0] == '/' {
		t.kind = tokenClose
		name = name[1:]
	}
	if i := strings.IndexFunc(name, func(r rune) bool { return r > 127 || !isTagNameByte(byte(r)) }); i >= 0 { //nolint:gosec // r <= 127 here
		name = name[:i]
	}
	t.name = strings.ToLower(name)
	return t
}

// entityLen returns the length of the entity s starts with, or 0.
func entityLen(s string) int {
	for i := 1; i < len(s) && i <= 12; i++ {
		c := s[i]
		if c == ';' {
			if i == 1 {
				return 0
			}
			return i + 1
		}
		if (!isTagNameByte(c) || c == '-') && c != '#' {
			return 0
		}
	}
	return 0
}

// splitHTML cuts html into chunks of at most limit units, each valid on its own:
// tags open at a cut are closed there and reopened in the next chunk. It cuts
// after a newline if it can, else after a space, else between two characters.
// Chunks with nothing visible are dropped, since Telegram refuses them.
func splitHTML(html string, limit int) []string {
	toks := tokenize(html)
	var chunks []string
	var open []token
	for start := 0; start < len(toks); {
		cut, stack := findCut(toks, start, limit, open)

		var b strings.Builder
		visible := false
		for _, t := range open {
			b.WriteString(t.raw)
		}
		for _, t := range toks[start:cut] {
			b.WriteString(t.raw)
			if t.kind == tokenText && !isSpaceToken(t) {
				visible = true
			}
		}
		for i := len(stack) - 1; i >= 0; i-- {
			b.WriteString("</" + stack[i].name + ">")
		}
		if visible {
			chunks = append(chunks, b.String())
		}
		start, open = cut, stack
	}
	return chunks
}

// findCut returns where the chunk starting at start should end and the tags
// still open there.
func findCut(toks []token, start, limit int, open []token) (int, []token) {
	stack := append([]token(nil), open...)
	var lineCut, spaceCut int
	var lineStack, spaceStack []token
	units := 0
	for i := start; i < len(toks); i++ {
		t := toks[i]
		switch t.kind {
		case tokenOpen:
			stack = append(stack, t)
			continue
		case tokenClose:
			stack = popTag(stack, t.name)
			continue
		}
		if units+t.units > limit {
			switch {
			case lineCut > start:
				return absorbClosers(toks, lineCut, lineStack)
			case spaceCut > start:
				return absorbClosers(toks, spaceCut, spaceStack)
			case i > start:
				return absorbClosers(toks, i, stack)
			}
			// limit is smaller than one character; still make progress.
			return i + 1, stack
		}
		units += t.units
		if t.raw == "\n" {
			lineCut, lineStack = i+1, append([]token(nil), stack...)
		} else if isSpaceToken(t) {
			spaceCut, spaceStack = i+1, append([]token(nil), stack...)
		}
	}
	return len(toks), stack
}

// absorbClosers moves a cut past closing tags that immediately follow it, so the
// next chunk does not begin with an empty <b></b>.
func absorbClosers(toks []token, cut int, stack []token) (int, []token) {
	for cut < len(toks) && toks[cut].kind == tokenClose && len(stack) > 0 && stack[len(stack)-1].name == toks[cut].name {
		stack = stack[:len(stack)-1]
		cut++
	}
	return cut, stack
}

func popTag(stack []token, name string) []token {
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i].name == name {
			return stack[:i]
		}
	}
	return stack
}

func isSpaceToken(t token) bool {
	r, _ := utf8.DecodeRuneInString(t.raw)
	return unicode.IsSpace(r)
}
