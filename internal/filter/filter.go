// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package filter inspects untagged IMAP responses (LIST, LSUB, STATUS) and
// returns nil for those whose mailbox is hidden under the per-connection
// rules. All other lines are returned unchanged.
//
// Mailbox names are decoded from modified UTF-7 to UTF-8 before matching, so
// configuration rules can be written in plain UTF-8.
package filter

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/benalbrecht/imap-shadow/internal/rules"
	"github.com/emersion/go-imap/utf7"
)

// Filter applies a single Matcher to incoming server lines.
type Filter struct {
	m *rules.Matcher
}

// New wraps a rules Matcher in a Filter.
func New(m *rules.Matcher) *Filter {
	return &Filter{m: m}
}

// Process returns line for keep, or nil for drop.
func (f *Filter) Process(line []byte) []byte {
	if f == nil || f.m == nil || len(line) == 0 {
		return line
	}
	name, ok := mailboxFromResponse(line)
	if !ok {
		return line
	}
	decoded, err := utf7.Encoding.NewDecoder().String(name)
	if err != nil {
		decoded = name
	}
	if f.m.ShouldHide(decoded) {
		return nil
	}
	return line
}

// mailboxFromResponse extracts the mailbox name from a "* LIST", "* LSUB" or
// "* STATUS" response. Returns ("", false) for any other line shape, or when
// parsing fails.
func mailboxFromResponse(line []byte) (string, bool) {
	if len(line) < 4 || line[0] != '*' || line[1] != ' ' {
		return "", false
	}
	rest := line[2:]
	upper := bytes.ToUpper(rest)
	switch {
	case bytes.HasPrefix(upper, []byte("LIST ")) || bytes.HasPrefix(upper, []byte("LSUB ")):
		return mailboxFromList(rest[5:])
	case bytes.HasPrefix(upper, []byte("STATUS ")):
		return mailboxFromStatus(rest[7:])
	}
	return "", false
}

// mailboxFromList parses the args of a LIST/LSUB response: "(flags) delim mailbox".
func mailboxFromList(b []byte) (string, bool) {
	p := &parser{buf: b}
	if !p.skipParenList() {
		return "", false
	}
	if !p.skipArg() { // delimiter
		return "", false
	}
	return p.readArg()
}

// mailboxFromStatus parses the args of a STATUS response: "mailbox (...)".
func mailboxFromStatus(b []byte) (string, bool) {
	p := &parser{buf: b}
	return p.readArg()
}

type parser struct {
	buf []byte
	pos int
}

func (p *parser) skipWS() {
	for p.pos < len(p.buf) && (p.buf[p.pos] == ' ' || p.buf[p.pos] == '\t') {
		p.pos++
	}
}

// skipParenList consumes a "(...)" list including nested parens.
func (p *parser) skipParenList() bool {
	p.skipWS()
	if p.pos >= len(p.buf) || p.buf[p.pos] != '(' {
		return false
	}
	depth := 0
	for p.pos < len(p.buf) {
		c := p.buf[p.pos]
		switch c {
		case '(':
			depth++
		case ')':
			depth--
			p.pos++
			if depth == 0 {
				return true
			}
			continue
		}
		p.pos++
	}
	return false
}

// skipArg discards the next IMAP argument (atom, NIL, quoted, or literal).
func (p *parser) skipArg() bool {
	_, ok := p.readArg()
	return ok
}

// readArg reads a single IMAP argument and returns it as a Go string.
// For NIL, returns ("", true) — caller decides what NIL means.
func (p *parser) readArg() (string, bool) {
	p.skipWS()
	if p.pos >= len(p.buf) {
		return "", false
	}
	switch p.buf[p.pos] {
	case '"':
		return p.readQuoted()
	case '{':
		return p.readLiteral()
	default:
		return p.readAtom()
	}
}

func (p *parser) readQuoted() (string, bool) {
	if p.pos >= len(p.buf) || p.buf[p.pos] != '"' {
		return "", false
	}
	p.pos++
	var out []byte
	for p.pos < len(p.buf) {
		c := p.buf[p.pos]
		if c == '\\' && p.pos+1 < len(p.buf) {
			out = append(out, p.buf[p.pos+1])
			p.pos += 2
			continue
		}
		if c == '"' {
			p.pos++
			return string(out), true
		}
		out = append(out, c)
		p.pos++
	}
	return "", false
}

// readLiteral consumes a "{N}\r\n<N bytes>" form. The framer has already
// inlined the bytes for us.
func (p *parser) readLiteral() (string, bool) {
	if p.pos >= len(p.buf) || p.buf[p.pos] != '{' {
		return "", false
	}
	end := bytes.IndexByte(p.buf[p.pos:], '}')
	if end < 0 {
		return "", false
	}
	digits := p.buf[p.pos+1 : p.pos+end]
	if len(digits) > 0 && digits[len(digits)-1] == '+' {
		digits = digits[:len(digits)-1]
	}
	n, err := strconv.Atoi(string(digits))
	if err != nil || n < 0 {
		return "", false
	}
	// after '}', expect "\r\n"
	after := p.pos + end + 1
	if after+2 > len(p.buf) || p.buf[after] != '\r' || p.buf[after+1] != '\n' {
		return "", false
	}
	start := after + 2
	if start+n > len(p.buf) {
		return "", false
	}
	val := string(p.buf[start : start+n])
	p.pos = start + n
	return val, true
}

func (p *parser) readAtom() (string, bool) {
	start := p.pos
	for p.pos < len(p.buf) {
		c := p.buf[p.pos]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '(' || c == ')' {
			break
		}
		p.pos++
	}
	if p.pos == start {
		return "", false
	}
	atom := string(p.buf[start:p.pos])
	if strings.EqualFold(atom, "NIL") {
		return "", true
	}
	return atom, true
}
