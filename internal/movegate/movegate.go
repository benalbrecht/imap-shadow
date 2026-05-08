// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package movegate prevents accidental cross-account MOVE / UID MOVE
// operations. It snoops SELECT/EXAMINE/CLOSE/UNSELECT to know the
// currently selected mailbox, then evaluates each MOVE / UID MOVE on
// the wire and reports whether the proxy should forward it or
// short-circuit it with a tagged NO.
//
// COPY is intentionally not gated — copying between accounts is
// considered a deliberate action.
//
// "Account" derivation: if the mailbox name starts with one of the
// configured shared prefixes (e.g. "Shared Folders/"), the account is
// the prefix plus the next path segment (e.g. "Shared Folders/foo@bar").
// Otherwise the account is the empty string, representing the user's
// own personal namespace. Two mailboxes belong to different accounts
// iff their derived account strings differ.
package movegate

import (
	"bytes"
	"strings"
)

// Decision is what the Tracker returns for a client line. When Block is
// true the session must NOT forward the line upstream and must instead
// write a tagged NO response to the client using Tag and Reason.
type Decision struct {
	Block  bool
	Tag    string
	Reason string
}

// Tracker is a stateful, NOT goroutine-safe state machine; the session
// owns one per connection and serialises calls.
type Tracker struct {
	// SharedPrefixes lists the path prefixes (each ending in "/") that
	// mark the shared-folder namespace. Identical to rules.SharedPrefixes.
	SharedPrefixes []string

	selected string // currently selected mailbox, or "" when none

	// pending* describe an in-flight SELECT/EXAMINE/CLOSE/UNSELECT.
	pendingTag        string
	pendingMailbox    string // for SELECT/EXAMINE
	pendingDeselect   bool   // for CLOSE/UNSELECT or any failed SELECT/EXAMINE
}

// HandleClientLine inspects a client→server line and returns a Decision.
// Lines other than SELECT/EXAMINE/CLOSE/UNSELECT/MOVE/UID MOVE are
// ignored. Decision.Block is true only for cross-account MOVE / UID MOVE.
func (t *Tracker) HandleClientLine(line []byte) Decision {
	tag, cmd, rest, ok := splitTagCommand(line)
	if !ok {
		return Decision{}
	}
	upper := strings.ToUpper(cmd)

	switch upper {
	case "SELECT", "EXAMINE":
		mailbox := readMailboxArg(rest)
		t.pendingTag = tag
		t.pendingMailbox = mailbox
		t.pendingDeselect = false
		return Decision{}
	case "CLOSE", "UNSELECT":
		t.pendingTag = tag
		t.pendingMailbox = ""
		t.pendingDeselect = true
		return Decision{}
	case "MOVE":
		return t.evalMove(tag, rest)
	case "UID":
		// UID MOVE / UID COPY: the second word is the actual command.
		sub, sub2, ok := splitFirstWord(rest)
		if !ok || strings.ToUpper(sub) != "MOVE" {
			return Decision{}
		}
		return t.evalMove(tag, sub2)
	}
	return Decision{}
}

// HandleServerLine inspects a server→client line; updates selected state
// when a pending SELECT/EXAMINE/CLOSE/UNSELECT is tagged-OK or NO/BAD.
// Returns no Decision (server lines are never blocked here).
func (t *Tracker) HandleServerLine(line []byte) {
	if len(line) == 0 || line[0] == '*' || line[0] == '+' {
		return
	}
	tag, status, _, ok := splitTagCommand(line)
	if !ok || t.pendingTag == "" || tag != t.pendingTag {
		return
	}
	defer t.resetPending()
	switch strings.ToUpper(status) {
	case "OK":
		if t.pendingDeselect {
			t.selected = ""
		} else {
			t.selected = t.pendingMailbox
		}
	default:
		// NO/BAD on SELECT/EXAMINE: per RFC, no mailbox is selected.
		// On CLOSE/UNSELECT failures, leave state alone.
		if !t.pendingDeselect {
			t.selected = ""
		}
	}
}

func (t *Tracker) resetPending() {
	t.pendingTag = ""
	t.pendingMailbox = ""
	t.pendingDeselect = false
}

// evalMove parses a MOVE argument tail "<seq> <mailbox>" and decides
// whether to block based on selected vs target accounts.
func (t *Tracker) evalMove(tag string, args []byte) Decision {
	if t.selected == "" {
		// No selected mailbox: forward and let the upstream reject.
		return Decision{}
	}
	// Skip the sequence-set (first whitespace-delimited token).
	_, after, ok := splitFirstWord(args)
	if !ok {
		return Decision{}
	}
	target := readMailboxArg(after)
	if target == "" {
		return Decision{}
	}
	if t.accountOf(t.selected) == t.accountOf(target) {
		return Decision{}
	}
	return Decision{
		Block:  true,
		Tag:    tag,
		Reason: "[CANNOT] cross-account move not permitted.",
	}
}

// accountOf returns the "account" that mailbox belongs to: "" for the
// user's own personal namespace, or "<sharedPrefix><first segment>" for
// any mailbox under a shared prefix.
func (t *Tracker) accountOf(mailbox string) string {
	for _, p := range t.SharedPrefixes {
		if !strings.HasPrefix(mailbox, p) {
			continue
		}
		rest := mailbox[len(p):]
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			return p + rest[:i]
		}
		// mailbox IS the shared root itself (e.g. "Shared Folders/foo@bar")
		return p + rest
	}
	return ""
}

// --- IMAP line parsing -----------------------------------------------------

// splitTagCommand parses "<tag> <CMD> <rest>". rest preserves the trailing
// CRLF (if any). Empty rest is allowed (e.g. tagged "t1 NOOP\r\n").
func splitTagCommand(line []byte) (tag, cmd string, rest []byte, ok bool) {
	sp1 := bytes.IndexByte(line, ' ')
	if sp1 <= 0 {
		return "", "", nil, false
	}
	tag = string(line[:sp1])
	after := line[sp1+1:]
	sp2 := bytes.IndexByte(after, ' ')
	if sp2 < 0 {
		cmd = string(trimCRLF(after))
		return tag, cmd, nil, true
	}
	cmd = string(after[:sp2])
	rest = after[sp2+1:]
	return tag, cmd, rest, true
}

// splitFirstWord splits "<word> <rest>". The first word ends at the first
// space; rest is everything after (may be empty or just CRLF).
func splitFirstWord(b []byte) (word string, rest []byte, ok bool) {
	b = trimLeadingSpace(b)
	if len(b) == 0 {
		return "", nil, false
	}
	sp := bytes.IndexByte(b, ' ')
	if sp < 0 {
		return string(trimCRLF(b)), nil, true
	}
	return string(b[:sp]), b[sp+1:], true
}

// readMailboxArg parses an IMAP mailbox argument (atom, quoted-string, or
// {N}\r\n literal) starting at the beginning of b (after optional leading
// whitespace). Returns the unescaped UTF-8 (or raw bytes for literals)
// mailbox name, or "" if it cannot parse one.
func readMailboxArg(b []byte) string {
	b = trimLeadingSpace(b)
	if len(b) == 0 {
		return ""
	}
	switch b[0] {
	case '"':
		// quoted-string with backslash escapes
		var out []byte
		i := 1
		for i < len(b) {
			c := b[i]
			if c == '\\' && i+1 < len(b) {
				out = append(out, b[i+1])
				i += 2
				continue
			}
			if c == '"' {
				return string(out)
			}
			out = append(out, c)
			i++
		}
		return ""
	case '{':
		// literal: {N}\r\n followed by N bytes (the framer has already
		// inlined the literal payload into the same logical line).
		end := bytes.IndexByte(b, '}')
		if end < 0 {
			return ""
		}
		ndigits := b[1:end]
		if len(ndigits) > 0 && ndigits[len(ndigits)-1] == '+' {
			ndigits = ndigits[:len(ndigits)-1]
		}
		n := 0
		for _, c := range ndigits {
			if c < '0' || c > '9' {
				return ""
			}
			n = n*10 + int(c-'0')
		}
		// after '}' we expect \r\n then N bytes of payload
		i := end + 1
		if i+1 < len(b) && b[i] == '\r' && b[i+1] == '\n' {
			i += 2
		} else if i < len(b) && b[i] == '\n' {
			i++
		}
		if i+n > len(b) {
			return ""
		}
		return string(b[i : i+n])
	default:
		// atom: read until whitespace / CRLF
		end := 0
		for end < len(b) && b[end] != ' ' && b[end] != '\t' && b[end] != '\r' && b[end] != '\n' {
			end++
		}
		if end == 0 {
			return ""
		}
		return string(b[:end])
	}
}

func trimLeadingSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	return b
}

func trimCRLF(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\r' || b[len(b)-1] == '\n') {
		b = b[:len(b)-1]
	}
	return b
}
