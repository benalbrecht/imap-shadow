// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

package filter

import (
	"testing"

	"github.com/benalbrecht/imap-shadow/internal/rules"
)

func mkFilter(hide ...string) *Filter {
	r := &rules.Rules{
		Users: []rules.UserRule{{User: "*", Hide: hide}},
	}
	return New(r.For("alice"))
}

func TestPassthroughNonResponseLines(t *testing.T) {
	f := mkFilter("Trash")
	for _, line := range []string{
		"a1 OK NOOP completed\r\n",
		"+ go ahead\r\n",
		"* 1 EXISTS\r\n",
		"* OK [CAPABILITY IMAP4rev1] hi\r\n",
		"",
	} {
		if got := f.Process([]byte(line)); string(got) != line {
			t.Errorf("%q: got %q", line, got)
		}
	}
}

func TestListQuotedMailboxHidden(t *testing.T) {
	f := mkFilter("Trash")
	in := []byte(`* LIST (\HasNoChildren) "/" "Trash"` + "\r\n")
	if got := f.Process(in); got != nil {
		t.Errorf("expected drop, got %q", got)
	}
}

func TestListQuotedMailboxKept(t *testing.T) {
	f := mkFilter("Trash")
	in := []byte(`* LIST (\HasNoChildren) "/" "Inbox"` + "\r\n")
	if got := f.Process(in); string(got) != string(in) {
		t.Errorf("expected keep, got %q", got)
	}
}

func TestListLiteralMailboxHidden(t *testing.T) {
	f := mkFilter("Trash!")
	in := []byte("* LIST (\\HasNoChildren) \"/\" {6}\r\nTrash!\r\n")
	if got := f.Process(in); got != nil {
		t.Errorf("expected drop, got %q", got)
	}
}

func TestListAtomMailboxHidden(t *testing.T) {
	f := mkFilter("Trash")
	in := []byte("* LIST () \"/\" Trash\r\n")
	if got := f.Process(in); got != nil {
		t.Errorf("expected drop, got %q", got)
	}
}

func TestListNilDelimiter(t *testing.T) {
	f := mkFilter("Trash")
	in := []byte("* LIST () NIL \"Trash\"\r\n")
	if got := f.Process(in); got != nil {
		t.Errorf("expected drop with NIL delim, got %q", got)
	}
}

func TestLsubHidden(t *testing.T) {
	f := mkFilter("Trash")
	in := []byte("* LSUB () \"/\" \"Trash\"\r\n")
	if got := f.Process(in); got != nil {
		t.Errorf("expected drop, got %q", got)
	}
}

func TestStatusMailboxHidden(t *testing.T) {
	f := mkFilter("Trash")
	in := []byte(`* STATUS "Trash" (MESSAGES 5 RECENT 0)` + "\r\n")
	if got := f.Process(in); got != nil {
		t.Errorf("expected drop, got %q", got)
	}
}

func TestStatusMailboxKept(t *testing.T) {
	f := mkFilter("Trash")
	in := []byte(`* STATUS "INBOX" (MESSAGES 5 RECENT 0)` + "\r\n")
	if got := f.Process(in); string(got) != string(in) {
		t.Errorf("expected keep, got %q", got)
	}
}

func TestSubfolderCascadeHidden(t *testing.T) {
	f := mkFilter("Trash")
	in := []byte(`* LIST (\HasNoChildren) "/" "Trash/Old/2024"` + "\r\n")
	if got := f.Process(in); got != nil {
		t.Errorf("expected drop (cascade), got %q", got)
	}
}

func TestModifiedUTF7Decoded(t *testing.T) {
	// "Büro" is encoded on the wire as "B&APw-ro" in modified UTF-7.
	// Rules use plain UTF-8.
	f := mkFilter("Büro")
	in := []byte(`* LIST () "/" "B&APw-ro"` + "\r\n")
	if got := f.Process(in); got != nil {
		t.Errorf("expected drop after mUTF-7 decode, got %q", got)
	}
}

func TestINBOXNeverHiddenEvenIfRuled(t *testing.T) {
	// Belt-and-braces: the rules layer guarantees this, but the filter must
	// not bypass it.
	f := mkFilter("INBOX")
	in := []byte(`* LIST () "/" "INBOX"` + "\r\n")
	if string(f.Process(in)) != string(in) {
		t.Error("INBOX must always pass through")
	}
}

func TestCaseInsensitiveResponseKeyword(t *testing.T) {
	f := mkFilter("Trash")
	in := []byte(`* list () "/" "Trash"` + "\r\n")
	if got := f.Process(in); got != nil {
		t.Errorf("expected drop with lowercase 'list', got %q", got)
	}
}

func TestMalformedLinePassesThrough(t *testing.T) {
	// If the line looks like a LIST but we can't parse it, don't drop —
	// passthrough is the safer default.
	f := mkFilter("Trash")
	in := []byte("* LIST garbled\r\n")
	if got := f.Process(in); string(got) != string(in) {
		t.Errorf("expected passthrough on malformed line, got %q", got)
	}
}
