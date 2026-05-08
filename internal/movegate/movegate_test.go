// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

package movegate

import (
	"testing"
)

func newTracker() *Tracker {
	return &Tracker{SharedPrefixes: []string{"Shared Folders/", "Other Users/"}}
}

// drives both directions through the tracker for a SELECT-then-MOVE sequence
// and returns the decision for the MOVE line.
func selectThenMove(t *testing.T, tr *Tracker, srcMailbox, moveLine string) Decision {
	t.Helper()
	tr.HandleClientLine([]byte("s1 SELECT \"" + srcMailbox + "\"\r\n"))
	tr.HandleServerLine([]byte("* 0 EXISTS\r\n"))
	tr.HandleServerLine([]byte("s1 OK [READ-WRITE] SELECT completed\r\n"))
	return tr.HandleClientLine([]byte(moveLine))
}

func TestForwardsWhenSrcAndDstSameSharedAccount(t *testing.T) {
	tr := newTracker()
	d := selectThenMove(t, tr,
		"Shared Folders/foo@bar.com/INBOX",
		"m1 MOVE 1:5 \"Shared Folders/foo@bar.com/Archive\"\r\n")
	if d.Block {
		t.Fatalf("same-account move must forward; got Block=%q", d.Reason)
	}
}

func TestBlocksCrossSharedAccountMove(t *testing.T) {
	tr := newTracker()
	d := selectThenMove(t, tr,
		"Shared Folders/foo@bar.com/INBOX",
		"m1 MOVE 1:5 \"Shared Folders/baz@bar.com/INBOX\"\r\n")
	if !d.Block {
		t.Fatalf("cross-shared-account move must block")
	}
	if d.Tag != "m1" {
		t.Fatalf("tag=%q want m1", d.Tag)
	}
}

func TestBlocksCrossSharedAccountUIDMove(t *testing.T) {
	tr := newTracker()
	d := selectThenMove(t, tr,
		"Shared Folders/foo@bar.com/INBOX",
		"m2 UID MOVE 1:5 \"Shared Folders/baz@bar.com/INBOX\"\r\n")
	if !d.Block {
		t.Fatalf("cross-shared-account UID MOVE must block")
	}
	if d.Tag != "m2" {
		t.Fatalf("tag=%q want m2", d.Tag)
	}
}

func TestBlocksMoveFromOwnToShared(t *testing.T) {
	tr := newTracker()
	d := selectThenMove(t, tr,
		"INBOX",
		"m3 MOVE 1 \"Shared Folders/foo@bar.com/INBOX\"\r\n")
	if !d.Block {
		t.Fatalf("own→shared MOVE must block")
	}
}

func TestBlocksMoveFromSharedToOwn(t *testing.T) {
	tr := newTracker()
	d := selectThenMove(t, tr,
		"Shared Folders/foo@bar.com/INBOX",
		"m4 MOVE 1 \"INBOX\"\r\n")
	if !d.Block {
		t.Fatalf("shared→own MOVE must block")
	}
}

func TestForwardsOwnToOwn(t *testing.T) {
	tr := newTracker()
	d := selectThenMove(t, tr,
		"INBOX",
		"m5 MOVE 1 \"Sent Items\"\r\n")
	if d.Block {
		t.Fatalf("own→own MOVE must forward; got Block=%q", d.Reason)
	}
}

func TestCopyAlwaysForwards(t *testing.T) {
	tr := newTracker()
	for _, line := range []string{
		"c1 COPY 1 \"Shared Folders/baz@bar.com/INBOX\"\r\n",
		"c2 UID COPY 1 \"INBOX\"\r\n",
	} {
		d := selectThenMove(t, tr, "Shared Folders/foo@bar.com/INBOX", line)
		if d.Block {
			t.Fatalf("COPY must always forward; got Block=%q for %q", d.Reason, line)
		}
	}
}

func TestUnknownMailboxArgForwards(t *testing.T) {
	// MOVE before SELECT (illegal); we can't make a decision, so forward
	// and let upstream return BAD/NO.
	tr := newTracker()
	d := tr.HandleClientLine([]byte("m1 MOVE 1 \"Shared Folders/baz@bar.com/INBOX\"\r\n"))
	if d.Block {
		t.Fatalf("no selected mailbox: must forward, not block")
	}
}

func TestSelectFailureClearsSelected(t *testing.T) {
	tr := newTracker()
	tr.HandleClientLine([]byte("s1 SELECT \"INBOX\"\r\n"))
	tr.HandleServerLine([]byte("s1 OK SELECT completed\r\n"))
	tr.HandleClientLine([]byte("s2 SELECT \"NoSuch\"\r\n"))
	tr.HandleServerLine([]byte("s2 NO mailbox does not exist\r\n"))
	// Per RFC, after a failed SELECT no mailbox is selected.
	d := tr.HandleClientLine([]byte("m1 MOVE 1 \"Shared Folders/x@y.com/INBOX\"\r\n"))
	if d.Block {
		t.Fatalf("after failed SELECT no selected mailbox; must forward")
	}
}

func TestCloseAndUnselectClearSelected(t *testing.T) {
	for _, cmd := range []string{"CLOSE", "UNSELECT"} {
		tr := newTracker()
		tr.HandleClientLine([]byte("s1 SELECT \"INBOX\"\r\n"))
		tr.HandleServerLine([]byte("s1 OK SELECT completed\r\n"))
		tr.HandleClientLine([]byte("c1 " + cmd + "\r\n"))
		tr.HandleServerLine([]byte("c1 OK " + cmd + " completed\r\n"))
		d := tr.HandleClientLine([]byte("m1 MOVE 1 \"Shared Folders/x@y.com/INBOX\"\r\n"))
		if d.Block {
			t.Fatalf("after %s no selected mailbox; must forward", cmd)
		}
	}
}

func TestMailboxArgLiteralForm(t *testing.T) {
	// IMAP allows {N}\r\n<N bytes> for mailbox arguments. The framer
	// returns one logical line including the literal payload.
	tr := newTracker()
	tr.HandleClientLine([]byte("s1 SELECT {32}\r\nShared Folders/foo@bar.com/INBOX\r\n"))
	tr.HandleServerLine([]byte("s1 OK SELECT completed\r\n"))
	d := tr.HandleClientLine([]byte("m1 MOVE 1 {37}\r\nShared Folders/baz@bar.com/INBOX/sub\r\n"))
	if !d.Block {
		t.Fatalf("literal-form cross-account MOVE must block")
	}
}

func TestMailboxArgAtomForm(t *testing.T) {
	// Atom-form mailbox (no quotes), e.g. INBOX or simple ASCII names.
	tr := newTracker()
	tr.HandleClientLine([]byte("s1 SELECT INBOX\r\n"))
	tr.HandleServerLine([]byte("s1 OK SELECT completed\r\n"))
	d := tr.HandleClientLine([]byte("m1 MOVE 1 SomeOther\r\n"))
	if d.Block {
		t.Fatalf("INBOX→SomeOther is own→own; must forward")
	}
}

func TestExamineAlsoTracksSelected(t *testing.T) {
	tr := newTracker()
	tr.HandleClientLine([]byte("s1 EXAMINE \"Shared Folders/foo@bar.com/INBOX\"\r\n"))
	tr.HandleServerLine([]byte("s1 OK EXAMINE completed\r\n"))
	d := tr.HandleClientLine([]byte("m1 MOVE 1 \"Shared Folders/baz@bar.com/INBOX\"\r\n"))
	if !d.Block {
		t.Fatalf("after EXAMINE the selected mailbox must be tracked too")
	}
}

func TestUnrelatedCommandsDoNotBlock(t *testing.T) {
	tr := newTracker()
	tr.HandleClientLine([]byte("s1 SELECT \"Shared Folders/foo@bar.com/INBOX\"\r\n"))
	tr.HandleServerLine([]byte("s1 OK SELECT completed\r\n"))
	for _, line := range []string{
		"f1 FETCH 1 (BODY[HEADER])\r\n",
		"st1 STORE 1 +FLAGS (\\Seen)\r\n",
		"l1 LIST \"\" \"*\"\r\n",
		"n1 NOOP\r\n",
		"a1 APPEND \"Shared Folders/baz@bar.com/INBOX\" {3}\r\nabc\r\n",
	} {
		d := tr.HandleClientLine([]byte(line))
		if d.Block {
			t.Fatalf("non-MOVE command must not block; got Block for %q", line)
		}
	}
}
