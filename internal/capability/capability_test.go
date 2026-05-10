// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

package capability

import "testing"

func TestRewriteUntaggedCapability(t *testing.T) {
	r := New([]string{"COMPRESS=DEFLATE", "REFERRAL", "AUTH=GSSAPI"})
	in := []byte("* CAPABILITY IMAP4rev1 IDLE COMPRESS=DEFLATE AUTH=PLAIN AUTH=GSSAPI REFERRAL\r\n")
	want := []byte("* CAPABILITY IMAP4rev1 IDLE AUTH=PLAIN\r\n")
	got := r.Rewrite(in)
	if string(got) != string(want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestRewriteOKCapabilityResponseCode(t *testing.T) {
	r := New([]string{"COMPRESS=DEFLATE"})
	in := []byte("* OK [CAPABILITY IMAP4rev1 IDLE COMPRESS=DEFLATE] Logged in\r\n")
	want := []byte("* OK [CAPABILITY IMAP4rev1 IDLE] Logged in\r\n")
	got := r.Rewrite(in)
	if string(got) != string(want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestRewriteCaseInsensitive(t *testing.T) {
	r := New([]string{"compress=deflate"})
	in := []byte("* CAPABILITY IMAP4rev1 COMPRESS=DEFLATE\r\n")
	want := []byte("* CAPABILITY IMAP4rev1\r\n")
	got := r.Rewrite(in)
	if string(got) != string(want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestRewritePassthroughForUnrelatedLines(t *testing.T) {
	r := New([]string{"COMPRESS=DEFLATE"})
	for _, line := range []string{
		"a1 OK LOGIN completed\r\n",
		"* 1 EXISTS\r\n",
		"+ go ahead\r\n",
		"",
	} {
		in := []byte(line)
		got := r.Rewrite(in)
		if string(got) != line {
			t.Errorf("%q: rewriter altered unrelated line: got %q", line, got)
		}
	}
}

func TestRewriteEmptyStripList(t *testing.T) {
	r := New(nil)
	in := []byte("* CAPABILITY IMAP4rev1 COMPRESS=DEFLATE\r\n")
	got := r.Rewrite(in)
	if string(got) != string(in) {
		t.Errorf("nil strip list must be a passthrough")
	}
}

func TestRewritePreservesCRLF(t *testing.T) {
	r := New([]string{"X"})
	in := []byte("* CAPABILITY A B X C\r\n")
	got := r.Rewrite(in)
	if len(got) < 2 || got[len(got)-2] != '\r' || got[len(got)-1] != '\n' {
		t.Errorf("CRLF lost: %q", got)
	}
}

func TestRewriteCollapsesWhitespace(t *testing.T) {
	// after stripping, we must not leave a double space.
	r := New([]string{"X"})
	in := []byte("* CAPABILITY A X B\r\n")
	want := []byte("* CAPABILITY A B\r\n")
	got := r.Rewrite(in)
	if string(got) != string(want) {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestRewriteStripsTrailingItem(t *testing.T) {
	r := New([]string{"X"})
	in := []byte("* CAPABILITY A B X\r\n")
	want := []byte("* CAPABILITY A B\r\n")
	got := r.Rewrite(in)
	if string(got) != string(want) {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestRewriteStripsLeadingItem(t *testing.T) {
	// X right after "CAPABILITY"
	r := New([]string{"X"})
	in := []byte("* CAPABILITY X A B\r\n")
	want := []byte("* CAPABILITY A B\r\n")
	got := r.Rewrite(in)
	if string(got) != string(want) {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestRewriteDoesNotStripSubstringMatch(t *testing.T) {
	// "AUTH=PLAIN" must not match strip="PLAIN".
	r := New([]string{"PLAIN"})
	in := []byte("* CAPABILITY AUTH=PLAIN PLAIN_NOPE PLAIN\r\n")
	want := []byte("* CAPABILITY AUTH=PLAIN PLAIN_NOPE\r\n")
	got := r.Rewrite(in)
	if string(got) != string(want) {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestRewriteRemovesAllUntaggedCapabilitiesCleanly(t *testing.T) {
	r := New([]string{"A", "B"})
	in := []byte("* CAPABILITY A B\r\n")
	want := []byte("* CAPABILITY\r\n")
	got := r.Rewrite(in)
	if string(got) != string(want) {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestRewriteRemovesAllBracketCapabilitiesCleanly(t *testing.T) {
	r := New([]string{"A", "B"})
	in := []byte("* OK [CAPABILITY A B] ready\r\n")
	want := []byte("* OK [CAPABILITY] ready\r\n")
	got := r.Rewrite(in)
	if string(got) != string(want) {
		t.Errorf("got %q want %q", got, want)
	}
}
