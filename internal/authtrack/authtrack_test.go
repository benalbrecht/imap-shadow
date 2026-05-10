// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

package authtrack

import (
	"encoding/base64"
	"testing"
)

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func TestLoginOK(t *testing.T) {
	tr := &Tracker{}
	tr.HandleClientLine([]byte(`t1 LOGIN "alice" "secret"` + "\r\n"))
	if tr.User() != "" {
		t.Fatal("user should not be committed before OK")
	}
	committed := tr.HandleServerLine([]byte("t1 OK Logged in\r\n"))
	if !committed || tr.User() != "alice" {
		t.Fatalf("expected commit, got user=%q committed=%v", tr.User(), committed)
	}
}

func TestLoginNO(t *testing.T) {
	tr := &Tracker{}
	tr.HandleClientLine([]byte(`t1 LOGIN "alice" "wrong"` + "\r\n"))
	committed := tr.HandleServerLine([]byte("t1 NO bad credentials\r\n"))
	if committed || tr.User() != "" {
		t.Errorf("must not commit on NO; user=%q", tr.User())
	}
	// retry succeeds
	tr.HandleClientLine([]byte(`t2 LOGIN "alice" "right"` + "\r\n"))
	tr.HandleServerLine([]byte("t2 OK Logged in\r\n"))
	if tr.User() != "alice" {
		t.Errorf("retry: user=%q", tr.User())
	}
}

func TestAuthenticatePlainSASLIR(t *testing.T) {
	tr := &Tracker{}
	payload := b64("\x00alice\x00secret")
	tr.HandleClientLine([]byte("t1 AUTHENTICATE PLAIN " + payload + "\r\n"))
	if tr.User() != "" {
		t.Error("not yet committed")
	}
	tr.HandleServerLine([]byte("t1 OK Authenticated\r\n"))
	if tr.User() != "alice" {
		t.Errorf("user=%q", tr.User())
	}
}

func TestAuthenticatePlainMultiLine(t *testing.T) {
	tr := &Tracker{}
	tr.HandleClientLine([]byte("t1 AUTHENTICATE PLAIN\r\n"))
	tr.HandleServerLine([]byte("+ \r\n"))
	payload := b64("\x00alice\x00secret")
	tr.HandleClientLine([]byte(payload + "\r\n"))
	tr.HandleServerLine([]byte("t1 OK Authenticated\r\n"))
	if tr.User() != "alice" {
		t.Errorf("user=%q", tr.User())
	}
}

func TestAuthenticatePlainEmptyInitialResponse(t *testing.T) {
	tr := &Tracker{}
	tr.HandleClientLine([]byte("t1 AUTHENTICATE PLAIN =\r\n"))
	tr.HandleServerLine([]byte("+ \r\n"))
	payload := b64("\x00alice\x00secret")
	tr.HandleClientLine([]byte(payload + "\r\n"))
	tr.HandleServerLine([]byte("t1 OK Authenticated\r\n"))
	if tr.User() != "alice" {
		t.Errorf("user=%q", tr.User())
	}
}

func TestAuthenticateXOAUTH2SASLIR(t *testing.T) {
	tr := &Tracker{}
	payload := b64("user=alice@example.com\x01auth=Bearer abc\x01\x01")
	tr.HandleClientLine([]byte("t1 AUTHENTICATE XOAUTH2 " + payload + "\r\n"))
	tr.HandleServerLine([]byte("t1 OK ok\r\n"))
	if tr.User() != "alice@example.com" {
		t.Errorf("user=%q", tr.User())
	}
}

func TestAuthenticateOAUTHBEARERMultiLine(t *testing.T) {
	tr := &Tracker{}
	tr.HandleClientLine([]byte("t1 AUTHENTICATE OAUTHBEARER\r\n"))
	tr.HandleServerLine([]byte("+ \r\n"))
	payload := b64("n,,\x01user=alice\x01auth=Bearer xyz\x01\x01")
	tr.HandleClientLine([]byte(payload + "\r\n"))
	tr.HandleServerLine([]byte("t1 OK ok\r\n"))
	if tr.User() != "alice" {
		t.Errorf("user=%q", tr.User())
	}
}

func TestAuthenticateOAUTHBEARERRoundcubeStyle(t *testing.T) {
	// Real Roundcube/Kolab OAUTHBEARER per RFC 7628: the authentication
	// identity is in the GS2 "a=" authzid; there is no "user=" field.
	tr := &Tracker{}
	tr.HandleClientLine([]byte("A0001 AUTHENTICATE OAUTHBEARER\r\n"))
	tr.HandleServerLine([]byte("+ \r\n"))
	payload := b64("n,a=alice@example.com,\x01host=mail.example.com\x01port=143\x01auth=Bearer xyz\x01\x01")
	tr.HandleClientLine([]byte(payload + "\r\n"))
	committed := tr.HandleServerLine([]byte("A0001 OK [CAPABILITY IMAP4rev2 IMAP4rev1] Authentication successful\r\n"))
	if !committed {
		t.Fatalf("expected committed=true on tagged OK")
	}
	if tr.User() != "alice@example.com" {
		t.Errorf("user=%q want %q", tr.User(), "alice@example.com")
	}
}

func TestAuthenticateOAUTHBEARERRoundcubeStyleSASLIR(t *testing.T) {
	// Roundcube actually sends SASL-IR (RFC 4959): the base64 payload
	// rides on the same line as AUTHENTICATE, no "+" continuation.
	tr := &Tracker{}
	payload := b64("n,a=alice@example.com,\x01host=mail.example.com\x01port=143\x01auth=Bearer xyz\x01\x01")
	tr.HandleClientLine([]byte("A0001 AUTHENTICATE OAUTHBEARER " + payload + "\r\n"))
	committed := tr.HandleServerLine([]byte("A0001 OK [CAPABILITY IMAP4rev2 IMAP4rev1] Authentication successful\r\n"))
	if !committed {
		t.Fatalf("expected committed=true on tagged OK")
	}
	if tr.User() != "alice@example.com" {
		t.Errorf("user=%q want %q", tr.User(), "alice@example.com")
	}
}

func TestAuthenticateClientCancellation(t *testing.T) {
	// During multi-line AUTHENTICATE the client may send "*" to cancel.
	// State must reset.
	tr := &Tracker{}
	tr.HandleClientLine([]byte("t1 AUTHENTICATE PLAIN\r\n"))
	tr.HandleServerLine([]byte("+ \r\n"))
	tr.HandleClientLine([]byte("*\r\n"))
	tr.HandleServerLine([]byte("t1 BAD cancelled\r\n"))
	if tr.User() != "" {
		t.Errorf("must not commit on cancellation")
	}
}

func TestUnsupportedMechIsHarmless(t *testing.T) {
	tr := &Tracker{}
	tr.HandleClientLine([]byte("t1 AUTHENTICATE GSSAPI\r\n"))
	tr.HandleServerLine([]byte("+ challenge\r\n"))
	tr.HandleClientLine([]byte("response\r\n"))
	tr.HandleServerLine([]byte("t1 OK ok\r\n"))
	if tr.User() != "" {
		t.Errorf("unsupported mech must not extract a user; got %q", tr.User())
	}
}

func TestUnrelatedClientLinesIgnored(t *testing.T) {
	tr := &Tracker{}
	tr.HandleClientLine([]byte("t1 NOOP\r\n"))
	tr.HandleServerLine([]byte("t1 OK\r\n"))
	tr.HandleClientLine([]byte("t2 LIST \"\" \"*\"\r\n"))
	tr.HandleServerLine([]byte("t2 OK\r\n"))
	if tr.User() != "" {
		t.Errorf("unrelated lines must not commit")
	}
}

func TestServerOKForUnrelatedTagDoesNotCommit(t *testing.T) {
	tr := &Tracker{}
	tr.HandleClientLine([]byte(`t1 LOGIN "alice" "secret"` + "\r\n"))
	// some other tag completes first (shouldn't happen for LOGIN, but be defensive)
	tr.HandleServerLine([]byte("t99 OK something\r\n"))
	if tr.User() != "" {
		t.Errorf("must not commit for unrelated tag")
	}
	tr.HandleServerLine([]byte("t1 OK Logged in\r\n"))
	if tr.User() != "alice" {
		t.Errorf("must commit on matching tag")
	}
}

func TestUserCaseInsensitiveAuthKeyword(t *testing.T) {
	tr := &Tracker{}
	tr.HandleClientLine([]byte(`t1 login "alice" "secret"` + "\r\n"))
	tr.HandleServerLine([]byte("t1 ok\r\n"))
	if tr.User() != "alice" {
		t.Errorf("case-insensitive keyword: user=%q", tr.User())
	}
}
