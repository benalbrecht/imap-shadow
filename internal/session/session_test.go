// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/benalbrecht/imap-shadow/internal/capability"
	"github.com/benalbrecht/imap-shadow/internal/rules"
)

// pair returns two net.Pipe ends. The "left" is what the test writes/reads,
// the "right" is what the session sees.
func pair() (net.Conn, net.Conn) {
	return net.Pipe()
}

// runSession starts a Session in a goroutine and returns a "client" Conn
// (what the test pretends to be) and a "server" Conn (likewise), plus a
// done channel that closes when the session exits.
func runSession(t *testing.T, r *rules.Rules, rw *capability.Rewriter) (clientSide, serverSide net.Conn, done chan struct{}) {
	t.Helper()
	clientSide, proxyClient := pair()
	proxyServer, serverSide := pair()
	done = make(chan struct{})
	s := &Session{
		Client:   proxyClient,
		Server:   proxyServer,
		Rules:    r,
		Rewriter: rw,
	}
	go func() {
		_ = s.Run()
		close(done)
	}()
	t.Cleanup(func() {
		clientSide.Close()
		serverSide.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("session did not exit")
		}
	})
	return clientSide, serverSide, done
}

// readLine reads up to "\r\n" from r.
func readLine(t *testing.T, r io.Reader) string {
	t.Helper()
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	return line
}

// readWithDeadline returns a function that reads one line with a deadline.
func newLineReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

func TestPassthroughBothDirections(t *testing.T) {
	r := &rules.Rules{}
	rw := capability.New(nil)
	client, server, _ := runSession(t, r, rw)

	// server pushes banner
	go func() {
		_, _ = server.Write([]byte("* OK [CAPABILITY IMAP4rev1] hi\r\n"))
	}()

	cr := newLineReader(client)
	got, _ := cr.ReadString('\n')
	if got != "* OK [CAPABILITY IMAP4rev1] hi\r\n" {
		t.Errorf("banner: %q", got)
	}

	// client sends NOOP
	go func() {
		_, _ = client.Write([]byte("a1 NOOP\r\n"))
	}()
	sr := newLineReader(server)
	got, _ = sr.ReadString('\n')
	if got != "a1 NOOP\r\n" {
		t.Errorf("NOOP: %q", got)
	}
}

func TestCapabilityRewriteOnBanner(t *testing.T) {
	r := &rules.Rules{}
	rw := capability.New([]string{"COMPRESS=DEFLATE"})
	client, server, _ := runSession(t, r, rw)

	go func() {
		_, _ = server.Write([]byte("* OK [CAPABILITY IMAP4rev1 COMPRESS=DEFLATE IDLE] hi\r\n"))
	}()
	cr := newLineReader(client)
	got, _ := cr.ReadString('\n')
	want := "* OK [CAPABILITY IMAP4rev1 IDLE] hi\r\n"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestFilterAppliesAfterAuth(t *testing.T) {
	r := &rules.Rules{
		Users: []rules.UserRule{{User: "*", Hide: []string{"Trash"}}},
	}
	rw := capability.New(nil)
	client, server, _ := runSession(t, r, rw)

	cr := newLineReader(client)
	sr := newLineReader(server)

	// client logs in
	go func() {
		_, _ = client.Write([]byte(`a1 LOGIN "alice" "pass"` + "\r\n"))
	}()
	loginLine, _ := sr.ReadString('\n')
	if !strings.HasPrefix(loginLine, "a1 LOGIN") {
		t.Fatalf("server didn't see LOGIN: %q", loginLine)
	}
	go func() {
		_, _ = server.Write([]byte("a1 OK Logged in\r\n"))
	}()
	okLine, _ := cr.ReadString('\n')
	if !strings.HasPrefix(okLine, "a1 OK") {
		t.Fatalf("client didn't see OK: %q", okLine)
	}

	// client lists
	go func() {
		_, _ = client.Write([]byte("a2 LIST \"\" \"*\"\r\n"))
	}()
	listLine, _ := sr.ReadString('\n')
	if !strings.HasPrefix(listLine, "a2 LIST") {
		t.Fatalf("server didn't see LIST: %q", listLine)
	}

	// server returns three folders, "Trash" should be filtered out
	go func() {
		_, _ = server.Write([]byte(`* LIST () "/" "INBOX"` + "\r\n"))
		_, _ = server.Write([]byte(`* LIST () "/" "Trash"` + "\r\n"))
		_, _ = server.Write([]byte(`* LIST () "/" "Sent"` + "\r\n"))
		_, _ = server.Write([]byte("a2 OK LIST done\r\n"))
	}()

	var got []string
	for {
		line, err := cr.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, line)
		if strings.HasPrefix(line, "a2 OK") {
			break
		}
	}
	want := []string{
		`* LIST () "/" "INBOX"` + "\r\n",
		`* LIST () "/" "Sent"` + "\r\n",
		"a2 OK LIST done\r\n",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d:\ngot: %q\nwant: %q", len(got), len(want), got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("line %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestFilterDoesNotApplyBeforeAuth(t *testing.T) {
	// Pre-auth, even if we matched a "*" rule, we don't have a user yet.
	// In that state, no filtering should happen.
	r := &rules.Rules{
		Users: []rules.UserRule{{User: "*", Hide: []string{"Trash"}}},
	}
	rw := capability.New(nil)
	client, server, _ := runSession(t, r, rw)

	cr := newLineReader(client)

	// server pushes a stray LIST line before auth (unrealistic but tests
	// the behaviour: pre-auth means no matcher).
	go func() {
		_, _ = server.Write([]byte(`* LIST () "/" "Trash"` + "\r\n"))
	}()
	got, _ := cr.ReadString('\n')
	want := `* LIST () "/" "Trash"` + "\r\n"
	if got != want {
		t.Errorf("pre-auth filter applied: got %q", got)
	}
}

func TestAuthSnoopExtractsUserViaPLAIN(t *testing.T) {
	r := &rules.Rules{
		Users: []rules.UserRule{{User: "alice@example.com", Hide: []string{"Trash"}}},
	}
	rw := capability.New(nil)
	client, server, _ := runSession(t, r, rw)

	cr := newLineReader(client)
	sr := newLineReader(server)

	payload := base64.StdEncoding.EncodeToString([]byte("\x00alice@example.com\x00secret"))
	go func() { _, _ = client.Write([]byte("a1 AUTHENTICATE PLAIN " + payload + "\r\n")) }()
	if _, err := sr.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = server.Write([]byte("a1 OK Authenticated\r\n")) }()
	if _, err := cr.ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	// Now LIST: Trash should be filtered (only because matcher is now built
	// for alice, not the wildcard).
	go func() { _, _ = client.Write([]byte(`a2 LIST "" "*"` + "\r\n")) }()
	if _, err := sr.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = server.Write([]byte(`* LIST () "/" "Trash"` + "\r\n"))
		_, _ = server.Write([]byte("a2 OK done\r\n"))
	}()
	got, _ := cr.ReadString('\n')
	if !strings.HasPrefix(got, "a2 OK") {
		t.Errorf("Trash should have been hidden; first line: %q", got)
	}
}

func TestBlockCrossAccountMoveSendsNOAndDoesNotForward(t *testing.T) {
	r := &rules.Rules{SharedPrefixes: []string{"Shared Folders/"}}
	rw := capability.New(nil)
	clientSide, proxyClient := pair()
	proxyServer, serverSide := pair()
	done := make(chan struct{})
	s := &Session{
		Client:                 proxyClient,
		Server:                 proxyServer,
		Rules:                  r,
		Rewriter:               rw,
		BlockCrossAccountMoves: true,
		SharedPrefixes:         r.SharedPrefixes,
	}
	go func() { _ = s.Run(); close(done) }()
	t.Cleanup(func() {
		clientSide.Close()
		serverSide.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("session did not exit")
		}
	})
	cr := newLineReader(clientSide)
	sr := newLineReader(serverSide)

	// 1. SELECT a shared mailbox; server confirms.
	go func() {
		_, _ = clientSide.Write([]byte("s1 SELECT \"Shared Folders/foo@bar.com/INBOX\"\r\n"))
	}()
	if _, err := sr.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = serverSide.Write([]byte("s1 OK SELECT done\r\n")) }()
	if _, err := cr.ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	// 2. MOVE to a different shared account: must NOT reach the server,
	//    client must receive a tagged NO.
	go func() {
		_, _ = clientSide.Write([]byte("m1 MOVE 1 \"Shared Folders/baz@bar.com/INBOX\"\r\n"))
	}()
	got, err := cr.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "m1 NO ") {
		t.Fatalf("client got %q; expected tagged NO for m1", got)
	}

	// 3. Follow-up NOOP must reach the server (proves MOVE was dropped,
	//    not just stuck in the pipeline).
	go func() { _, _ = clientSide.Write([]byte("n1 NOOP\r\n")) }()
	got, err = sr.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "n1 NOOP") {
		t.Fatalf("server saw %q; expected n1 NOOP after blocked MOVE", got)
	}
}

func TestBlockCrossAccountMoveDisabledByDefault(t *testing.T) {
	// With BlockCrossAccountMoves false (the default), a cross-account
	// MOVE must be forwarded untouched.
	r := &rules.Rules{SharedPrefixes: []string{"Shared Folders/"}}
	rw := capability.New(nil)
	client, server, _ := runSession(t, r, rw)
	cr := newLineReader(client)
	sr := newLineReader(server)

	go func() {
		_, _ = client.Write([]byte("s1 SELECT \"Shared Folders/foo@bar.com/INBOX\"\r\n"))
	}()
	if _, err := sr.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = server.Write([]byte("s1 OK\r\n")) }()
	if _, err := cr.ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	go func() {
		_, _ = client.Write([]byte("m1 MOVE 1 \"Shared Folders/baz@bar.com/INBOX\"\r\n"))
	}()
	got, err := sr.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "m1 MOVE") {
		t.Fatalf("server got %q; MOVE must pass through when gate is disabled", got)
	}
}

func TestSessionExitsOnClientClose(t *testing.T) {
	r := &rules.Rules{}
	rw := capability.New(nil)
	client, _, done := runSession(t, r, rw)
	client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("session did not exit on client close")
	}
}

func TestSessionExitsOnServerClose(t *testing.T) {
	r := &rules.Rules{}
	rw := capability.New(nil)
	_, server, done := runSession(t, r, rw)
	server.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("session did not exit on server close")
	}
}
