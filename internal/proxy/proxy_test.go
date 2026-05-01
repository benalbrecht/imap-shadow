// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/benalbrecht/imap-shadow/internal/capability"
	"github.com/benalbrecht/imap-shadow/internal/rules"
)

// fakeUpstream listens on a random local TCP port and echoes a banner +
// reflects the client. The first connection is captured and made available
// via accepted.
func fakeUpstream(t *testing.T) (addr string, accepted chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted = make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	return ln.Addr().String(), accepted
}

func TestHandleBridgesToUpstream(t *testing.T) {
	addr, accepted := fakeUpstream(t)
	p := &Proxy{
		Dialer:   &TCPDialer{Addr: addr},
		Rewriter: capability.New(nil),
	}
	p.SetRules(&rules.Rules{})
	clientSide, proxyClient := net.Pipe()
	defer clientSide.Close()
	go p.Handle(proxyClient)

	upstream := <-accepted
	defer upstream.Close()

	// upstream pushes banner; client should see it
	go func() { _, _ = upstream.Write([]byte("* OK banner\r\n")) }()
	cr := bufio.NewReader(clientSide)
	got, _ := cr.ReadString('\n')
	if got != "* OK banner\r\n" {
		t.Errorf("got %q", got)
	}

	// client sends NOOP; upstream should see it
	go func() { _, _ = clientSide.Write([]byte("a1 NOOP\r\n")) }()
	ur := bufio.NewReader(upstream)
	got, _ = ur.ReadString('\n')
	if got != "a1 NOOP\r\n" {
		t.Errorf("got %q", got)
	}
}

func TestServeAcceptsMultipleConns(t *testing.T) {
	addr, accepted := fakeUpstream(t)
	p := &Proxy{
		Dialer:   &TCPDialer{Addr: addr},
		Rewriter: capability.New(nil),
	}
	p.SetRules(&rules.Rules{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve(ln)
	defer ln.Close()

	// dial twice
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		// wait for upstream-side accept
		select {
		case u := <-accepted:
			defer u.Close()
		case <-time.After(time.Second):
			t.Fatal("upstream did not accept")
		}
	}
}

func TestHandleClosesUpstreamOnClientClose(t *testing.T) {
	addr, accepted := fakeUpstream(t)
	p := &Proxy{
		Dialer:   &TCPDialer{Addr: addr},
		Rewriter: capability.New(nil),
	}
	p.SetRules(&rules.Rules{})
	clientSide, proxyClient := net.Pipe()
	done := make(chan struct{})
	go func() { _ = p.Handle(proxyClient); close(done) }()

	upstream := <-accepted
	defer upstream.Close()

	clientSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Handle did not return")
	}
}

func TestHandleReportsDialError(t *testing.T) {
	p := &Proxy{
		// unreachable port that should refuse immediately
		Dialer:   &TCPDialer{Addr: "127.0.0.1:1"},
		Rewriter: capability.New(nil),
	}
	p.SetRules(&rules.Rules{})
	clientSide, proxyClient := net.Pipe()
	defer clientSide.Close()
	err := p.Handle(proxyClient)
	if err == nil || !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("expected dial error, got %v", err)
	}
}
