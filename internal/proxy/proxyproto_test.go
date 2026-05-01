// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
)

func TestProxyHeaderAddrsIPv4(t *testing.T) {
	src, dst, tp, err := proxyHeaderAddrs(
		&net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 42424},
		&net.TCPAddr{IP: net.ParseIP("192.0.2.5"), Port: 993},
	)
	if err != nil {
		t.Fatal(err)
	}
	if tp != proxyproto.TCPv4 {
		t.Fatalf("transport=%v", tp)
	}
	if src.(*net.TCPAddr).IP.To4() == nil || dst.(*net.TCPAddr).IP.To4() == nil {
		t.Fatal("expected IPv4 addresses")
	}
}

func TestProxyHeaderAddrsIPv6(t *testing.T) {
	src, dst, tp, err := proxyHeaderAddrs(
		&net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 42424},
		&net.TCPAddr{IP: net.ParseIP("2001:db8::20"), Port: 993},
	)
	if err != nil {
		t.Fatal(err)
	}
	if tp != proxyproto.TCPv6 {
		t.Fatalf("transport=%v", tp)
	}
	if src.(*net.TCPAddr).IP.To4() != nil || dst.(*net.TCPAddr).IP.To4() != nil {
		t.Fatal("expected IPv6 addresses")
	}
}

func TestProxyHeaderAddrsMappedIPv4(t *testing.T) {
	src, dst, tp, err := proxyHeaderAddrs(
		&net.TCPAddr{IP: net.ParseIP("::ffff:203.0.113.10"), Port: 42424},
		&net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.5"), Port: 993},
	)
	if err != nil {
		t.Fatal(err)
	}
	if tp != proxyproto.TCPv4 {
		t.Fatalf("transport=%v", tp)
	}
	if src.(*net.TCPAddr).IP.To4() == nil || dst.(*net.TCPAddr).IP.To4() == nil {
		t.Fatal("expected normalized IPv4 addresses")
	}
}

func TestProxyHeaderAddrsFamilyMismatch(t *testing.T) {
	_, _, _, err := proxyHeaderAddrs(
		&net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 42424},
		&net.TCPAddr{IP: net.ParseIP("2001:db8::20"), Port: 993},
	)
	if err == nil {
		t.Fatal("expected family mismatch error")
	}
}

// realClientConn returns a connected net.Conn pair using a TCP loopback
// listener so RemoteAddr/LocalAddr are real *net.TCPAddr values.
func realClientConn(t *testing.T) (clientSide, proxySide net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type result struct {
		c   net.Conn
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		resCh <- result{c, err}
	}()
	cs, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-resCh
	if r.err != nil {
		t.Fatal(r.err)
	}
	return cs, r.c
}

func TestProxyProtocolHeaderWrittenFirst(t *testing.T) {
	addr, accepted := fakeUpstream(t)

	d := &TCPDialer{Addr: addr, ProxyProtocol: true}

	_, proxyClient := realClientConn(t)
	defer proxyClient.Close()

	upConn, err := d.Dial(proxyClient)
	if err != nil {
		t.Fatal(err)
	}
	defer upConn.Close()

	// Have the dialer push some IMAP-ish bytes; PROXY header must come first.
	go func() { _, _ = upConn.Write([]byte("a1 NOOP\r\n")) }()

	server := <-accepted
	defer server.Close()

	// First read on the server side must parse a PROXY v2 header.
	br := bufio.NewReader(server)
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	hdr, err := proxyproto.Read(br)
	if err != nil {
		t.Fatalf("PROXY parse: %v", err)
	}
	if hdr.Version != 2 || hdr.Command != proxyproto.PROXY {
		t.Errorf("bad header: version=%d cmd=%v", hdr.Version, hdr.Command)
	}
	if hdr.SourceAddr.String() != proxyClient.RemoteAddr().String() {
		t.Errorf("src=%v want %v", hdr.SourceAddr, proxyClient.RemoteAddr())
	}
	if hdr.DestinationAddr.String() != proxyClient.LocalAddr().String() {
		t.Errorf("dst=%v want %v", hdr.DestinationAddr, proxyClient.LocalAddr())
	}

	// Subsequent bytes are the verbatim payload.
	got, _ := br.ReadString('\n')
	if got != "a1 NOOP\r\n" {
		t.Errorf("payload after PROXY: %q", got)
	}
}

func TestProxyProtocolNotSentWhenDisabled(t *testing.T) {
	addr, accepted := fakeUpstream(t)
	d := &TCPDialer{Addr: addr, ProxyProtocol: false}
	_, proxyClient := realClientConn(t)
	defer proxyClient.Close()

	upConn, err := d.Dial(proxyClient)
	if err != nil {
		t.Fatal(err)
	}
	defer upConn.Close()
	go func() { _, _ = upConn.Write([]byte("a1 NOOP\r\n")) }()

	server := <-accepted
	defer server.Close()
	br := bufio.NewReader(server)
	got, _ := br.ReadString('\n')
	if got != "a1 NOOP\r\n" {
		t.Errorf("expected verbatim payload, got %q", got)
	}
}

func TestProxyProtocolIPv6(t *testing.T) {
	// Bind upstream on IPv6 loopback if available; skip otherwise.
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("ipv6 not available: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	// Real IPv6 client conn.
	cln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("ipv6 not available: %v", err)
	}
	defer cln.Close()
	resCh := make(chan net.Conn, 1)
	go func() {
		c, err := cln.Accept()
		if err != nil {
			return
		}
		resCh <- c
	}()
	clientSide, err := net.Dial("tcp", cln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientSide.Close()
	proxyClient := <-resCh
	defer proxyClient.Close()

	d := &TCPDialer{Addr: ln.Addr().String(), ProxyProtocol: true}
	upConn, err := d.Dial(proxyClient)
	if err != nil {
		t.Fatal(err)
	}
	defer upConn.Close()

	server := <-accepted
	defer server.Close()
	br := bufio.NewReader(server)
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	hdr, err := proxyproto.Read(br)
	if err != nil {
		t.Fatalf("PROXY parse: %v", err)
	}
	if hdr.TransportProtocol != proxyproto.TCPv6 {
		t.Errorf("expected TCPv6, got %v", hdr.TransportProtocol)
	}
}
