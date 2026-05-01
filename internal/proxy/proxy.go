// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package proxy is the connection accept loop and upstream dialer. It is
// the I/O layer that sits between the public TLS listener and the in-memory
// session bridge.
package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"

	"github.com/benalbrecht/imap-shadow/internal/capability"
	"github.com/benalbrecht/imap-shadow/internal/rules"
	"github.com/benalbrecht/imap-shadow/internal/session"
)

// Dialer abstracts how an upstream connection is obtained, so tests can
// substitute fakes. The client connection is supplied so the dialer can
// emit a PROXY-protocol header carrying the original peer addresses.
type Dialer interface {
	Dial(client net.Conn) (net.Conn, error)
}

// TCPDialer dials a TCP host, optionally wrapping the connection in TLS
// and optionally prefixing it with a PROXY v2 header.
type TCPDialer struct {
	Addr          string
	TLS           bool
	SNI           string
	SkipVerify    bool
	ProxyProtocol bool
}

// Dial connects to the upstream IMAP server. If ProxyProtocol is true, a
// PROXY v2 header carrying client.RemoteAddr → client.LocalAddr is
// written before any other bytes (and before the TLS handshake, if any).
func (d *TCPDialer) Dial(client net.Conn) (net.Conn, error) {
	c, err := net.Dial("tcp", d.Addr)
	if err != nil {
		return nil, err
	}
	if d.ProxyProtocol {
		if err := writeProxyHeader(c, client); err != nil {
			c.Close()
			return nil, err
		}
	}
	if !d.TLS {
		return c, nil
	}
	return tls.Client(c, &tls.Config{
		ServerName:         d.SNI,
		InsecureSkipVerify: d.SkipVerify, //nolint:gosec // opt-in via config
	}), nil
}

// writeProxyHeader emits a PROXY v2 header describing the client peer.
func writeProxyHeader(upstream net.Conn, client net.Conn) error {
	src, dst, tp, err := proxyHeaderAddrs(client.RemoteAddr(), client.LocalAddr())
	if err != nil {
		return err
	}
	hdr := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: tp,
		SourceAddr:        src,
		DestinationAddr:   dst,
	}
	_, err = hdr.WriteTo(upstream)
	return err
}

// proxyHeaderAddrs normalizes source/destination TCP addresses and returns
// the matching PROXY-protocol transport tag.
func proxyHeaderAddrs(srcRaw, dstRaw net.Addr) (net.Addr, net.Addr, proxyproto.AddressFamilyAndProtocol, error) {
	src, ok := srcRaw.(*net.TCPAddr)
	if !ok {
		return nil, nil, 0, fmt.Errorf("proxy proto source is not TCP: %T", srcRaw)
	}
	dst, ok := dstRaw.(*net.TCPAddr)
	if !ok {
		return nil, nil, 0, fmt.Errorf("proxy proto destination is not TCP: %T", dstRaw)
	}
	srcNorm := normalizeTCPAddr(src)
	dstNorm := normalizeTCPAddr(dst)

	srcV4 := srcNorm.IP.To4() != nil
	dstV4 := dstNorm.IP.To4() != nil
	switch {
	case srcV4 && dstV4:
		return srcNorm, dstNorm, proxyproto.TCPv4, nil
	case !srcV4 && !dstV4:
		return srcNorm, dstNorm, proxyproto.TCPv6, nil
	default:
		return nil, nil, 0, fmt.Errorf("proxy proto address family mismatch: src=%s dst=%s", srcNorm, dstNorm)
	}
}

func normalizeTCPAddr(a *net.TCPAddr) *net.TCPAddr {
	if a == nil {
		return &net.TCPAddr{}
	}
	n := *a
	if ip4 := n.IP.To4(); ip4 != nil {
		n.IP = ip4
		n.Zone = ""
	}
	return &n
}

// Proxy ties together the listener, dialer and per-connection session.
//
// Rules can be hot-swapped via SetRules; in-flight connections keep the
// pointer they captured at Handle time, new connections pick up the new
// pointer.
type Proxy struct {
	Dialer   Dialer
	Rewriter *capability.Rewriter

	rules atomic.Pointer[rules.Rules]
}

// SetRules atomically replaces the rules used for new connections.
func (p *Proxy) SetRules(r *rules.Rules) { p.rules.Store(r) }

// Rules returns the currently active rules pointer (may be nil).
func (p *Proxy) Rules() *rules.Rules { return p.rules.Load() }

// Serve accepts connections from ln until it errors and dispatches each
// one to Handle in its own goroutine.
func (p *Proxy) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) { _ = p.Handle(c) }(c)
	}
}

// Handle services a single client connection: dial upstream, run a session,
// close both ends when done.
func (p *Proxy) Handle(client net.Conn) error {
	defer client.Close()
	if err := handshakeClient(client); err != nil {
		return err
	}
	upstream, err := p.Dialer.Dial(client)
	if err != nil {
		sendBYE(client)
		return err
	}
	defer upstream.Close()

	s := &session.Session{
		Client:   client,
		Server:   upstream,
		Rules:    p.Rules(),
		Rewriter: p.Rewriter,
	}
	return s.Run()
}

func handshakeClient(client net.Conn) error {
	tlsClient, ok := client.(*tls.Conn)
	if !ok {
		return nil
	}
	return tlsClient.Handshake()
}

func sendBYE(client net.Conn) {
	_ = client.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = client.Write([]byte("* BYE upstream unavailable\r\n"))
	_ = client.SetWriteDeadline(time.Time{})
}
