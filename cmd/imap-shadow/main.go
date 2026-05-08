// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

// imap-shadow is a transparent IMAP proxy that hides specific shared
// folders from specific users — a UI/UX workaround for the lack of "deny"
// ACLs in some IMAP servers (notably Stalwart). See README.md and the
// design doc for details.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/benalbrecht/imap-shadow/internal/capability"
	"github.com/benalbrecht/imap-shadow/internal/config"
	"github.com/benalbrecht/imap-shadow/internal/proxy"
)

func main() {
	cfgPath := flag.String("config", "/etc/imap-shadow/config.toml", "path to configuration file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Build the proxy with current rules.
	p := &proxy.Proxy{
		Dialer: &proxy.TCPDialer{
			Addr:          cfg.Upstream.Addr,
			TLS:           cfg.Upstream.TLS,
			SNI:           cfg.Upstream.SNI,
			SkipVerify:    cfg.Upstream.TLSSkipVerify,
			ProxyProtocol: cfg.Upstream.ProxyProtocol,
		},
		Rewriter: capability.New(cfg.Capability.Strip),
		OnAuth: func(client net.Conn, user string) {
			log.Printf("auth ok: client=%s user=%s", client.RemoteAddr(), user)
		},
		BlockCrossAccountMoves: cfg.Policy.BlockCrossAccountMoves,
	}
	p.SetRules(cfg.CompileRules())

	// ACME via HTTP-01.
	tlsCfg, httpHandler, acmeMgr := newACME(cfg)

	// HTTP-01 challenge server. Must be reachable from the internet on :80.
	httpLn, err := net.Listen("tcp", cfg.ACME.HTTPAddr)
	if err != nil {
		log.Fatalf("acme http listen: %v", err)
	}
	httpSrv := &http.Server{
		Handler:           httpHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("acme: listening on %s for HTTP-01 challenges", httpLn.Addr().String())
		if err := httpSrv.Serve(httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("acme http: %v", err)
		}
	}()
	warmCtx, warmCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	go warmCertificates(warmCtx, acmeMgr, cfg.ACME.Hostnames)

	// IMAPS listener.
	rawLn, err := net.Listen("tcp", cfg.Listen.Addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	tlsLn := tls.NewListener(rawLn, tlsCfg)
	log.Printf("imap-shadow: serving %s -> %s", cfg.Listen.Addr, cfg.Upstream.Addr)

	// Signal handling: SIGHUP reloads rules, SIGINT/SIGTERM shuts down.
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				newCfg, err := config.Load(*cfgPath)
				if err != nil {
					log.Printf("reload: %v", err)
					continue
				}
				p.SetRules(newCfg.CompileRules())
				log.Printf("reload: rules updated")
			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("shutdown: signal %s", sig)
				warmCancel()
				_ = tlsLn.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = httpSrv.Shutdown(ctx)
				cancel()
				return
			}
		}
	}()

	if err := p.Serve(tlsLn); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Fatalf("serve: %v", err)
	}
}

// newACME constructs an autocert.Manager-backed *tls.Config plus the HTTP
// handler that serves HTTP-01 challenges.
func newACME(cfg *config.Config) (*tls.Config, http.Handler, *autocert.Manager) {
	if len(cfg.ACME.Hostnames) == 0 {
		log.Fatal("acme.hostnames must be set")
	}
	if cfg.ACME.CacheDir == "" {
		log.Fatal("acme.cache_dir must be set")
	}
	if err := os.MkdirAll(cfg.ACME.CacheDir, 0o700); err != nil {
		log.Fatalf("acme cache_dir: %v", err)
	}
	m := &autocert.Manager{
		Cache:      autocert.DirCache(cfg.ACME.CacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.ACME.Hostnames...),
		Email:      cfg.ACME.Email,
	}
	if cfg.ACME.Directory != "" {
		m.Client = &acme.Client{DirectoryURL: cfg.ACME.Directory}
	}
	tlsCfg := m.TLSConfig()
	return tlsCfg, m.HTTPHandler(nil), m
}

func warmCertificates(ctx context.Context, m *autocert.Manager, hostnames []string) {
	for _, host := range uniqueHostnames(hostnames) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		log.Printf("acme: ensuring certificate for %s", host)
		_, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
		if err != nil {
			log.Printf("acme: initial certificate request for %s failed: %v", host, err)
			continue
		}
		log.Printf("acme: certificate ready for %s", host)
	}
}

func uniqueHostnames(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, h := range in {
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}
