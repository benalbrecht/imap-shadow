// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package session bridges one IMAP client connection and one upstream
// connection, applying capability rewriting (always), filter rules
// (post-authentication), and auth snooping.
//
// The session owns no I/O of its own beyond the two ReadWriters it is
// constructed with. It is the caller's job to terminate TLS and dial
// upstream before handing the streams in.
package session

import (
	"io"
	"sync"

	"github.com/benalbrecht/imap-shadow/internal/authtrack"
	"github.com/benalbrecht/imap-shadow/internal/capability"
	"github.com/benalbrecht/imap-shadow/internal/filter"
	"github.com/benalbrecht/imap-shadow/internal/framer"
	"github.com/benalbrecht/imap-shadow/internal/rules"
)

// Session is one client ⇄ upstream relay.
type Session struct {
	Client   io.ReadWriter
	Server   io.ReadWriter
	Rules    *rules.Rules
	Rewriter *capability.Rewriter
	// OnAuth, if non-nil, is invoked once for the session at the moment
	// the upstream confirms the authenticated user. Useful for logging.
	// Never called with an empty username.
	OnAuth func(user string)

	mu      sync.Mutex
	tracker authtrack.Tracker
	filter  *filter.Filter // nil until authenticated
}

// Run starts the bidirectional bridge and returns when either side closes
// or an I/O error occurs. Whichever direction errors first wins; the other
// is unblocked by closing the underlying streams (if they happen to be
// io.Closers).
func (s *Session) Run() error {
	errc := make(chan error, 2)

	go func() { errc <- s.copyClientToServer() }()
	go func() { errc <- s.copyServerToClient() }()

	err := <-errc
	closeIfPossible(s.Client)
	closeIfPossible(s.Server)
	<-errc
	if err == io.EOF {
		return nil
	}
	return err
}

func (s *Session) copyClientToServer() error {
	f := framer.New(s.Client)
	for {
		s.mu.Lock()
		authed := s.tracker.User() != ""
		s.mu.Unlock()
		if authed {
			_, err := f.CopyTo(s.Server)
			return err
		}

		line, rerr := f.ReadLine()
		if len(line) > 0 {
			s.mu.Lock()
			s.tracker.HandleClientLine(line)
			s.mu.Unlock()
			if _, werr := s.Server.Write(line); werr != nil {
				return werr
			}
		}
		if rerr != nil {
			return rerr
		}
	}
}

func (s *Session) copyServerToClient() error {
	f := framer.New(s.Server)
	for {
		line, rerr := f.ReadLine()
		if len(line) > 0 {
			s.mu.Lock()
			committed := s.tracker.HandleServerLine(line)
			user := ""
			if committed {
				user = s.tracker.User()
				if s.Rules != nil {
					s.filter = filter.New(user, s.Rules.For(user))
				}
			}
			fl := s.filter
			s.mu.Unlock()
			if committed && user != "" && s.OnAuth != nil {
				s.OnAuth(user)
			}

			if s.Rewriter != nil {
				line = s.Rewriter.Rewrite(line)
			}
			if fl != nil {
				line = fl.Process(line)
			}
			if line != nil {
				if _, werr := s.Client.Write(line); werr != nil {
					return werr
				}
			}
		}
		if rerr != nil {
			return rerr
		}
	}
}

func closeIfPossible(x any) {
	if c, ok := x.(io.Closer); ok {
		_ = c.Close()
	}
}
