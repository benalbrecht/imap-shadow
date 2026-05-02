// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package framer reads an IMAP byte stream and emits one logical
// command/response per ReadLine call. IMAP is line-oriented (CRLF
// delimited) except for "literals", which appear at the end of an
// otherwise-incomplete line as the marker:
//
//	{N}\r\n   (synchronising literal — RFC 3501)
//	{N+}\r\n  (non-synchronising literal — LITERAL+ extension, RFC 7888)
//
// After such a marker, exactly N bytes of payload follow, then parsing
// continues on the same logical line. A line may contain any number of
// literals.
//
// ReadLine returns the entire logical line — every literal marker, every
// payload byte, and the terminating CRLF — as a single freshly-allocated
// slice. Callers may mutate the slice (e.g. to zero a password) without
// affecting subsequent reads.
package framer

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
)

// ErrLiteralTooLarge is returned when a literal exceeds the maximum allowed size.
var ErrLiteralTooLarge = errors.New("framer: literal too large")

// ErrLineTooLong is returned when a line exceeds the maximum allowed size.
var ErrLineTooLong = errors.New("framer: line too long")

const maxLiteralSize = 256 * 1024 * 1024 // 256 MiB

// maxLineSize is maxLiteralSize plus a generous 64 KiB allowance for the
// rest of the logical line (commands, multiple literal markers, etc.) to
// prevent unbounded memory growth on infinite non-newline streams.
const maxLineSize = maxLiteralSize + 65536

// Framer reads logical IMAP lines from an underlying byte stream.
type Framer struct {
	br *bufio.Reader
}

// New wraps r in a Framer. r is buffered internally; do not wrap it again.
func New(r io.Reader) *Framer {
	return &Framer{br: bufio.NewReader(r)}
}

// ReadLine returns the next logical IMAP line. On a clean EOF before any
// bytes are read it returns io.EOF; on EOF mid-line it returns
// io.ErrUnexpectedEOF.
func (f *Framer) ReadLine() ([]byte, error) {
	var out []byte
	for {
		chunk, err := f.br.ReadSlice('\n')
		if len(chunk) > 0 {
			out = append(out, chunk...)
		}

		if len(out) > maxLineSize {
			return out, ErrLineTooLong
		}

		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				// We haven't seen a newline yet. Keep going.
				continue
			}
			if errors.Is(err, io.EOF) {
				if len(out) == 0 {
					return nil, io.EOF
				}
				return out, io.ErrUnexpectedEOF
			}
			return out, err
		}
		// We have a CRLF-terminated chunk. Check for a literal marker at the
		// end of the chunk just before the CRLF.
		n, ok := literalCount(out)
		if !ok {
			return out, nil
		}
		if n > 0 {
			if n > maxLiteralSize {
				return out, ErrLiteralTooLarge
			}
			if len(out)+n > maxLineSize {
				return out, ErrLineTooLong
			}
			rem := n
			for rem > 0 {
				chunkSize := rem
				if chunkSize > 32768 {
					chunkSize = 32768
				}
				start := len(out)
				out = append(out, make([]byte, chunkSize)...)
				nr, err := io.ReadFull(f.br, out[start:start+chunkSize])
				out = out[:start+nr]
				rem -= nr
				if err != nil {
					if errors.Is(err, io.EOF) {
						return out, io.ErrUnexpectedEOF
					}
					return out, err
				}
			}
		}
		// loop: read the next chunk that continues this logical line
	}
}

// literalCount inspects the tail of line. If line ends with "{N}\r\n" or
// "{N+}\r\n" — and only there — it returns N and true. Otherwise (0, false).
func literalCount(line []byte) (int, bool) {
	if !bytes.HasSuffix(line, []byte("\r\n")) {
		return 0, false
	}
	// trim CRLF
	body := line[:len(line)-2]
	if len(body) < 3 || body[len(body)-1] != '}' {
		return 0, false
	}
	// strip the trailing '}'
	body = body[:len(body)-1]
	if len(body) > 0 && body[len(body)-1] == '+' {
		body = body[:len(body)-1] // LITERAL+ marker
	}
	// walk back over digits
	i := len(body)
	for i > 0 && body[i-1] >= '0' && body[i-1] <= '9' {
		i--
	}
	digits := body[i:]
	if len(digits) == 0 || i == 0 || body[i-1] != '{' {
		return 0, false
	}
	n, err := strconv.Atoi(string(digits))
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
