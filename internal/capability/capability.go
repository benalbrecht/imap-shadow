// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package capability rewrites the CAPABILITY responses Stalwart sends to the
// client by removing tokens the proxy can't safely transit. Two forms are
// recognised:
//
//   - CAPABILITY <token> <token> ...
//   - OK [CAPABILITY <token> <token> ...] <free text>
//
// Comparison is case-insensitive on the whole token (so "AUTH=PLAIN" with
// strip = "PLAIN" is *not* removed; the strip list must contain whole
// tokens). Lines that are not capability advertisements are returned
// unchanged. CRLF terminators are preserved.
package capability

import (
	"bytes"
	"strings"
)

// Rewriter removes a configured set of capability tokens from CAPABILITY
// responses.
type Rewriter struct {
	strip map[string]struct{}
}

// New compiles a Rewriter. Tokens are stored case-folded so callers can use
// any casing in config.
func New(strip []string) *Rewriter {
	r := &Rewriter{strip: make(map[string]struct{}, len(strip))}
	for _, s := range strip {
		r.strip[strings.ToUpper(s)] = struct{}{}
	}
	return r
}

// Rewrite returns the line with stripped tokens removed. The input is not
// mutated. If the line isn't a capability advertisement, the original slice
// is returned unchanged.
func (r *Rewriter) Rewrite(line []byte) []byte {
	if len(r.strip) == 0 || len(line) == 0 {
		return line
	}
	// Locate the inner token list.
	// 1. * CAPABILITY ...
	// 2. * OK [CAPABILITY ...] ...
	upper := bytes.ToUpper(line)
	if start := indexAfter(upper, []byte("* CAPABILITY ")); start >= 0 {
		// tokens run until CRLF or end
		end := tokensEnd(line, start)
		return rebuild(line, start, end, r.strip)
	}
	if start := indexAfter(upper, []byte("[CAPABILITY ")); start >= 0 {
		// tokens run until ']'
		end := bytes.IndexByte(line[start:], ']')
		if end < 0 {
			return line
		}
		end += start
		return rebuild(line, start, end, r.strip)
	}
	return line
}

// indexAfter is bytes.Index, but returns the offset *after* the prefix.
func indexAfter(haystack, prefix []byte) int {
	i := bytes.Index(haystack, prefix)
	if i < 0 {
		return -1
	}
	return i + len(prefix)
}

// tokensEnd returns the offset of the CRLF (or end) following the tokens
// portion that starts at off.
func tokensEnd(line []byte, off int) int {
	if i := bytes.Index(line[off:], []byte("\r\n")); i >= 0 {
		return off + i
	}
	return len(line)
}

// rebuild splices a filtered token list back into line[start:end].
func rebuild(line []byte, start, end int, strip map[string]struct{}) []byte {
	tokens := bytes.Fields(line[start:end])
	kept := tokens[:0]
	for _, tok := range tokens {
		if _, drop := strip[strings.ToUpper(string(tok))]; drop {
			continue
		}
		kept = append(kept, tok)
	}
	out := make([]byte, 0, len(line))
	out = append(out, line[:start]...)
	out = append(out, bytes.Join(kept, []byte(" "))...)
	out = append(out, line[end:]...)
	// Trim a leftover space immediately before line[end] (e.g. when the last
	// token was stripped: "A B X" -> "A B " before splicing). We remove a
	// single trailing space at the end of the rewritten token region.
	if start < len(out) && len(kept) > 0 {
		// Recompute the new end of the token region after splice.
		newEnd := start + len(bytes.Join(kept, []byte(" ")))
		if newEnd < len(out) && out[newEnd] == ' ' {
			// Was there a separator already there? Look at original: if line[end-1]
			// was a space (e.g. trailing token before "]"), drop one space.
			if end > 0 && line[end-1] == ' ' {
				out = append(out[:newEnd], out[newEnd+1:]...)
			}
		}
		// Trim a trailing space immediately before CRLF / end.
		if len(out) >= 3 && out[len(out)-3] == ' ' && out[len(out)-2] == '\r' && out[len(out)-1] == '\n' {
			out = append(out[:len(out)-3], '\r', '\n')
		}
	}
	return out
}
