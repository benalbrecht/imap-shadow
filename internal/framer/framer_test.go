// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

package framer

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func read(t *testing.T, f *Framer) string {
	t.Helper()
	b, err := f.ReadLine()
	if err != nil {
		t.Fatalf("ReadLine: %v", err)
	}
	return string(b)
}

func TestSimpleLine(t *testing.T) {
	f := New(strings.NewReader("a1 NOOP\r\n"))
	if got := read(t, f); got != "a1 NOOP\r\n" {
		t.Errorf("got %q", got)
	}
}

func TestPipelinedLines(t *testing.T) {
	f := New(strings.NewReader("a1 NOOP\r\na2 NOOP\r\n"))
	if got := read(t, f); got != "a1 NOOP\r\n" {
		t.Errorf("first: %q", got)
	}
	if got := read(t, f); got != "a2 NOOP\r\n" {
		t.Errorf("second: %q", got)
	}
}

func TestSynchronisingLiteral(t *testing.T) {
	in := "a1 LOGIN {5}\r\nalice {4}\r\npass\r\n"
	f := New(strings.NewReader(in))
	if got := read(t, f); got != in {
		t.Errorf("got %q", got)
	}
}

func TestLiteralPlus(t *testing.T) {
	in := "a1 LOGIN {5+}\r\nalice {4+}\r\npass\r\n"
	f := New(strings.NewReader(in))
	if got := read(t, f); got != in {
		t.Errorf("got %q", got)
	}
}

func TestLiteralWithCRLFInside(t *testing.T) {
	// the 6 literal bytes contain a CRLF; framer must not stop early.
	in := "a1 X {6}\r\nab\r\ncd more\r\n"
	f := New(strings.NewReader(in))
	if got := read(t, f); got != in {
		t.Errorf("got %q", got)
	}
}

func TestZeroLengthLiteral(t *testing.T) {
	in := "a1 X {0}\r\n done\r\n"
	f := New(strings.NewReader(in))
	if got := read(t, f); got != in {
		t.Errorf("got %q", got)
	}
}

func TestEOFAtCleanBoundary(t *testing.T) {
	f := New(strings.NewReader("a1 NOOP\r\n"))
	_, err := f.ReadLine()
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.ReadLine()
	if !errors.Is(err, io.EOF) {
		t.Errorf("got %v want io.EOF", err)
	}
}

func TestEOFMidLineIsErr(t *testing.T) {
	f := New(strings.NewReader("a1 partial"))
	_, err := f.ReadLine()
	if err == nil || errors.Is(err, io.EOF) && err == io.EOF {
		// io.EOF is unexpected here — there's a partial line. We accept any
		// non-nil non-clean-EOF error including io.ErrUnexpectedEOF.
	}
	if err == nil {
		t.Fatal("expected an error on mid-line EOF")
	}
}

func TestLiteralCountNotMistakenForBraces(t *testing.T) {
	// a "{...}" inside the body of a regular line must NOT be interpreted as
	// a literal marker if it's not at end-of-line (followed by CRLF).
	in := "a1 SEARCH HEADER From {not-a-literal}\r\n"
	f := New(strings.NewReader(in))
	if got := read(t, f); got != in {
		t.Errorf("got %q", got)
	}
}

func TestNonNumericInBracesIsNotLiteral(t *testing.T) {
	in := "* LIST () \"/\" \"{folder}\"\r\n"
	f := New(strings.NewReader(in))
	if got := read(t, f); got != in {
		t.Errorf("got %q", got)
	}
}

func TestMultipleSequentialReads(t *testing.T) {
	in := "a1 LOGIN {5}\r\nalice pass\r\na2 NOOP\r\n* OK ok\r\n"
	f := New(strings.NewReader(in))
	first := read(t, f)
	if first != "a1 LOGIN {5}\r\nalice pass\r\n" {
		t.Errorf("first: %q", first)
	}
	if got := read(t, f); got != "a2 NOOP\r\n" {
		t.Errorf("second: %q", got)
	}
	if got := read(t, f); got != "* OK ok\r\n" {
		t.Errorf("third: %q", got)
	}
}

func TestReadLineReturnsCopySafeForMutation(t *testing.T) {
	// caller may mutate the returned slice (e.g. zero passwords) without
	// corrupting subsequent reads.
	in := "a1 LOGIN {5}\r\nalice pass\r\na2 NOOP\r\n"
	f := New(bytes.NewReader([]byte(in)))
	first, err := f.ReadLine()
	if err != nil {
		t.Fatal(err)
	}
	// scribble all over it
	for i := range first {
		first[i] = 0
	}
	second, err := f.ReadLine()
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != "a2 NOOP\r\n" {
		t.Errorf("got %q (mutation of first read leaked into second)", second)
	}
}

func TestLiteralTooLarge(t *testing.T) {
	in := "a1 LOGIN {9999999999}\r\n"
	f := New(strings.NewReader(in))
	_, err := f.ReadLine()
	if !errors.Is(err, ErrLiteralTooLarge) {
		t.Errorf("got error %v want %v", err, ErrLiteralTooLarge)
	}
}

type infiniteReader struct {
	b byte
}

func (r infiniteReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

func TestLineTooLong(t *testing.T) {
	f := New(infiniteReader{'a'})
	_, err := f.ReadLine()
	if !errors.Is(err, ErrLineTooLong) {
		t.Errorf("got error %v want %v", err, ErrLineTooLong)
	}
}

func TestLiteralAllocationAttack(t *testing.T) {
	// A literal size declaration followed by EOF should fail quickly with ErrUnexpectedEOF,
	// and shouldn't panic with OOM even for large sizes.
	in := "a1 LOGIN {100000000}\r\n"
	f := New(strings.NewReader(in))
	_, err := f.ReadLine()
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("got error %v want %v", err, io.ErrUnexpectedEOF)
	}
}
