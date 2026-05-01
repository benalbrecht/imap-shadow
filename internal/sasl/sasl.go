// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sasl extracts the authenticated username from the wire-level
// payloads of the SASL mechanisms in use by Stalwart deployments here:
// LOGIN, AUTHENTICATE PLAIN, AUTHENTICATE XOAUTH2, AUTHENTICATE OAUTHBEARER.
//
// Every function zeroes out the byte ranges that contained the password or
// bearer token before returning, so callers don't need to do that themselves.
// The username is returned as a freshly-allocated string and contains no
// reference to the input slice.
package sasl

import (
	"bytes"
	"encoding/base64"
	"errors"
)

// UsernameFromLogin parses the arguments of an IMAP LOGIN command (everything
// after the literal "LOGIN " keyword, up to but not including CRLF) and
// returns the username. The password bytes inside the input slice are zeroed
// before return.
//
// Supported argument forms:
//
//	"user" "password"
//	user password
//	"escaped\"user" "pass"
//
// Literal-form ({N}\r\n...) arguments must be resolved by the caller's framer
// before being passed in.
func UsernameFromLogin(args []byte) (string, error) {
	user, userEnd, err := readIMAPString(args, 0)
	if err != nil {
		return "", err
	}
	// skip whitespace between user and pass
	i := userEnd
	for i < len(args) && (args[i] == ' ' || args[i] == '\t') {
		i++
	}
	if i >= len(args) {
		return "", errors.New("LOGIN: missing password")
	}
	// password starts at i; we don't actually need its value, just to zero it.
	passStart := i
	if args[i] == '"' {
		// quoted: zero from opening quote through closing quote
		_, passEnd, err := readIMAPString(args, i)
		if err != nil {
			return "", err
		}
		zero(args[passStart:passEnd])
	} else {
		// atom: zero to end of args (or next whitespace)
		end := i
		for end < len(args) && args[end] != ' ' && args[end] != '\t' {
			end++
		}
		zero(args[passStart:end])
	}
	return user, nil
}

// readIMAPString parses a quoted-string or atom starting at offset off and
// returns the decoded value plus the offset of the first byte after it.
func readIMAPString(b []byte, off int) (string, int, error) {
	if off >= len(b) {
		return "", off, errors.New("unexpected end of input")
	}
	if b[off] == '"' {
		// quoted-string with backslash escapes for " and \
		var out []byte
		i := off + 1
		for i < len(b) {
			c := b[i]
			if c == '\\' && i+1 < len(b) {
				out = append(out, b[i+1])
				i += 2
				continue
			}
			if c == '"' {
				return string(out), i + 1, nil
			}
			out = append(out, c)
			i++
		}
		return "", off, errors.New("unterminated quoted-string")
	}
	// atom: read until whitespace
	end := off
	for end < len(b) && b[end] != ' ' && b[end] != '\t' {
		end++
	}
	if end == off {
		return "", off, errors.New("empty atom")
	}
	return string(b[off:end]), end, nil
}

// UsernameFromPlain decodes a SASL PLAIN base64 payload and returns the
// authentication identity (the second \x00-separated field). The password
// region of the decoded buffer and the entire base64 input are zeroed before
// return.
//
// Per RFC 4616, the payload is: authzid \0 authcid \0 passwd
func UsernameFromPlain(b64 []byte) (string, error) {
	defer zero(b64)
	dec := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	n, err := base64.StdEncoding.Decode(dec, b64)
	if err != nil {
		return "", err
	}
	dec = dec[:n]
	defer zero(dec)
	parts := bytes.SplitN(dec, []byte{0}, 3)
	if len(parts) != 3 {
		return "", errors.New("PLAIN: expected three NUL-separated fields")
	}
	user := parts[1]
	if len(user) == 0 {
		return "", errors.New("PLAIN: empty authcid")
	}
	return string(user), nil
}

// UsernameFromBearer decodes a base64 XOAUTH2 / OAUTHBEARER payload and
// returns the username carried in the "user=<value>\x01" key/value pair.
// Both wire formats use this same key, so a single extractor covers them.
// The bearer-token region of the decoded buffer and the entire base64 input
// are zeroed before return.
func UsernameFromBearer(b64 []byte) (string, error) {
	defer zero(b64)
	dec := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	n, err := base64.StdEncoding.Decode(dec, b64)
	if err != nil {
		return "", err
	}
	dec = dec[:n]
	defer zero(dec)
	// fields are \x01-separated; locate one that begins with "user=".
	const sep = '\x01'
	const key = "user="
	for i := 0; i < len(dec); {
		// find end of this field
		end := i
		for end < len(dec) && dec[end] != sep {
			end++
		}
		field := dec[i:end]
		if len(field) >= len(key) && string(field[:len(key)]) == key {
			val := field[len(key):]
			if len(val) == 0 {
				return "", errors.New("bearer: empty user value")
			}
			return string(val), nil
		}
		if end >= len(dec) {
			break
		}
		i = end + 1
	}
	return "", errors.New("bearer: no user= field")
}

// zero overwrites the slice with NUL bytes.
func zero(b []byte) {
	clear(b)
}
