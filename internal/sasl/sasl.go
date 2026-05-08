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
// returns the authentication identity. Two wire forms are supported:
//
//   - XOAUTH2 (Google) and the non-standard OAUTHBEARER variant some
//     clients send, both of which carry "user=<value>\x01" as one of the
//     \x01-separated fields.
//   - RFC 7628 OAUTHBEARER, where the identity lives in the GS2 header
//     authzid as "a=<value>" inside the FIRST field (the GS2 header has
//     the shape "<cb-flag>,a=<saslname>,"). Roundcube/Kolab uses this.
//
// The "user=" form takes precedence when both are present; otherwise the
// GS2 "a=" authzid is used. The bearer-token region of the decoded buffer
// and the entire base64 input are zeroed before return.
func UsernameFromBearer(b64 []byte) (string, error) {
	defer zero(b64)
	dec := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	n, err := base64.StdEncoding.Decode(dec, b64)
	if err != nil {
		return "", err
	}
	dec = dec[:n]
	defer zero(dec)
	const sep = '\x01'
	const userKey = "user="

	// Walk \x01-separated fields. Remember the first field separately
	// because that is where the GS2 header lives in OAUTHBEARER.
	var gs2 []byte
	first := true
	for i := 0; i < len(dec); {
		end := i
		for end < len(dec) && dec[end] != sep {
			end++
		}
		field := dec[i:end]
		if first {
			gs2 = field
			first = false
		}
		if len(field) >= len(userKey) && string(field[:len(userKey)]) == userKey {
			val := field[len(userKey):]
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
	if u := authzidFromGS2(gs2); u != "" {
		return u, nil
	}
	return "", errors.New("bearer: no user= field and no GS2 a= authzid")
}

// authzidFromGS2 extracts the saslname from a GS2 header of the form
// "<cb-flag>,a=<saslname>," (RFC 5801 §4). Returns "" when no authzid is
// present (e.g. "n,," / "y,,") or when the input does not look like a GS2
// header at all. Per RFC 5801, the saslname uses "=2C" / "=3D" escapes for
// "," and "=" respectively; those are decoded here.
func authzidFromGS2(field []byte) string {
	// Must start with cb-flag ("n", "y", or "p=...") followed by ",".
	if len(field) < 2 {
		return ""
	}
	switch field[0] {
	case 'n', 'y':
		if field[1] != ',' {
			return ""
		}
	case 'p':
		// p=<cb-name>,
		if len(field) < 3 || field[1] != '=' {
			return ""
		}
	default:
		return ""
	}
	comma := bytes.IndexByte(field, ',')
	if comma < 0 || comma+1 >= len(field) {
		return ""
	}
	rest := field[comma+1:] // either "" or "a=<saslname>,..."
	if len(rest) < 2 || rest[0] != 'a' || rest[1] != '=' {
		return ""
	}
	raw := rest[2:]
	// The saslname terminates at the first unescaped "," (the comma that
	// closes the GS2 header). Within the saslname, "," is escaped as
	// "=2C" per RFC 5801 §4 and so does NOT terminate.
	end := 0
	for end < len(raw) {
		if raw[end] == ',' {
			break
		}
		if raw[end] == '=' && end+2 < len(raw) {
			// skip "=2C" / "=3D" escape, do not split here
			end += 3
			continue
		}
		end++
	}
	raw = raw[:end]
	if len(raw) == 0 {
		return ""
	}
	return decodeSaslname(raw)
}

// decodeSaslname unescapes the RFC 5801 saslname escapes "=2C" -> "," and
// "=3D" -> "=".
func decodeSaslname(b []byte) string {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '=' && i+2 < len(b) {
			switch {
			case b[i+1] == '2' && (b[i+2] == 'C' || b[i+2] == 'c'):
				out = append(out, ',')
				i += 2
				continue
			case b[i+1] == '3' && (b[i+2] == 'D' || b[i+2] == 'd'):
				out = append(out, '=')
				i += 2
				continue
			}
		}
		out = append(out, b[i])
	}
	return string(out)
}

// zero overwrites the slice with NUL bytes.
func zero(b []byte) {
	clear(b)
}
