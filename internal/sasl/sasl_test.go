// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

package sasl

import (
	"encoding/base64"
	"testing"
)

func TestUsernameFromLogin(t *testing.T) {
	tests := []struct {
		name    string
		args    string
		want    string
		wantErr bool
	}{
		{"quoted", `"alice@example.com" "hunter2"`, "alice@example.com", false},
		{"quoted with spaces in pass", `"alice" "two words"`, "alice", false},
		{"atom unquoted", `bob secret`, "bob", false},
		{"quoted user, atom pass", `"carol" secret`, "carol", false},
		{"quoted with escaped quote", `"da\"ve" "pw"`, `da"ve`, false},
		{"quoted with escaped backslash", `"a\\b" "pw"`, `a\b`, false},
		{"missing pass", `"alice"`, "", true},
		{"empty", ``, "", true},
		{"unterminated quote", `"alice`, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UsernameFromLogin([]byte(tt.args))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestUsernameFromLoginZeroesPassword(t *testing.T) {
	// caller may pass a mutable slice; the password portion must be zeroed.
	src := []byte(`"alice" "supersecret"`)
	user, err := UsernameFromLogin(src)
	if err != nil {
		t.Fatal(err)
	}
	if user != "alice" {
		t.Fatalf("user=%q", user)
	}
	// The bytes that originally spelled "supersecret" must no longer contain that string.
	if containsBytes(src, []byte("supersecret")) {
		t.Fatalf("password not zeroed in source: %q", string(src))
	}
}

func TestUsernameFromPlain(t *testing.T) {
	tests := []struct {
		name    string
		decoded string
		want    string
		wantErr bool
	}{
		{"basic", "\x00alice\x00hunter2", "alice", false},
		{"with authzid", "alice\x00alice\x00hunter2", "alice", false},
		{"empty user", "\x00\x00pass", "", true},
		{"no separators", "alicehunter2", "", true},
		{"only one separator", "\x00alice", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b64 := []byte(base64.StdEncoding.EncodeToString([]byte(tt.decoded)))
			got, err := UsernameFromPlain(b64)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestUsernameFromPlainZeroesPasswordAndB64(t *testing.T) {
	decoded := "\x00alice\x00supersecret"
	b64 := []byte(base64.StdEncoding.EncodeToString([]byte(decoded)))
	originalB64 := append([]byte(nil), b64...)
	user, err := UsernameFromPlain(b64)
	if err != nil {
		t.Fatal(err)
	}
	if user != "alice" {
		t.Fatalf("user=%q", user)
	}
	// b64 buffer must be wiped (not equal to original).
	if string(b64) == string(originalB64) {
		t.Fatalf("b64 buffer not zeroed: %q", b64)
	}
}

func TestUsernameFromBearer(t *testing.T) {
	tests := []struct {
		name    string
		decoded string
		want    string
		wantErr bool
	}{
		{
			name:    "xoauth2",
			decoded: "user=alice@example.com\x01auth=Bearer abc123\x01\x01",
			want:    "alice@example.com",
		},
		{
			name:    "oauthbearer with gs2 header user= form",
			decoded: "n,,\x01user=alice@example.com\x01auth=Bearer abc\x01\x01",
			want:    "alice@example.com",
		},
		{
			name:    "no user field",
			decoded: "auth=Bearer abc\x01\x01",
			wantErr: true,
		},
		{
			name:    "empty",
			decoded: "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b64 := []byte(base64.StdEncoding.EncodeToString([]byte(tt.decoded)))
			got, err := UsernameFromBearer(b64)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestUsernameFromBearerZeroesToken(t *testing.T) {
	decoded := "user=alice\x01auth=Bearer secrettoken\x01\x01"
	b64 := []byte(base64.StdEncoding.EncodeToString([]byte(decoded)))
	user, err := UsernameFromBearer(b64)
	if err != nil {
		t.Fatal(err)
	}
	if user != "alice" {
		t.Fatalf("user=%q", user)
	}
	// Decode the (now-mutated) base64 and ensure "secrettoken" is gone.
	if containsBytes(b64, []byte(base64.StdEncoding.EncodeToString([]byte("secrettoken")))) {
		t.Fatalf("token-containing b64 still present")
	}
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
