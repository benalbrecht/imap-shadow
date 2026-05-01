// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config loads the imap-shadow TOML configuration file.
//
// The schema mirrors the example in README.md / config.toml: small,
// flat, and hand-edited. CompileRules turns the [[rules]] blocks into
// the compiled form expected by the rules package.
package config

import (
	"github.com/BurntSushi/toml"

	"github.com/benalbrecht/imap-shadow/internal/rules"
)

// Config is the on-disk shape of imap-shadow.toml.
type Config struct {
	Listen     Listen     `toml:"listen"`
	ACME       ACME       `toml:"acme"`
	Upstream   Upstream   `toml:"upstream"`
	Capability Capability `toml:"capability"`
	Namespace  Namespace  `toml:"namespace"`
	Rules      []Rule     `toml:"rules"`
}

// Listen controls the public IMAPS endpoint.
type Listen struct {
	Addr string `toml:"addr"`
}

// ACME configures certificate issuance via HTTP-01.
type ACME struct {
	Hostnames []string `toml:"hostnames"`
	Email     string   `toml:"email"`
	CacheDir  string   `toml:"cache_dir"`
	Directory string   `toml:"directory"`
	HTTPAddr  string   `toml:"http_addr"`
}

// Upstream points at the backing IMAP server (Stalwart, on loopback).
type Upstream struct {
	Addr          string `toml:"addr"`
	TLS           bool   `toml:"tls"`
	TLSSkipVerify bool   `toml:"tls_skip_verify"`
	SNI           string `toml:"sni"`
	// ProxyProtocol enables emission of a PROXY v2 header before any other
	// bytes, so the upstream sees the client's real peer address.
	ProxyProtocol bool `toml:"proxy_protocol"`
}

// Capability lists CAPABILITY tokens to strip from server responses.
type Capability struct {
	Strip []string `toml:"strip"`
}

// Namespace declares which prefixes mark the shared-folder namespace.
type Namespace struct {
	SharedPrefixes []string `toml:"shared_prefixes"`
}

// Rule is one [[rules]] block.
type Rule struct {
	User         string   `toml:"user"`
	Hide         []string `toml:"hide"`
	HidePersonal bool     `toml:"hide_personal"`
}

// Load parses the TOML file at path and applies safe defaults.
func Load(path string) (*Config, error) {
	c := &Config{}
	if _, err := toml.DecodeFile(path, c); err != nil {
		return nil, err
	}
	if c.Listen.Addr == "" {
		c.Listen.Addr = "0.0.0.0:993"
	}
	if c.ACME.HTTPAddr == "" {
		c.ACME.HTTPAddr = "0.0.0.0:80"
	}
	return c, nil
}

// CompileRules turns the on-disk rule blocks into the form used at
// match-time.
func (c *Config) CompileRules() *rules.Rules {
	out := &rules.Rules{
		SharedPrefixes: c.Namespace.SharedPrefixes,
	}
	for _, r := range c.Rules {
		out.Users = append(out.Users, rules.UserRule{
			User:         r.User,
			Hide:         r.Hide,
			HidePersonal: r.HidePersonal,
		})
	}
	return out
}
