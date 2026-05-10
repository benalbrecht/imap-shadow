// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"testing"
)

const sample = `
[listen]
addr = "0.0.0.0:993"

[acme]
hostnames = ["mail.example.com"]
email = "admin@example.com"
cache_dir = "/var/lib/imap-shadow/acme"
http_addr = "0.0.0.0:80"

[upstream]
addr = "127.0.0.1:143"
tls = false
proxy_protocol = true

[capability]
strip = ["COMPRESS=DEFLATE", "REFERRAL"]

[namespace]
shared_prefixes = ["Shared Folders/", "Other Users/"]

[[rules]]
user = "*"
hide = ["Trash", "Archive/Legacy"]

[[rules]]
user = "newsletter-bot@example.com"
hide_personal = true
`

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadParsesAllSections(t *testing.T) {
	c, err := Load(writeTemp(t, sample))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen.Addr != "0.0.0.0:993" {
		t.Errorf("listen.addr=%q", c.Listen.Addr)
	}
	if len(c.ACME.Hostnames) != 1 || c.ACME.Hostnames[0] != "mail.example.com" {
		t.Errorf("acme.hostnames=%v", c.ACME.Hostnames)
	}
	if c.ACME.Email != "admin@example.com" {
		t.Errorf("acme.email=%q", c.ACME.Email)
	}
	if c.ACME.CacheDir != "/var/lib/imap-shadow/acme" {
		t.Errorf("acme.cache_dir=%q", c.ACME.CacheDir)
	}
	if c.ACME.HTTPAddr != "0.0.0.0:80" {
		t.Errorf("acme.http_addr=%q", c.ACME.HTTPAddr)
	}
	if c.Upstream.Addr != "127.0.0.1:143" || c.Upstream.TLS {
		t.Errorf("upstream=%+v", c.Upstream)
	}
	if len(c.Capability.Strip) != 2 {
		t.Errorf("capability.strip=%v", c.Capability.Strip)
	}
	if len(c.Namespace.SharedPrefixes) != 2 {
		t.Errorf("namespace.shared_prefixes=%v", c.Namespace.SharedPrefixes)
	}
	if len(c.Rules) != 2 {
		t.Fatalf("rules len=%d", len(c.Rules))
	}
	if c.Rules[0].User != "*" || len(c.Rules[0].Hide) != 2 {
		t.Errorf("rules[0]=%+v", c.Rules[0])
	}
	if c.Rules[1].User != "newsletter-bot@example.com" || c.Rules[1].HidePersonal == nil || !*c.Rules[1].HidePersonal {
		t.Errorf("rules[1]=%+v", c.Rules[1])
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("/nonexistent/path/that/does/not/exist.toml"); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadInvalidTOML(t *testing.T) {
	if _, err := Load(writeTemp(t, "not valid = = =")); err == nil {
		t.Error("expected error for invalid TOML")
	}
}

func TestRulesProducesCompiledRules(t *testing.T) {
	c, err := Load(writeTemp(t, sample))
	if err != nil {
		t.Fatal(err)
	}
	r := c.CompileRules()
	if len(r.SharedPrefixes) != 2 {
		t.Errorf("compiled prefixes=%v", r.SharedPrefixes)
	}
	if len(r.Users) != 2 {
		t.Errorf("compiled rules=%v", r.Users)
	}
	// And matching works as expected
	m := r.For("newsletter-bot@example.com")
	if !m.ShouldHide("Trash") {
		t.Error("Trash must be hidden via wildcard rule")
	}
	if !m.ShouldHide("Sent") {
		t.Error("Sent must be hidden via hide_personal")
	}
	if m.ShouldHide("Shared Folders/x/Inbox") {
		t.Error("shared mailbox must remain visible")
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	// Minimal config — most fields blank — must still load with safe defaults.
	c, err := Load(writeTemp(t, `
[acme]
hostnames = ["mail.example.com"]
email = "admin@example.com"
cache_dir = "/tmp/acme"

[upstream]
addr = "127.0.0.1:143"
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen.Addr == "" {
		t.Error("listen.addr should default to :993")
	}
	if c.ACME.HTTPAddr == "" {
		t.Error("acme.http_addr should default to :80")
	}
}

func TestCompileRulesAllowsWhitelistOverrideForHidePersonal(t *testing.T) {
	c, err := Load(writeTemp(t, `
[acme]
hostnames = ["mail.example.com"]
email = "admin@example.com"
cache_dir = "/tmp/acme"

[upstream]
addr = "127.0.0.1:143"

[[rules]]
user = "*"
hide_personal = true

[[rules]]
user = "alice@example.com"
hide_personal = false
`))
	if err != nil {
		t.Fatal(err)
	}
	r := c.CompileRules()
	if !r.For("bob@example.com").ShouldHide("Sent") {
		t.Error("wildcard hide_personal=true must hide personal folders for bob")
	}
	if r.For("alice@example.com").ShouldHide("Sent") {
		t.Error("alice hide_personal=false must override wildcard true")
	}
}
