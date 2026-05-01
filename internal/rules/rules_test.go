// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

package rules

import "testing"

func TestINBOXIsNeverHidden(t *testing.T) {
	r := &Rules{
		Users: []UserRule{
			{User: "*", Hide: []string{"INBOX"}, HidePersonal: true},
		},
	}
	m := r.For("alice@example.com")
	for _, name := range []string{"INBOX", "inbox", "Inbox", "INbOX"} {
		if m.ShouldHide(name) {
			t.Errorf("%q must never be hidden", name)
		}
	}
}

func TestExactHide(t *testing.T) {
	r := &Rules{
		Users: []UserRule{
			{User: "alice", Hide: []string{"Trash"}},
		},
	}
	m := r.For("alice")
	if !m.ShouldHide("Trash") {
		t.Error("Trash must be hidden")
	}
	if m.ShouldHide("TrashCan") {
		t.Error("TrashCan must NOT be hidden (no false-prefix match)")
	}
}

func TestHideCascadesToSubfolders(t *testing.T) {
	r := &Rules{
		Users: []UserRule{
			{User: "*", Hide: []string{"Trash", "Archive/Legacy"}},
		},
	}
	m := r.For("anyone")
	cases := map[string]bool{
		"Trash":             true,
		"Trash/2024":        true,
		"Trash/Old/Deep":    true,
		"Archive/Legacy":    true,
		"Archive/Legacy/X":  true,
		"Archive":           false,
		"Archive/Other":     false,
		"OtherFolder":       false,
	}
	for name, want := range cases {
		if got := m.ShouldHide(name); got != want {
			t.Errorf("%q: got %v want %v", name, got, want)
		}
	}
}

func TestUserGlobStarMatchesEveryone(t *testing.T) {
	r := &Rules{
		Users: []UserRule{
			{User: "*", Hide: []string{"Trash"}},
		},
	}
	if !r.For("anyone@example.com").ShouldHide("Trash") {
		t.Error("* must match everyone")
	}
}

func TestExactUserMatchOnly(t *testing.T) {
	r := &Rules{
		Users: []UserRule{
			{User: "bob@example.com", Hide: []string{"Sent"}},
		},
	}
	if !r.For("bob@example.com").ShouldHide("Sent") {
		t.Error("bob must hide Sent")
	}
	if r.For("alice@example.com").ShouldHide("Sent") {
		t.Error("alice must NOT hide Sent")
	}
}

func TestStackingUnionsHideAndORsPersonal(t *testing.T) {
	r := &Rules{
		SharedPrefixes: []string{"Shared Folders/"},
		Users: []UserRule{
			{User: "*", Hide: []string{"Trash"}},
			{User: "bob", Hide: []string{"Archive"}, HidePersonal: true},
		},
	}
	m := r.For("bob")
	for _, name := range []string{"Trash", "Trash/Old", "Archive", "Archive/Sub"} {
		if !m.ShouldHide(name) {
			t.Errorf("%q must be hidden via union", name)
		}
	}
	// hide_personal hides arbitrary personal folders too
	if !m.ShouldHide("RandomPersonal") {
		t.Error("hide_personal must hide arbitrary personal folder")
	}
	if m.ShouldHide("Shared Folders/team/Inbox") {
		t.Error("hide_personal must NOT hide shared folders")
	}
}

func TestHidePersonalDoesNotAffectSharedNamespace(t *testing.T) {
	r := &Rules{
		SharedPrefixes: []string{"Shared Folders/", "Other Users/"},
		Users: []UserRule{
			{User: "newsletter-bot", HidePersonal: true},
		},
	}
	m := r.For("newsletter-bot")
	hidden := []string{"Sent", "Drafts", "Personal/Notes"}
	visible := []string{
		"INBOX",
		"Shared Folders/team/Inbox",
		"Other Users/admin/Sent",
	}
	for _, n := range hidden {
		if !m.ShouldHide(n) {
			t.Errorf("%q must be hidden", n)
		}
	}
	for _, n := range visible {
		if m.ShouldHide(n) {
			t.Errorf("%q must be visible", n)
		}
	}
}

func TestNoMatchingRulesNothingHidden(t *testing.T) {
	r := &Rules{
		Users: []UserRule{
			{User: "alice", Hide: []string{"Trash"}},
		},
	}
	m := r.For("bob")
	for _, n := range []string{"Trash", "Anything", "Foo/Bar"} {
		if m.ShouldHide(n) {
			t.Errorf("%q must NOT be hidden for unrelated user", n)
		}
	}
}

func TestEmptyRulesSafeToUse(t *testing.T) {
	r := &Rules{}
	m := r.For("anyone")
	if m.ShouldHide("Trash") {
		t.Error("empty rules must not hide anything")
	}
}
