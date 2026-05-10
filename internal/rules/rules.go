// Copyright (C) 2026 Benjamin Albreht
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package rules expresses which mailbox names are hidden from which
// authenticated user. Inputs are plain UTF-8 (the filter layer is
// responsible for decoding modified-UTF-7 wire names before matching).
//
// Semantics
//
//   - INBOX (case-insensitive) is hardcoded to never be hidden.
//   - Each entry in Hide matches the named mailbox AND any descendant
//     under the "/" delimiter, but NOT mailboxes that merely share a
//     prefix substring (e.g. "Trash" hides "Trash/Old" but not "TrashCan").
//   - HidePersonal hides every name that is not under any of
//     SharedPrefixes — except INBOX.
//   - When several user rules match (exact user name and the "*"
//     wildcard), their Hide lists are unioned.
//   - HidePersonal defaults from wildcard rules, but any exact-user
//     HidePersonal entries override the wildcard value.
//   - With no matching rule, nothing is hidden.
package rules

import "strings"

// Rules is the parsed configuration: a global namespace setting plus the
// list of per-user rule blocks.
type Rules struct {
	// SharedPrefixes lists the path prefixes (each ending in "/") that mark
	// the shared-folder namespace and are therefore exempt from
	// HidePersonal. Typical values: "Shared Folders/", "Other Users/".
	SharedPrefixes []string
	Users          []UserRule
}

// UserRule is one [[rules]] block from the config file.
type UserRule struct {
	// User is the authenticated username this block applies to. The
	// literal "*" matches every user.
	User string
	// Hide lists mailbox names to hide; cascades to descendants.
	Hide []string
	// HidePersonal hides every non-shared, non-INBOX mailbox when non-nil.
	HidePersonal *bool
}

// Matcher is the per-user compiled form, suitable for hot-path lookups.
type Matcher struct {
	hide           []string
	hidePersonal   bool
	sharedPrefixes []string
}

// For returns a Matcher with all rules applicable to user merged in.
func (r *Rules) For(user string) *Matcher {
	m := &Matcher{sharedPrefixes: r.SharedPrefixes}
	baseHidePersonal := false
	exactHasHidePersonal := false
	exactHidePersonal := false
	for _, ur := range r.Users {
		if ur.User != "*" && ur.User != user {
			continue
		}
		m.hide = append(m.hide, ur.Hide...)
		if ur.HidePersonal == nil {
			continue
		}
		if ur.User == "*" {
			baseHidePersonal = baseHidePersonal || *ur.HidePersonal
			continue
		}
		exactHasHidePersonal = true
		exactHidePersonal = exactHidePersonal || *ur.HidePersonal
	}
	if exactHasHidePersonal {
		m.hidePersonal = exactHidePersonal
	} else {
		m.hidePersonal = baseHidePersonal
	}
	return m
}

// ShouldHide reports whether name is hidden under this matcher.
func (m *Matcher) ShouldHide(name string) bool {
	hidden, _ := m.HideDecision(name)
	return hidden
}

// HideDecision reports whether name is hidden and a short reason code.
func (m *Matcher) HideDecision(name string) (bool, string) {
	if strings.EqualFold(name, "INBOX") {
		return false, "inbox-exempt"
	}
	for _, h := range m.hide {
		if name == h || strings.HasPrefix(name, h+"/") {
			return true, "hide-rule"
		}
	}
	if m.hidePersonal {
		shared := false
		for _, p := range m.sharedPrefixes {
			if strings.HasPrefix(name, p) {
				shared = true
				break
			}
		}
		if !shared {
			return true, "hide-personal"
		}
	}
	return false, "visible"
}
