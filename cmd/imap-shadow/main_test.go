package main

import (
	"reflect"
	"testing"
)

func TestUniqueHostnames(t *testing.T) {
	got := uniqueHostnames([]string{
		"mail.example.com",
		"",
		"mail.example.com",
		"imap.example.com",
		"imap.example.com",
	})
	want := []string{"mail.example.com", "imap.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("uniqueHostnames()=%v want %v", got, want)
	}
}
