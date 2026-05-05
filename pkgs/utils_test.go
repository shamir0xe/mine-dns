package utils

import (
	"testing"
)

const idCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func TestGenerateID_Length(t *testing.T) {
	id := GenerateID()
	if len(id) != 8 {
		t.Errorf("expected length 8, got %d", len(id))
	}
}

func TestGenerateID_ValidCharset(t *testing.T) {
	valid := make(map[rune]bool, len(idCharset))
	for _, c := range idCharset {
		valid[c] = true
	}
	for range 200 {
		for _, c := range GenerateID() {
			if !valid[c] {
				t.Errorf("unexpected character %q in generated ID", c)
			}
		}
	}
}
