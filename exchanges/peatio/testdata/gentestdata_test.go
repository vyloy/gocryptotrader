package main

import "testing"

func TestRandomHex(t *testing.T) {
	s, err := randomHex(12)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(s)
}
