package db

import "testing"

func TestHashTokenDeterministic(t *testing.T) {
	a := HashToken("abc")
	b := HashToken("abc")
	c := HashToken("def")
	if a != b {
		t.Fatalf("expected deterministic hash")
	}
	if a == c {
		t.Fatalf("expected distinct hash")
	}
}
