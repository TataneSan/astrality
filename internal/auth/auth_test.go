package auth

import (
	"context"
	"testing"

	"astrality/internal/config"
)

func TestDevAuthenticate(t *testing.T) {
	a, err := New(context.Background(), config.Config{
		DevBearerAdmin:    "a",
		DevBearerOperator: "o",
		DevBearerViewer:   "v",
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.Authenticate(context.Background(), "Bearer a")
	if err != nil {
		t.Fatal(err)
	}
	if p.Role != "admin" {
		t.Fatalf("expected admin, got %s", p.Role)
	}
}

func TestHasRole(t *testing.T) {
	if !HasRole("admin", "viewer") {
		t.Fatal("admin should satisfy viewer")
	}
	if HasRole("viewer", "operator") {
		t.Fatal("viewer should not satisfy operator")
	}
}
