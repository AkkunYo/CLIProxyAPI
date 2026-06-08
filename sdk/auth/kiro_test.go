package auth_test

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
)

func TestKiroAuthenticatorProvider(t *testing.T) {
	a := auth.NewKiroAuthenticator()
	if a.Provider() != "kiro" {
		t.Fatalf("Provider() = %q, want \"kiro\"", a.Provider())
	}
}

func TestKiroAuthenticatorRefreshLead(t *testing.T) {
	a := auth.NewKiroAuthenticator()
	lead := a.RefreshLead()
	if lead == nil {
		t.Fatal("RefreshLead() = nil, want non-nil")
	}
	if *lead <= 0 {
		t.Fatalf("RefreshLead() = %v, want positive duration", *lead)
	}
}
