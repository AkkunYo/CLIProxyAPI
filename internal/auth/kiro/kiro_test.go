package kiro_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/kiro"
)

func TestParseOAuthKey_SnakeCase(t *testing.T) {
	payload := map[string]any{
		"refresh_token": "rt-123",
		"access_token":  "at-456",
		"expires_at":    "2030-01-01T00:00:00Z",
		"region":        "us-east-1",
		"idc_region":    "us-east-1",
		"client_id":     "cid",
		"client_secret": "csecret",
		"auth_method":   "social",
		"profile_arn":   "arn:aws:iam::123456789012:role/KiroRole",
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	key, err := kiro.ParseOAuthKey(string(raw))
	if err != nil {
		t.Fatalf("ParseOAuthKey returned unexpected error: %v", err)
	}
	if key.RefreshToken != "rt-123" {
		t.Errorf("RefreshToken = %q, want %q", key.RefreshToken, "rt-123")
	}
	if key.ProfileArn != "arn:aws:iam::123456789012:role/KiroRole" {
		t.Errorf("ProfileArn = %q, want %q", key.ProfileArn, "arn:aws:iam::123456789012:role/KiroRole")
	}
	if key.IDCRegion != "us-east-1" {
		t.Errorf("IDCRegion = %q, want %q", key.IDCRegion, "us-east-1")
	}
	if key.ClientID != "cid" {
		t.Errorf("ClientID = %q, want %q", key.ClientID, "cid")
	}
}

func TestParseOAuthKey_PlainString(t *testing.T) {
	plain := "plain-refresh-token-value"
	key, err := kiro.ParseOAuthKey(plain)
	if err != nil {
		t.Fatalf("ParseOAuthKey returned unexpected error: %v", err)
	}
	if key.RefreshToken != plain {
		t.Errorf("RefreshToken = %q, want %q", key.RefreshToken, plain)
	}
	if key.AccessToken != "" {
		t.Errorf("AccessToken should be empty for plain string, got %q", key.AccessToken)
	}
}

func TestParseOAuthKey_Empty(t *testing.T) {
	_, err := kiro.ParseOAuthKey("")
	if err == nil {
		t.Fatal("expected error for empty string, got nil")
	}
}

func TestOAuthKey_IsExpired_NoToken(t *testing.T) {
	key := &kiro.OAuthKey{AccessToken: ""}
	if !key.IsExpired(30 * time.Second) {
		t.Error("expected IsExpired=true when AccessToken is empty")
	}
}

func TestOAuthKey_IsExpired_Future(t *testing.T) {
	future := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
	key := &kiro.OAuthKey{
		AccessToken: "some-token",
		ExpiresAt:   future,
	}
	if key.IsExpired(30 * time.Second) {
		t.Error("expected IsExpired=false when token expires 1h from now with 30s threshold")
	}
}

func TestOAuthKey_IsExpired_Past(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	key := &kiro.OAuthKey{
		AccessToken: "some-token",
		ExpiresAt:   past,
	}
	if !key.IsExpired(30 * time.Second) {
		t.Error("expected IsExpired=true when token expired 1h ago")
	}
}
