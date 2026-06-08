// Package kiro provides authentication and token management for Kiro (Amazon Q)
// services. It handles OAuth key parsing, token expiry checks, and token storage
// for both social and builder-id authentication methods.
package kiro

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	log "github.com/sirupsen/logrus"
)

// OAuthKey holds the credential material for authenticating with Kiro.
// It supports two authentication methods: "social" (Kiro-hosted OAuth) and
// "builder-id" (AWS IAM Identity Center / OIDC).
type OAuthKey struct {
	// RefreshToken is the long-lived token used to obtain new access tokens.
	RefreshToken string `json:"refresh_token"`
	// AccessToken is the short-lived bearer token for API calls.
	AccessToken string `json:"access_token"`
	// ExpiresAt is an RFC3339 timestamp indicating when AccessToken expires.
	ExpiresAt string `json:"expires_at"`
	// Region is the AWS region for Kiro endpoints, e.g. "us-east-1".
	Region string `json:"region"`
	// IDCRegion is the IAM Identity Center region for builder-id auth.
	IDCRegion string `json:"idc_region"`
	// ClientID is the OIDC client identifier used for builder-id auth.
	ClientID string `json:"client_id"`
	// ClientSecret is the OIDC client secret used for builder-id auth.
	ClientSecret string `json:"client_secret"`
	// AuthMethod explicitly selects "social" or "builder-id".
	// When empty, the method is auto-detected from ClientID/ClientSecret.
	AuthMethod string `json:"auth_method"`
	// ProfileArn is the ARN of the Kiro profile returned after social auth.
	ProfileArn string `json:"profile_arn"`
}

// ParseOAuthKey parses a credential string into an OAuthKey.
//
// Supported formats:
//   - Empty string: returns an error.
//   - JSON object (starts with '{'): unmarshaled into OAuthKey.
//   - Anything else: treated as a plain refresh token.
func ParseOAuthKey(keyStr string) (*OAuthKey, error) {
	if keyStr == "" {
		return nil, fmt.Errorf("kiro: empty key")
	}
	if !strings.HasPrefix(keyStr, "{") {
		return &OAuthKey{RefreshToken: keyStr}, nil
	}
	var key OAuthKey
	if err := json.Unmarshal([]byte(keyStr), &key); err != nil {
		return nil, fmt.Errorf("kiro: parse oauth key: %w", err)
	}
	return &key, nil
}

// IsExpired reports whether the access token has expired or will expire within
// the given threshold duration.
//
// Special cases:
//   - AccessToken is empty: always returns true (no usable token).
//   - ExpiresAt is empty: returns false (no expiry information, assume valid).
//   - ExpiresAt cannot be parsed: returns true (treat as expired).
func (k *OAuthKey) IsExpired(threshold time.Duration) bool {
	if k.AccessToken == "" {
		return true
	}
	if k.ExpiresAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, k.ExpiresAt)
	if err != nil {
		log.Warnf("kiro: failed to parse expires_at %q: %v", k.ExpiresAt, err)
		return true
	}
	return time.Until(t) < threshold
}

// KiroTokenStorage persists Kiro OAuth credentials to a JSON file on disk.
// It implements the baseauth.TokenStorage interface.
type KiroTokenStorage struct {
	// Type identifies the provider; always "kiro" when saved.
	Type string `json:"type"`
	// RefreshToken is the long-lived refresh token.
	RefreshToken string `json:"refresh_token"`
	// AccessToken is the short-lived bearer token.
	AccessToken string `json:"access_token"`
	// ExpiresAt is an RFC3339 timestamp when AccessToken expires.
	ExpiresAt string `json:"expires_at"`
	// Region is the AWS region for Kiro endpoints.
	Region string `json:"region"`
	// IDCRegion is the IAM Identity Center region.
	IDCRegion string `json:"idc_region"`
	// ClientID is the OIDC client identifier.
	ClientID string `json:"client_id"`
	// ClientSecret is the OIDC client secret.
	ClientSecret string `json:"client_secret"`
	// AuthMethod is "social" or "builder-id".
	AuthMethod string `json:"auth_method"`
	// ProfileArn is the ARN of the Kiro profile.
	ProfileArn string `json:"profile_arn"`

	// Metadata holds arbitrary key-value pairs injected via hooks.
	// It is not exported to JSON directly to allow flattening during serialization.
	Metadata map[string]any `json:"-"`
}

// SetMetadata allows external callers to inject metadata into the storage before saving.
func (ts *KiroTokenStorage) SetMetadata(meta map[string]any) {
	ts.Metadata = meta
}

// SaveTokenToFile serializes the Kiro token storage to a JSON file at authFilePath.
func (ts *KiroTokenStorage) SaveTokenToFile(authFilePath string) error {
	misc.LogSavingCredentials(authFilePath)
	ts.Type = "kiro"

	if err := os.MkdirAll(filepath.Dir(authFilePath), 0o700); err != nil {
		return fmt.Errorf("kiro: create directory: %w", err)
	}

	file, err := os.Create(authFilePath)
	if err != nil {
		return fmt.Errorf("kiro: create token file: %w", err)
	}
	defer func() {
		if errClose := file.Close(); errClose != nil {
			log.Errorf("kiro: close token file: %v", errClose)
		}
	}()

	data, errMerge := misc.MergeMetadata(ts, ts.Metadata)
	if errMerge != nil {
		return fmt.Errorf("kiro: merge metadata: %w", errMerge)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(data); err != nil {
		return fmt.Errorf("kiro: write token file: %w", err)
	}
	return nil
}
