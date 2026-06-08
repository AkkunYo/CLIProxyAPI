package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	kiroauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/kiro"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// kiroRefreshLead is the duration before token expiry when refresh should occur.
var kiroRefreshLead = 5 * time.Minute

// KiroAuthenticator implements the Authenticator interface for Kiro (Amazon Q).
type KiroAuthenticator struct{}

// NewKiroAuthenticator constructs a new Kiro authenticator.
func NewKiroAuthenticator() Authenticator {
	return &KiroAuthenticator{}
}

// Provider returns the provider key for kiro.
func (KiroAuthenticator) Provider() string {
	return "kiro"
}

// RefreshLead returns the duration before token expiry when refresh should occur.
func (KiroAuthenticator) RefreshLead() *time.Duration {
	return &kiroRefreshLead
}

// Login initiates Kiro OAuth via AWS Builder ID device authorization flow.
func (a KiroAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if opts == nil {
		opts = &LoginOptions{}
	}

	region := "us-east-1"
	_ = cfg // region hardcoded; no AWS region field in config

	fmt.Println("Initializing Kiro (Amazon Q) authentication...")

	deviceFlow, err := kiroauth.StartDeviceFlow(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("kiro: start device flow: %w", err)
	}

	authURL := deviceFlow.VerificationURIComplete
	if authURL == "" {
		authURL = deviceFlow.VerificationURI
	}

	fmt.Printf("\nVisit this URL to authorize:\n%s\n", authURL)
	if deviceFlow.UserCode != "" {
		fmt.Printf("User code: %s\n", deviceFlow.UserCode)
	}
	fmt.Println("\nWaiting for authorization...")

	if !opts.NoBrowser {
		if browser.IsAvailable() {
			if errOpen := browser.OpenURL(authURL); errOpen != nil {
				log.Warnf("Failed to open browser: %v", errOpen)
			} else {
				fmt.Println("Opened browser for authentication")
			}
		}
	}

	result, err := kiroauth.WaitForDeviceAuthorization(ctx, deviceFlow, region)
	if err != nil {
		return nil, fmt.Errorf("kiro: wait for authorization: %w", err)
	}

	metadata := map[string]any{
		"type":          "kiro",
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"auth_method":   result.AuthMethod,
		"region":        result.Region,
	}
	if !result.ExpiresAt.IsZero() {
		metadata["expires_at"] = result.ExpiresAt.Format(time.RFC3339)
	}
	if result.ProfileArn != "" {
		metadata["profile_arn"] = result.ProfileArn
	}
	if result.ClientID != "" {
		metadata["client_id"] = result.ClientID
	}
	if result.ClientSecret != "" {
		metadata["client_secret"] = result.ClientSecret
	}
	if result.IDCRegion != "" {
		metadata["idc_region"] = result.IDCRegion
	}

	label := "Kiro"
	if result.AuthMethod == "builder-id" {
		label = "AWS Builder ID"
	}

	fileName := fmt.Sprintf("kiro-%d.json", time.Now().UnixMilli())

	auth := &coreauth.Auth{
		ID:              fileName,
		Provider:        "kiro",
		FileName:        fileName,
		Label:           label,
		Metadata:        metadata,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		LastRefreshedAt: time.Now(),
	}

	fmt.Println("\nAuthentication successful!")
	return auth, nil
}

// Refresh reads the refresh_token from existing.Metadata, calls kiroauth.RefreshToken,
// and returns an updated Auth clone with the new credential material.
func (a KiroAuthenticator) Refresh(ctx context.Context, _ *config.Config, existing *coreauth.Auth) (*coreauth.Auth, error) {
	if existing == nil {
		return nil, fmt.Errorf("kiro: existing auth is nil")
	}

	refreshToken := kiroMetaStr(existing.Metadata, "refresh_token")
	if refreshToken == "" {
		return nil, fmt.Errorf("kiro: no refresh_token in metadata")
	}

	key := &kiroauth.OAuthKey{
		AccessToken:  kiroMetaStr(existing.Metadata, "access_token"),
		RefreshToken: refreshToken,
		ExpiresAt:    kiroMetaStr(existing.Metadata, "expires_at"),
		AuthMethod:   kiroMetaStr(existing.Metadata, "auth_method"),
		Region:       kiroMetaStr(existing.Metadata, "region"),
		ClientID:     kiroMetaStr(existing.Metadata, "client_id"),
		ClientSecret: kiroMetaStr(existing.Metadata, "client_secret"),
		IDCRegion:    kiroMetaStr(existing.Metadata, "idc_region"),
		ProfileArn:   kiroMetaStr(existing.Metadata, "profile_arn"),
	}

	result, err := kiroauth.RefreshToken(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("kiro: refresh token: %w", err)
	}

	updated := existing.Clone()
	if updated.Metadata == nil {
		updated.Metadata = make(map[string]any)
	}
	updated.Metadata["access_token"] = result.AccessToken
	updated.Metadata["refresh_token"] = result.RefreshToken
	if !result.ExpiresAt.IsZero() {
		updated.Metadata["expires_at"] = result.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if strings.TrimSpace(result.ProfileArn) != "" {
		updated.Metadata["profile_arn"] = result.ProfileArn
	}
	updated.LastRefreshedAt = time.Now()

	return updated, nil
}

// kiroMetaStr extracts a trimmed string value from a metadata map.
// Returns an empty string if the key is missing or the value is not a string.
func kiroMetaStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}
