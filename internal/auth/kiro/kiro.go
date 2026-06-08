package kiro

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// kiroSocialAuthEndpoint is the base URL for Kiro's social authentication service.
	kiroSocialAuthEndpoint = "https://prod.us-east-1.auth.desktop.kiro.dev"
	// kiroOIDCEndpoint is the base URL for AWS OIDC token exchange (builder-id auth).
	kiroOIDCEndpoint = "https://oidc.us-east-1.amazonaws.com"
	// kiroDefaultRegion is the fallback AWS region when none is specified in the key.
	kiroDefaultRegion = "us-east-1"
	// kiroRefreshTimeout is the maximum time allowed for a token refresh HTTP call.
	// Timeouts are only permitted during credential acquisition per project rules.
	kiroRefreshTimeout = 15 * time.Second
)

// OAuthTokenResult holds the refreshed credential material returned after a
// successful token refresh operation.
type OAuthTokenResult struct {
	// AccessToken is the new short-lived bearer token.
	AccessToken string
	// RefreshToken is the (possibly rotated) long-lived refresh token.
	RefreshToken string
	// ExpiresAt is the absolute UTC time when AccessToken expires.
	ExpiresAt time.Time
	// AuthMethod is "social" or "builder-id".
	AuthMethod string
	// Region is the AWS region used for the refresh.
	Region string
	// ProfileArn is the Kiro profile ARN returned by social auth.
	ProfileArn string
	// ClientID is the OIDC client ID used for builder-id auth.
	ClientID string
	// ClientSecret is the OIDC client secret used for builder-id auth.
	ClientSecret string
	// IDCRegion is the IAM Identity Center region.
	IDCRegion string
}

// RefreshToken obtains a new access token using the credentials in key.
//
// The authentication method is resolved as follows:
//  1. If key.AuthMethod is non-empty, it is used directly.
//  2. If key.ClientID and key.ClientSecret are both non-empty, "builder-id" is used.
//  3. Otherwise, "social" is used.
//
// Returns an error when key is nil, required fields are missing, or the HTTP
// exchange fails.
func RefreshToken(ctx context.Context, key *OAuthKey) (*OAuthTokenResult, error) {
	if key == nil {
		return nil, fmt.Errorf("kiro: refresh token: key is nil")
	}

	region := key.Region
	if region == "" {
		region = kiroDefaultRegion
	}

	authMethod := key.AuthMethod
	if authMethod == "" {
		if key.ClientID != "" && key.ClientSecret != "" {
			authMethod = "builder-id"
		} else {
			authMethod = "social"
		}
	}

	switch authMethod {
	case "builder-id":
		if key.ClientID == "" || key.ClientSecret == "" {
			return nil, fmt.Errorf("kiro: refresh token: builder-id requires client_id and client_secret")
		}
		return refreshBuilderIDToken(ctx, key.RefreshToken, key.ClientID, key.ClientSecret, region, key.IDCRegion)
	case "social":
		return refreshSocialToken(ctx, key.RefreshToken, region)
	default:
		return nil, fmt.Errorf("kiro: refresh token: unknown auth_method %q", authMethod)
	}
}

// socialRefreshRequest is the JSON body for a social token refresh call.
type socialRefreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// socialRefreshResponse is the JSON body returned by the social refresh endpoint.
type socialRefreshResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int    `json:"expiresIn"`
	ProfileArn   string `json:"profileArn"`
}

// refreshSocialToken refreshes a Kiro social-auth access token.
func refreshSocialToken(ctx context.Context, refreshToken, region string) (*OAuthTokenResult, error) {
	endpoint := strings.Replace(kiroSocialAuthEndpoint, "us-east-1", region, 1) + "/refreshToken"

	body, err := json.Marshal(socialRefreshRequest{RefreshToken: refreshToken})
	if err != nil {
		return nil, fmt.Errorf("kiro: social refresh: marshal request: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, kiroRefreshTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("kiro: social refresh: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kiro: social refresh: do request: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("kiro: close response body: %v", errClose)
		}
	}()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("kiro: social refresh: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kiro: social refresh: unexpected status %d: %s", resp.StatusCode, string(respBytes))
	}

	var parsed socialRefreshResponse
	if err = json.Unmarshal(respBytes, &parsed); err != nil {
		return nil, fmt.Errorf("kiro: social refresh: parse response: %w", err)
	}

	newRefreshToken := parsed.RefreshToken
	if newRefreshToken == "" {
		newRefreshToken = refreshToken
	}

	var expiresAt time.Time
	if parsed.ExpiresIn > 0 {
		expiresAt = time.Now().UTC().Add(time.Duration(parsed.ExpiresIn) * time.Second)
	}

	return &OAuthTokenResult{
		AccessToken:  parsed.AccessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    expiresAt,
		AuthMethod:   "social",
		Region:       region,
		ProfileArn:   parsed.ProfileArn,
	}, nil
}

// builderIDRefreshResponse is the JSON body returned by the OIDC token endpoint.
type builderIDRefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// refreshBuilderIDToken refreshes a Kiro builder-id access token via AWS OIDC.
func refreshBuilderIDToken(ctx context.Context, refreshToken, clientID, clientSecret, region, idcRegion string) (*OAuthTokenResult, error) {
	endpoint := strings.Replace(kiroOIDCEndpoint, "us-east-1", region, 1) + "/token"

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)

	reqCtx, cancel := context.WithTimeout(ctx, kiroRefreshTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("kiro: builder-id refresh: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kiro: builder-id refresh: do request: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("kiro: close response body: %v", errClose)
		}
	}()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("kiro: builder-id refresh: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kiro: builder-id refresh: unexpected status %d: %s", resp.StatusCode, string(respBytes))
	}

	var parsed builderIDRefreshResponse
	if err = json.Unmarshal(respBytes, &parsed); err != nil {
		return nil, fmt.Errorf("kiro: builder-id refresh: parse response: %w", err)
	}

	newRefreshToken := parsed.RefreshToken
	if newRefreshToken == "" {
		newRefreshToken = refreshToken
	}

	var expiresAt time.Time
	if parsed.ExpiresIn > 0 {
		expiresAt = time.Now().UTC().Add(time.Duration(parsed.ExpiresIn) * time.Second)
	}

	return &OAuthTokenResult{
		AccessToken:  parsed.AccessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    expiresAt,
		AuthMethod:   "builder-id",
		Region:       region,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		IDCRegion:    idcRegion,
	}, nil
}

// registerClientResponse is the JSON body returned by the OIDC registerClient endpoint.
type registerClientResponse struct {
	ClientID              string `json:"clientId"`
	ClientSecret          string `json:"clientSecret"`
	ClientIDIssuedAt      int64  `json:"clientIdIssuedAt"`
	ClientSecretExpiresAt int64  `json:"clientSecretExpiresAt"`
}

// DeviceAuthorizationFlow holds the device authorization response.
type DeviceAuthorizationFlow struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	ExpiresIn               int    `json:"expiresIn"`
	Interval                int    `json:"interval"`
	// ClientID and ClientSecret from the registerClient step, carried for the token poll.
	ClientID     string `json:"-"`
	ClientSecret string `json:"-"`
}

// StartDeviceFlow registers an OIDC client, then initiates AWS Builder ID device authorization.
func StartDeviceFlow(ctx context.Context, region string) (*DeviceAuthorizationFlow, error) {
	if region == "" {
		region = kiroDefaultRegion
	}

	base := strings.Replace(kiroOIDCEndpoint, "us-east-1", region, 1)

	// Step 1: register a dynamic OIDC client.
	regBody, err := json.Marshal(map[string]any{
		"clientName": "kiro-cli-proxy",
		"clientType": "public",
		"scopes":     []string{"openid", "sso:account:access"},
	})
	if err != nil {
		return nil, fmt.Errorf("kiro: device auth: marshal register request: %w", err)
	}

	regReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/client/register", bytes.NewReader(regBody))
	if err != nil {
		return nil, fmt.Errorf("kiro: device auth: create register request: %w", err)
	}
	regReq.Header.Set("Content-Type", "application/json")

	regResp, err := http.DefaultClient.Do(regReq)
	if err != nil {
		return nil, fmt.Errorf("kiro: device auth: register client: %w", err)
	}
	regBytes, err := io.ReadAll(regResp.Body)
	_ = regResp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("kiro: device auth: read register response: %w", err)
	}
	if regResp.StatusCode != http.StatusCreated && regResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kiro: device auth: register client status %d: %s", regResp.StatusCode, string(regBytes))
	}

	var regParsed registerClientResponse
	if err = json.Unmarshal(regBytes, &regParsed); err != nil {
		return nil, fmt.Errorf("kiro: device auth: parse register response: %w", err)
	}
	if regParsed.ClientID == "" {
		return nil, fmt.Errorf("kiro: device auth: register client returned empty clientId: %s", string(regBytes))
	}

	// Step 2: start device authorization.
	authBody, err := json.Marshal(map[string]any{
		"clientId":     regParsed.ClientID,
		"clientSecret": regParsed.ClientSecret,
		"startUrl":     "https://view.awsapps.com/start",
	})
	if err != nil {
		return nil, fmt.Errorf("kiro: device auth: marshal auth request: %w", err)
	}

	authReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/device_authorization", bytes.NewReader(authBody))
	if err != nil {
		return nil, fmt.Errorf("kiro: device auth: create auth request: %w", err)
	}
	authReq.Header.Set("Content-Type", "application/json")

	authResp, err := http.DefaultClient.Do(authReq)
	if err != nil {
		return nil, fmt.Errorf("kiro: device auth: start device authorization: %w", err)
	}
	authBytes, err := io.ReadAll(authResp.Body)
	_ = authResp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("kiro: device auth: read auth response: %w", err)
	}
	if authResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kiro: device auth: start device authorization status %d: %s", authResp.StatusCode, string(authBytes))
	}

	var flow DeviceAuthorizationFlow
	if err = json.Unmarshal(authBytes, &flow); err != nil {
		return nil, fmt.Errorf("kiro: device auth: parse auth response: %w", err)
	}

	if flow.Interval == 0 {
		flow.Interval = 5
	}
	flow.ClientID = regParsed.ClientID
	flow.ClientSecret = regParsed.ClientSecret

	return &flow, nil
}

// deviceTokenResponse is the JSON body returned by the device token endpoint.
type deviceTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int    `json:"expiresIn"`
	TokenType    string `json:"tokenType"`
	Error        string `json:"error"`
}

// WaitForDeviceAuthorization polls the token endpoint until the user completes authorization.
func WaitForDeviceAuthorization(ctx context.Context, flow *DeviceAuthorizationFlow, region string) (*OAuthTokenResult, error) {
	if flow == nil {
		return nil, fmt.Errorf("kiro: device auth: flow is nil")
	}
	if region == "" {
		region = kiroDefaultRegion
	}

	base := strings.Replace(kiroOIDCEndpoint, "us-east-1", region, 1)
	endpoint := base + "/token"
	interval := time.Duration(flow.Interval) * time.Second
	deadline := time.Now().Add(time.Duration(flow.ExpiresIn) * time.Second)

	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("kiro: device auth: timeout")
		}

		tokenBody, err := json.Marshal(map[string]any{
			"grantType":    "urn:ietf:params:oauth:grant-type:device_code",
			"deviceCode":   flow.DeviceCode,
			"clientId":     flow.ClientID,
			"clientSecret": flow.ClientSecret,
		})
		if err != nil {
			return nil, fmt.Errorf("kiro: device token: marshal request: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(tokenBody))
		if err != nil {
			return nil, fmt.Errorf("kiro: device token: create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("kiro: device token: do request: %w", err)
		}

		respBytes, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("kiro: device token: read response: %w", err)
		}

		var parsed deviceTokenResponse
		if err = json.Unmarshal(respBytes, &parsed); err != nil {
			return nil, fmt.Errorf("kiro: device token: parse response: %w", err)
		}

		if parsed.Error == "authorization_pending" {
			time.Sleep(interval)
			continue
		}

		if parsed.Error == "slow_down" {
			interval += 5 * time.Second
			time.Sleep(interval)
			continue
		}

		if parsed.Error != "" {
			return nil, fmt.Errorf("kiro: device token: %s", parsed.Error)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("kiro: device token: unexpected status %d: %s", resp.StatusCode, string(respBytes))
		}

		if parsed.AccessToken == "" {
			return nil, fmt.Errorf("kiro: device token: empty access token")
		}

		var expiresAt time.Time
		if parsed.ExpiresIn > 0 {
			expiresAt = time.Now().UTC().Add(time.Duration(parsed.ExpiresIn) * time.Second)
		}

		return &OAuthTokenResult{
			AccessToken:  parsed.AccessToken,
			RefreshToken: parsed.RefreshToken,
			ExpiresAt:    expiresAt,
			AuthMethod:   "builder-id",
			Region:       region,
			ClientID:     flow.ClientID,
			ClientSecret: flow.ClientSecret,
		}, nil
	}
}
