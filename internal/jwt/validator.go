// Package jwt validates MQTT client tokens against the identity service's
// JWKS, adapting identity/common/auth to the claims the proxy needs.
package jwt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	commonauth "github.com/sweeney/identity/common/auth"
)

var (
	ErrTokenExpired  = errors.New("token is expired")
	ErrTokenInvalid  = errors.New("token is invalid")
	ErrMissingClaims = errors.New("token is missing required claims")

	// ErrKeysUnavailable means the token could not be checked, not that it was
	// bad. The distinction matters more here than in an HTTP service: a client
	// told its token is invalid re-authenticates or gives up, whereas one told
	// the service is unavailable should back off and retry. Without this, an
	// identity outage looks to every device like a bad credential.
	ErrKeysUnavailable = errors.New("signing keys unavailable")
)

// Claims holds the fields extracted from a validated JWT.
type Claims struct {
	Subject   string
	Role      string
	ExpiresAt time.Time
}

// Config configures a Validator.
type Config struct {
	// Issuer is the expected iss claim. Required.
	Issuer string
	// IssuerURL is the base URL the JWKS is fetched from, as
	// {IssuerURL}/.well-known/jwks.json. Defaults to Issuer, which is correct
	// whenever identity is not behind a reverse proxy that rewrites its name.
	IssuerURL string
	// Audience, when non-empty, is asserted against the aud claim.
	Audience string
	// DefaultRole is used when the token carries no rol claim. Empty means rol
	// is required. This is the proxy's own policy, not identity's.
	DefaultRole string
	// CacheTTL is how long fetched keys stay valid before a refetch.
	CacheTTL time.Duration
	// HTTPClient is used for JWKS fetches.
	HTTPClient *http.Client
}

// Validator parses and validates JWTs, extracting the claims the proxy needs.
type Validator struct {
	verifier    *commonauth.JWKSVerifier
	defaultRole string
}

// NewValidator creates a Validator from cfg.
func NewValidator(cfg Config) (*Validator, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("issuer must not be empty")
	}
	issuerURL := cfg.IssuerURL
	if issuerURL == "" {
		issuerURL = cfg.Issuer
	}

	verifier, err := commonauth.NewJWKSVerifier(commonauth.JWKSVerifierConfig{
		IssuerURL:        issuerURL,
		Issuer:           cfg.Issuer,
		RequiredAudience: cfg.Audience,
		CacheTTL:         cfg.CacheTTL,
		HTTPClient:       cfg.HTTPClient,
	})
	if err != nil {
		return nil, fmt.Errorf("build verifier: %w", err)
	}

	return &Validator{verifier: verifier, defaultRole: cfg.DefaultRole}, nil
}

// Validate parses the raw JWT, verifies its signature and claims, and returns
// the extracted Claims. Returns a sentinel error for each failure mode so
// callers can log or respond appropriately.
func (v *Validator) Validate(ctx context.Context, rawToken string) (*Claims, error) {
	tc, err := v.verifier.Parse(ctx, rawToken)
	switch {
	case errors.Is(err, commonauth.ErrKeysUnavailable):
		return nil, fmt.Errorf("%w: %v", ErrKeysUnavailable, err)
	case errors.Is(err, commonauth.ErrTokenExpired):
		return nil, fmt.Errorf("%w: %v", ErrTokenExpired, err)
	case err != nil:
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	if tc.UserID == "" {
		return nil, fmt.Errorf("%w: sub", ErrMissingClaims)
	}

	// A token with no exp cannot bound a session. The proxy holds the
	// connection open until the token runs out, so an absent expiry would
	// otherwise read as unix zero and disconnect the client the instant it
	// connected — worse, silently, and only for tokens minted without one.
	if tc.ExpiresAt == 0 {
		return nil, fmt.Errorf("%w: exp", ErrMissingClaims)
	}

	role := v.defaultRole
	if tc.Role != "" {
		role = string(tc.Role)
	}
	if role == "" {
		return nil, fmt.Errorf("%w: rol (and no default_role configured)", ErrMissingClaims)
	}

	return &Claims{
		Subject:   tc.UserID,
		Role:      role,
		ExpiresAt: time.Unix(tc.ExpiresAt, 0),
	}, nil
}
