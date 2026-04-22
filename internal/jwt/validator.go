// Package jwt validates MQTT client tokens against a JWKS key source.
package jwt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	gojwt "github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	ErrTokenExpired    = errors.New("token is expired")
	ErrInvalidIssuer   = errors.New("token issuer does not match")
	ErrInvalidAudience = errors.New("token audience does not match")
	ErrMissingClaims   = errors.New("token is missing required claims")
	ErrKeyNotFound     = errors.New("key not found")
)

// Claims holds the fields extracted from a validated JWT.
type Claims struct {
	Subject   string
	Role      string
	ExpiresAt time.Time
}

// KeySource is the interface the Validator uses to look up public keys by key
// ID. jwks.Client satisfies this interface directly.
type KeySource interface {
	GetKey(ctx context.Context, kid string) (jwk.Key, error)
}

// Validator parses and validates JWTs, extracting the claims the proxy needs.
type Validator struct {
	issuer      string
	audience    string
	defaultRole string
	keySource   KeySource
}

// NewValidator creates a Validator for the given issuer, audience, and default
// role. audience may be empty, in which case the aud claim is not validated.
// defaultRole is used when the token carries no rol claim; an empty defaultRole
// means rol is required.
func NewValidator(issuer, audience, defaultRole string, keySource KeySource) (*Validator, error) {
	if issuer == "" {
		return nil, fmt.Errorf("issuer must not be empty")
	}
	return &Validator{issuer: issuer, audience: audience, defaultRole: defaultRole, keySource: keySource}, nil
}

// Validate parses the raw JWT string, verifies its signature and claims, and
// returns the extracted Claims. Returns a sentinel error for each failure mode
// so callers can log or respond appropriately.
func (v *Validator) Validate(ctx context.Context, rawToken string) (*Claims, error) {
	// Parse the JWS message to extract the kid from the JOSE protected header.
	// kid lives in the header, not the payload, so ParseInsecure would not see it.
	msg, err := jws.Parse([]byte(rawToken))
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	if len(msg.Signatures()) == 0 {
		return nil, fmt.Errorf("parse token: no signatures")
	}
	kid := msg.Signatures()[0].ProtectedHeaders().KeyID()

	key, err := v.keySource.GetKey(ctx, kid) //nolint:contextcheck
	if err != nil {
		return nil, fmt.Errorf("get signing key: %w", err)
	}

	// Use the algorithm declared on the key itself rather than hardcoding one,
	// so the validator works with both ES256 (id.swee.net) and RS256.
	parseOpts := []gojwt.ParseOption{
		gojwt.WithKey(key.Algorithm(), key),
		gojwt.WithValidate(true),
		gojwt.WithIssuer(v.issuer),
	}
	if v.audience != "" {
		parseOpts = append(parseOpts, gojwt.WithAudience(v.audience))
	}
	tok, err := gojwt.Parse([]byte(rawToken), parseOpts...)
	if err != nil {
		return nil, mapParseError(err)
	}

	return v.extractClaims(tok)
}

// mapParseError converts lestrrat-go/jwx errors into our sentinel types.
func mapParseError(err error) error {
	msg := err.Error()
	switch {
	case contains(msg, `"exp" not satisfied`, "token is expired"):
		return fmt.Errorf("%w: %v", ErrTokenExpired, err)
	case contains(msg, `"iss" not satisfied`):
		return fmt.Errorf("%w: %v", ErrInvalidIssuer, err)
	case contains(msg, `"aud" not satisfied`):
		return fmt.Errorf("%w: %v", ErrInvalidAudience, err)
	default:
		return err
	}
}

func contains(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

const claimRole = "rol"

func (v *Validator) extractClaims(tok gojwt.Token) (*Claims, error) {
	subject := tok.Subject()
	if subject == "" {
		return nil, fmt.Errorf("%w: sub", ErrMissingClaims)
	}

	role := v.defaultRole
	if r, ok := stringClaim(tok, claimRole); ok && r != "" {
		role = r
	}
	if role == "" {
		return nil, fmt.Errorf("%w: rol (and no default_role configured)", ErrMissingClaims)
	}

	return &Claims{
		Subject:   subject,
		Role:      role,
		ExpiresAt: tok.Expiration(),
	}, nil
}

func stringClaim(tok gojwt.Token, key string) (string, bool) {
	v, ok := tok.Get(key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}
