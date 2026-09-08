package jwt_test

// These cover the proxy's own policy and the failure modes that are not part
// of the validation contract: role defaulting, which is mqttproxy's decision
// rather than identity's, and malformed or forged input.
//
// The token-shaped fixtures live in contract_test.go.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	gojwt "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/mqttproxy/internal/jwt"
)

const testAudience = "mqttauth"

// newValidatorWithDefaultRole builds a validator with an explicit default
// role, which newContractValidator fixes at "user".
func newValidatorWithDefaultRole(t *testing.T, s *identityStub, defaultRole string) *jwt.Validator {
	t.Helper()
	v, err := jwt.NewValidator(jwt.Config{
		Issuer:      s.URL,
		IssuerURL:   s.URL,
		Audience:    testAudience,
		DefaultRole: defaultRole,
		CacheTTL:    time.Hour,
		HTTPClient:  http.DefaultClient,
	})
	require.NoError(t, err)
	return v
}

func TestValidate_AdminRole(t *testing.T) {
	s := newIdentityStub(t)
	v := newContractValidator(t, s, testAudience)

	raw := s.mint(t, contractKID, func(tok gojwt.Token) {
		require.NoError(t, tok.Set("rol", "admin"))
	})

	claims, err := v.Validate(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, "admin", claims.Role)
}

func TestValidate_MissingRoleClaim_UsesDefault(t *testing.T) {
	s := newIdentityStub(t)
	v := newValidatorWithDefaultRole(t, s, "user")

	raw := s.mint(t, contractKID, func(tok gojwt.Token) {
		require.NoError(t, tok.Remove("rol"))
	})

	claims, err := v.Validate(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, "user", claims.Role)
}

func TestValidate_MissingRoleClaim_NoDefault(t *testing.T) {
	s := newIdentityStub(t)
	v := newValidatorWithDefaultRole(t, s, "")

	raw := s.mint(t, contractKID, func(tok gojwt.Token) {
		require.NoError(t, tok.Remove("rol"))
	})

	_, err := v.Validate(context.Background(), raw)
	require.Error(t, err)
	assert.ErrorIs(t, err, jwt.ErrMissingClaims)
}

func TestValidate_RolePresentOverridesDefault(t *testing.T) {
	s := newIdentityStub(t)
	v := newValidatorWithDefaultRole(t, s, "user")

	raw := s.mint(t, contractKID, func(tok gojwt.Token) {
		require.NoError(t, tok.Set("rol", "admin"))
	})

	claims, err := v.Validate(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, "admin", claims.Role)
}

// A token with no exp cannot bound a session. It must be rejected rather than
// read as unix zero, which would disconnect the client the moment it connected.
func TestValidate_MissingExpiry_Rejected(t *testing.T) {
	s := newIdentityStub(t)
	v := newContractValidator(t, s, testAudience)

	raw := s.mint(t, contractKID, func(tok gojwt.Token) {
		require.NoError(t, tok.Remove(gojwt.ExpirationKey))
	})

	_, err := v.Validate(context.Background(), raw)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "1970")
}

func TestValidate_InvalidSignature(t *testing.T) {
	s := newIdentityStub(t)
	v := newContractValidator(t, s, testAudience)

	// Sign with a key the stub never published, but claim the published kid.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	priv, err := jwk.FromRaw(other)
	require.NoError(t, err)
	require.NoError(t, priv.Set(jwk.KeyIDKey, contractKID))
	require.NoError(t, priv.Set(jwk.AlgorithmKey, jwa.ES256))

	tok, err := gojwt.NewBuilder().
		Issuer(s.URL).
		Subject("user-uuid-123").
		Audience([]string{testAudience}).
		Expiration(time.Now().Add(15*time.Minute)).
		Claim("rol", "user").
		Build()
	require.NoError(t, err)
	signed, err := gojwt.Sign(tok, gojwt.WithKey(jwa.ES256, priv))
	require.NoError(t, err)

	_, err = v.Validate(context.Background(), string(signed))
	require.Error(t, err)
	assert.ErrorIs(t, err, jwt.ErrTokenInvalid)
}

func TestValidate_Malformed(t *testing.T) {
	s := newIdentityStub(t)
	v := newContractValidator(t, s, testAudience)

	for _, raw := range []string{"", "not-a-jwt", "a.b.c"} {
		_, err := v.Validate(context.Background(), raw)
		require.Error(t, err, "expected rejection for %q", raw)
	}
}
