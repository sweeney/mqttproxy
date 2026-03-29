package jwt_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	gojwt "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/mqttproxy/internal/jwt"
)

const (
	testIssuer   = "https://id.test.example"
	testAudience = "mqttproxy"
)

// testKeys holds a key pair and a JWK Set of the public key for use in tests.
type testKeys struct {
	priv *rsa.PrivateKey
	set  jwk.Set
	kid  string
}

func generateKeys(t *testing.T) testKeys {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pub, err := jwk.FromRaw(priv.Public())
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, "test-kid-1"))
	require.NoError(t, pub.Set(jwk.AlgorithmKey, jwa.RS256))

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))

	return testKeys{priv: priv, set: set, kid: "test-kid-1"}
}

// buildToken signs a JWT with the given private key and options.
func buildToken(t *testing.T, keys testKeys, opts ...func(gojwt.Token)) []byte {
	t.Helper()
	tok, err := gojwt.NewBuilder().
		Issuer(testIssuer).
		Subject("user-uuid-123").
		Audience([]string{testAudience}).
		Expiration(time.Now().Add(15 * time.Minute)).
		IssuedAt(time.Now()).
		Claim("usr", "alice").
		Claim("rol", "user").
		Claim("act", true).
		Build()
	require.NoError(t, err)

	for _, o := range opts {
		o(tok)
	}

	privKey, err := jwk.FromRaw(keys.priv)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, keys.kid))
	require.NoError(t, privKey.Set(jwk.AlgorithmKey, jwa.RS256))

	signed, err := gojwt.Sign(tok, gojwt.WithKey(jwa.RS256, privKey))
	require.NoError(t, err)
	return signed
}

// staticKeySource implements jwt.KeySource returning a fixed JWK set.
type staticKeySource struct {
	set jwk.Set
}

func (s *staticKeySource) GetKey(_ context.Context, kid string) (jwk.Key, error) {
	k, ok := s.set.LookupKeyID(kid)
	if !ok {
		return nil, jwt.ErrKeyNotFound
	}
	return k, nil
}

func newValidator(t *testing.T, keys testKeys) *jwt.Validator {
	t.Helper()
	v, err := jwt.NewValidator(testIssuer, testAudience, &staticKeySource{set: keys.set})
	require.NoError(t, err)
	return v
}

// --- Tests ---

func TestValidate_ValidToken(t *testing.T) {
	keys := generateKeys(t)
	v := newValidator(t, keys)

	token := buildToken(t, keys)
	claims, err := v.Validate(t.Context(), string(token))
	require.NoError(t, err)

	assert.Equal(t, "user-uuid-123", claims.Subject)
	assert.Equal(t, "alice", claims.Username)
	assert.Equal(t, "user", claims.Role)
	assert.True(t, claims.IsActive)
	assert.WithinDuration(t, time.Now().Add(15*time.Minute), claims.ExpiresAt, 5*time.Second)
}

func TestValidate_AdminRole(t *testing.T) {
	keys := generateKeys(t)
	v := newValidator(t, keys)

	token := buildToken(t, keys, func(tok gojwt.Token) {
		tok.Set("rol", "admin")
	})
	claims, err := v.Validate(t.Context(), string(token))
	require.NoError(t, err)
	assert.Equal(t, "admin", claims.Role)
}

func TestValidate_Expired(t *testing.T) {
	keys := generateKeys(t)
	v := newValidator(t, keys)

	token := buildToken(t, keys, func(tok gojwt.Token) {
		tok.Set(gojwt.ExpirationKey, time.Now().Add(-time.Minute))
	})
	_, err := v.Validate(t.Context(), string(token))
	require.Error(t, err)
	assert.ErrorIs(t, err, jwt.ErrTokenExpired)
}

func TestValidate_InvalidSignature(t *testing.T) {
	keys := generateKeys(t)
	v := newValidator(t, keys)

	token := buildToken(t, keys)
	// Corrupt the signature (last 10 bytes).
	tampered := append([]byte{}, token...)
	for i := len(tampered) - 10; i < len(tampered); i++ {
		tampered[i] ^= 0xFF
	}

	_, err := v.Validate(t.Context(), string(tampered))
	require.Error(t, err)
}

func TestValidate_WrongIssuer(t *testing.T) {
	keys := generateKeys(t)
	v := newValidator(t, keys)

	token := buildToken(t, keys, func(tok gojwt.Token) {
		tok.Set(gojwt.IssuerKey, "https://evil.example")
	})
	_, err := v.Validate(t.Context(), string(token))
	require.Error(t, err)
	assert.ErrorIs(t, err, jwt.ErrInvalidIssuer)
}

func TestValidate_WrongAudience(t *testing.T) {
	keys := generateKeys(t)
	v := newValidator(t, keys)

	token := buildToken(t, keys, func(tok gojwt.Token) {
		tok.Set(gojwt.AudienceKey, []string{"some-other-service"})
	})
	_, err := v.Validate(t.Context(), string(token))
	require.Error(t, err)
	assert.ErrorIs(t, err, jwt.ErrInvalidAudience)
}

func TestValidate_NoAudienceCheck_WhenAudienceEmpty(t *testing.T) {
	keys := generateKeys(t)
	// Validator with no audience configured should not check aud.
	v, err := jwt.NewValidator(testIssuer, "", &staticKeySource{set: keys.set})
	require.NoError(t, err)

	// Token with a different audience — should still pass.
	token := buildToken(t, keys, func(tok gojwt.Token) {
		tok.Set(gojwt.AudienceKey, []string{"unrelated-service"})
	})
	_, err = v.Validate(t.Context(), string(token))
	require.NoError(t, err)
}

func TestValidate_MissingRoleClaim(t *testing.T) {
	keys := generateKeys(t)
	v := newValidator(t, keys)

	privKey, err := jwk.FromRaw(keys.priv)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, keys.kid))
	require.NoError(t, privKey.Set(jwk.AlgorithmKey, jwa.RS256))

	// Build a token without the rol claim.
	tok, err := gojwt.NewBuilder().
		Issuer(testIssuer).
		Subject("user-uuid-123").
		Audience([]string{testAudience}).
		Expiration(time.Now().Add(15 * time.Minute)).
		Claim("usr", "alice").
		Claim("act", true).
		Build()
	require.NoError(t, err)

	signed, err := gojwt.Sign(tok, gojwt.WithKey(jwa.RS256, privKey))
	require.NoError(t, err)

	_, err = v.Validate(t.Context(), string(signed))
	require.Error(t, err)
	assert.ErrorIs(t, err, jwt.ErrMissingClaims)
}

func TestValidate_InactiveUser(t *testing.T) {
	keys := generateKeys(t)
	v := newValidator(t, keys)

	token := buildToken(t, keys, func(tok gojwt.Token) {
		tok.Set("act", false)
	})
	_, err := v.Validate(t.Context(), string(token))
	require.Error(t, err)
	assert.ErrorIs(t, err, jwt.ErrUserInactive)
}

func TestValidate_UnknownKeyID(t *testing.T) {
	keys := generateKeys(t)
	v := newValidator(t, keys)

	// Sign with a different key whose kid is not in the validator's key source.
	otherKeys := generateKeys(t)
	otherPriv, err := jwk.FromRaw(otherKeys.priv)
	require.NoError(t, err)
	require.NoError(t, otherPriv.Set(jwk.KeyIDKey, "unknown-kid"))
	require.NoError(t, otherPriv.Set(jwk.AlgorithmKey, jwa.RS256))

	tok, err := gojwt.NewBuilder().
		Issuer(testIssuer).
		Subject("s").
		Audience([]string{testAudience}).
		Expiration(time.Now().Add(time.Minute)).
		Claim("usr", "u").
		Claim("rol", "user").
		Claim("act", true).
		Build()
	require.NoError(t, err)

	signed, err := gojwt.Sign(tok, gojwt.WithKey(jwa.RS256, otherPriv))
	require.NoError(t, err)

	_, err = v.Validate(t.Context(), string(signed))
	require.Error(t, err)
}

func TestValidate_Malformed(t *testing.T) {
	keys := generateKeys(t)
	v := newValidator(t, keys)

	_, err := v.Validate(t.Context(), "this.is.not.a.jwt")
	require.Error(t, err)
}
