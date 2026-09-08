package jwt_test

// Contract tests describe what the proxy needs from token validation,
// independent of which library provides it. They must pass before and after
// the swap to identity/common/auth, so they avoid anything implementation
// specific:
//
//   - ES256, because common/auth is ECDSA-only (it pins the algorithm rather
//     than trusting the one the JWKS key declares).
//   - a real JWKS endpoint over HTTP, not an injected KeySource, because that
//     interface does not survive the swap.
//   - rejection asserted as "an error", not as a particular sentinel, except
//     for expiry — which stays distinguishable on both sides because callers
//     act on it.
//
// newContractValidator is the single seam. It is the only thing in this file
// that B3 rewrites.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	gojwt "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/mqttproxy/internal/jwks"
	"github.com/sweeney/mqttproxy/internal/jwt"
)

const contractKID = "contract-kid-1"

// identityStub serves the two endpoints an identity service exposes: the
// well-known discovery document and the JWKS itself. Serving both means the
// same stub works for discovery-based lookup today and for the verifier's
// {IssuerURL}/.well-known/jwks.json convention afterwards.
type identityStub struct {
	*httptest.Server
	priv *ecdsa.PrivateKey
}

func newIdentityStub(t *testing.T) *identityStub {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pub, err := jwk.FromRaw(priv.Public())
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, contractKID))
	require.NoError(t, pub.Set(jwk.AlgorithmKey, jwa.ES256))
	require.NoError(t, pub.Set(jwk.KeyUsageKey, "sig"))

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))
	jwksJSON, err := json.Marshal(set)
	require.NoError(t, err)

	stub := &identityStub{priv: priv}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":"%s/.well-known/jwks.json"}`, stub.URL, stub.URL)
	})
	stub.Server = httptest.NewServer(mux)
	t.Cleanup(stub.Close)
	return stub
}

// mint signs an ES256 token carrying the claims identity stamps on a user
// access token. Options mutate the token before signing.
func (s *identityStub) mint(t *testing.T, kid string, opts ...func(gojwt.Token)) string {
	t.Helper()

	tok, err := gojwt.NewBuilder().
		Issuer(s.URL).
		Subject("user-uuid-123").
		Audience([]string{testAudience}).
		Expiration(time.Now().Add(15*time.Minute)).
		IssuedAt(time.Now()).
		Claim("usr", "alice").
		Claim("rol", "user").
		Claim("act", true).
		Build()
	require.NoError(t, err)

	for _, o := range opts {
		o(tok)
	}

	priv, err := jwk.FromRaw(s.priv)
	require.NoError(t, err)
	require.NoError(t, priv.Set(jwk.KeyIDKey, kid))
	require.NoError(t, priv.Set(jwk.AlgorithmKey, jwa.ES256))

	signed, err := gojwt.Sign(tok, gojwt.WithKey(jwa.ES256, priv))
	require.NoError(t, err)
	return string(signed)
}

// newContractValidator builds a validator against the stub. This is the seam:
// after the swap its body becomes a commonauth.JWKSVerifier, and every test
// below is unchanged.
func newContractValidator(t *testing.T, s *identityStub, audience string) *jwt.Validator {
	t.Helper()

	client, err := jwks.NewClient(s.URL+"/.well-known/oauth-authorization-server", time.Hour, http.DefaultClient)
	require.NoError(t, err)

	v, err := jwt.NewValidator(s.URL, audience, "user", client)
	require.NoError(t, err)
	return v
}

func TestContract_ValidToken_YieldsSubjectRoleExpiry(t *testing.T) {
	s := newIdentityStub(t)
	v := newContractValidator(t, s, testAudience)

	exp := time.Now().Add(15 * time.Minute)
	raw := s.mint(t, contractKID, func(tok gojwt.Token) {
		require.NoError(t, tok.Set(gojwt.ExpirationKey, exp))
	})

	claims, err := v.Validate(context.Background(), raw)
	require.NoError(t, err)

	// The proxy needs exactly these three: who, what they may do, and when to
	// hang up on them.
	assert.Equal(t, "user-uuid-123", claims.Subject)
	assert.Equal(t, "user", claims.Role)
	assert.WithinDuration(t, exp, claims.ExpiresAt, time.Second)
}

func TestContract_WrongAudience_Rejected(t *testing.T) {
	s := newIdentityStub(t)
	v := newContractValidator(t, s, testAudience)

	raw := s.mint(t, contractKID, func(tok gojwt.Token) {
		require.NoError(t, tok.Set(gojwt.AudienceKey, []string{"someone-else"}))
	})

	_, err := v.Validate(context.Background(), raw)
	require.Error(t, err)
}

func TestContract_WrongIssuer_Rejected(t *testing.T) {
	s := newIdentityStub(t)
	v := newContractValidator(t, s, testAudience)

	raw := s.mint(t, contractKID, func(tok gojwt.Token) {
		require.NoError(t, tok.Set(gojwt.IssuerKey, "https://evil.example"))
	})

	_, err := v.Validate(context.Background(), raw)
	require.Error(t, err)
}

func TestContract_Expired_Rejected(t *testing.T) {
	s := newIdentityStub(t)
	v := newContractValidator(t, s, testAudience)

	raw := s.mint(t, contractKID, func(tok gojwt.Token) {
		require.NoError(t, tok.Set(gojwt.ExpirationKey, time.Now().Add(-time.Minute)))
	})

	_, err := v.Validate(context.Background(), raw)
	require.Error(t, err)
	// Expiry stays distinguishable on both sides: an expired token means
	// "re-authenticate", which is not the same advice as "your token is junk".
	assert.ErrorIs(t, err, jwt.ErrTokenExpired)
}

func TestContract_UnknownKid_Rejected(t *testing.T) {
	s := newIdentityStub(t)
	v := newContractValidator(t, s, testAudience)

	raw := s.mint(t, "kid-that-was-never-published")

	_, err := v.Validate(context.Background(), raw)
	require.Error(t, err)
}

// TestContract_NoAudienceConfigured_SkipsAudCheck pins the "omit to skip"
// behaviour the config documents, which RequiredAudience preserves.
func TestContract_NoAudienceConfigured_SkipsAudCheck(t *testing.T) {
	s := newIdentityStub(t)
	v := newContractValidator(t, s, "")

	raw := s.mint(t, contractKID, func(tok gojwt.Token) {
		require.NoError(t, tok.Set(gojwt.AudienceKey, []string{"anything-at-all"}))
	})

	_, err := v.Validate(context.Background(), raw)
	require.NoError(t, err)
}
