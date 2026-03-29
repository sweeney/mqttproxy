package jwks_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/mqttproxy/internal/jwks"
)

// newTestKeyPair generates a fresh RSA key pair and returns the private key
// and a JWK Set containing the public key, keyed by the given kid.
func newTestKeyPair(t *testing.T, kid string) (*rsa.PrivateKey, jwk.Set) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKey, err := jwk.FromRaw(priv.Public())
	require.NoError(t, err)
	require.NoError(t, pubKey.Set(jwk.KeyIDKey, kid))
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, jwa.RS256))

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pubKey))
	return priv, set
}

func serveJWKS(t *testing.T, set jwk.Set) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := json.Marshal(set)
		if err != nil {
			http.Error(w, "marshal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}))
}

func serveWellKnown(t *testing.T, jwksURL string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]string{"jwks_uri": jwksURL}
		json.NewEncoder(w).Encode(resp)
	}))
}

// --- Tests ---

func TestClient_FetchAndGet(t *testing.T) {
	_, set := newTestKeyPair(t, "key-1")
	jwksSrv := serveJWKS(t, set)
	defer jwksSrv.Close()

	wkSrv := serveWellKnown(t, jwksSrv.URL)
	defer wkSrv.Close()

	client, err := jwks.NewClient(wkSrv.URL, time.Hour, http.DefaultClient)
	require.NoError(t, err)

	key, err := client.GetKey(t.Context(), "key-1")
	require.NoError(t, err)
	assert.NotNil(t, key)
}

func TestClient_CacheHit_NoRefetch(t *testing.T) {
	_, set := newTestKeyPair(t, "key-1")
	var fetchCount atomic.Int32

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		b, _ := json.Marshal(set)
		w.Write(b)
	}))
	defer jwksSrv.Close()

	wkSrv := serveWellKnown(t, jwksSrv.URL)
	defer wkSrv.Close()

	client, err := jwks.NewClient(wkSrv.URL, time.Hour, http.DefaultClient)
	require.NoError(t, err)

	_, err = client.GetKey(t.Context(), "key-1")
	require.NoError(t, err)

	_, err = client.GetKey(t.Context(), "key-1")
	require.NoError(t, err)

	// JWKS endpoint hit once for initial fetch, well-known hit once — total JWKS fetches = 1.
	assert.Equal(t, int32(1), fetchCount.Load())
}

func TestClient_CacheExpiry_Refetches(t *testing.T) {
	_, set := newTestKeyPair(t, "key-1")
	var fetchCount atomic.Int32

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		b, _ := json.Marshal(set)
		w.Write(b)
	}))
	defer jwksSrv.Close()

	wkSrv := serveWellKnown(t, jwksSrv.URL)
	defer wkSrv.Close()

	// Very short TTL so the cache expires immediately.
	client, err := jwks.NewClient(wkSrv.URL, time.Millisecond, http.DefaultClient)
	require.NoError(t, err)

	_, err = client.GetKey(t.Context(), "key-1")
	require.NoError(t, err)

	time.Sleep(5 * time.Millisecond)

	_, err = client.GetKey(t.Context(), "key-1")
	require.NoError(t, err)

	assert.Equal(t, int32(2), fetchCount.Load())
}

func TestClient_UnknownKID_TriggersRefresh(t *testing.T) {
	_, set1 := newTestKeyPair(t, "key-1")
	_, set2 := newTestKeyPair(t, "key-2")
	var fetchCount atomic.Int32

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := fetchCount.Add(1)
		var b []byte
		if n == 1 {
			b, _ = json.Marshal(set1) // first fetch: only key-1
		} else {
			b, _ = json.Marshal(set2) // second fetch: only key-2
		}
		w.Write(b)
	}))
	defer jwksSrv.Close()

	wkSrv := serveWellKnown(t, jwksSrv.URL)
	defer wkSrv.Close()

	client, err := jwks.NewClient(wkSrv.URL, time.Hour, http.DefaultClient)
	require.NoError(t, err)

	// Prime the cache with key-1.
	_, err = client.GetKey(t.Context(), "key-1")
	require.NoError(t, err)
	assert.Equal(t, int32(1), fetchCount.Load())

	// Requesting key-2 triggers a refresh even though TTL hasn't expired.
	key, err := client.GetKey(t.Context(), "key-2")
	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, int32(2), fetchCount.Load())
}

func TestClient_UnknownKID_NotFoundAfterRefresh(t *testing.T) {
	_, set := newTestKeyPair(t, "key-1")
	jwksSrv := serveJWKS(t, set)
	defer jwksSrv.Close()

	wkSrv := serveWellKnown(t, jwksSrv.URL)
	defer wkSrv.Close()

	client, err := jwks.NewClient(wkSrv.URL, time.Hour, http.DefaultClient)
	require.NoError(t, err)

	_, err = client.GetKey(t.Context(), "does-not-exist")
	require.Error(t, err)
	assert.ErrorIs(t, err, jwks.ErrKeyNotFound)
}

func TestClient_JWKSHTTPError(t *testing.T) {
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer jwksSrv.Close()

	wkSrv := serveWellKnown(t, jwksSrv.URL)
	defer wkSrv.Close()

	client, err := jwks.NewClient(wkSrv.URL, time.Hour, http.DefaultClient)
	require.NoError(t, err)

	_, err = client.GetKey(t.Context(), "key-1")
	require.Error(t, err)
}

func TestClient_JWKSInvalidJSON(t *testing.T) {
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	}))
	defer jwksSrv.Close()

	wkSrv := serveWellKnown(t, jwksSrv.URL)
	defer wkSrv.Close()

	client, err := jwks.NewClient(wkSrv.URL, time.Hour, http.DefaultClient)
	require.NoError(t, err)

	_, err = client.GetKey(t.Context(), "key-1")
	require.Error(t, err)
}

func TestClient_WellKnownMissingJWKSURI(t *testing.T) {
	wkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": "https://example.com"})
	}))
	defer wkSrv.Close()

	_, err := jwks.NewClient(wkSrv.URL, time.Hour, http.DefaultClient)
	require.Error(t, err)
	assert.ErrorIs(t, err, jwks.ErrNoJWKSURI)
}

func TestClient_WellKnownHTTPError(t *testing.T) {
	wkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer wkSrv.Close()

	_, err := jwks.NewClient(wkSrv.URL, time.Hour, http.DefaultClient)
	require.Error(t, err)
}
