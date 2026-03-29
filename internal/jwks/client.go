// Package jwks fetches and caches JSON Web Key Sets from an OAuth2
// well-known discovery endpoint.
package jwks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

var (
	ErrKeyNotFound = errors.New("key not found in JWKS")
	ErrNoJWKSURI   = errors.New("jwks_uri not present in well-known metadata")
)

// Client fetches and caches a JWKS, refreshing when the TTL expires or when
// a JWT references an unknown key ID.
type Client struct {
	jwksURL    string
	httpClient *http.Client
	ttl        time.Duration

	mu        sync.RWMutex
	cached    jwk.Set
	fetchedAt time.Time
}

// NewClient creates a Client by fetching the well-known OAuth2 server metadata
// to discover the jwks_uri, then performing an initial JWKS fetch.
func NewClient(wellKnownURL string, ttl time.Duration, httpClient *http.Client) (*Client, error) {
	jwksURL, err := discoverJWKSURI(wellKnownURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("discover jwks_uri: %w", err)
	}

	c := &Client{
		jwksURL:    jwksURL,
		httpClient: httpClient,
		ttl:        ttl,
	}
	return c, nil
}

// GetKey returns the JWK with the given key ID.
//
// Lookup order:
//  1. Return from cache if TTL has not expired and key is present.
//  2. If the TTL has expired, refresh the cache and retry.
//  3. If the key is still not found after refresh, return ErrKeyNotFound.
//
// A cache miss for an unknown kid (TTL not yet expired) also triggers a
// one-time refresh, to handle key rotation without waiting for the TTL.
func (c *Client) GetKey(ctx context.Context, kid string) (jwk.Key, error) {
	// Fast path: read-locked cache lookup.
	c.mu.RLock()
	key, fresh := c.lookupLocked(kid)
	c.mu.RUnlock()

	if fresh && key != nil {
		return key, nil
	}

	// Slow path: refresh needed (TTL expired or kid unknown).
	c.mu.Lock()
	defer c.mu.Unlock()

	// Re-check under write lock to avoid a double-fetch if another goroutine
	// already refreshed while we were waiting.
	key, fresh = c.lookupLocked(kid)
	if fresh && key != nil {
		return key, nil
	}

	if err := c.fetchLocked(ctx); err != nil {
		return nil, err
	}

	k, ok := c.cached.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrKeyNotFound, kid)
	}
	return k, nil
}

// lookupLocked checks the cache under the current lock. Returns the key (or
// nil) and whether the cache is still considered fresh.
func (c *Client) lookupLocked(kid string) (jwk.Key, bool) {
	if c.cached == nil {
		return nil, false
	}
	fresh := time.Since(c.fetchedAt) < c.ttl
	k, ok := c.cached.LookupKeyID(kid)
	if !ok {
		return nil, fresh
	}
	return k, fresh
}

func (c *Client) fetchLocked(ctx context.Context) error {
	set, err := fetchJWKS(ctx, c.jwksURL, c.httpClient)
	if err != nil {
		return err
	}
	c.cached = set
	c.fetchedAt = time.Now()
	return nil
}

// discoverJWKSURI fetches the OAuth2 well-known metadata and returns the
// jwks_uri field.
func discoverJWKSURI(wellKnownURL string, httpClient *http.Client) (string, error) {
	resp, err := httpClient.Get(wellKnownURL)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", wellKnownURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: status %d", wellKnownURL, resp.StatusCode)
	}

	var meta struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return "", fmt.Errorf("decode well-known metadata: %w", err)
	}
	if meta.JWKSURI == "" {
		return "", ErrNoJWKSURI
	}
	return meta.JWKSURI, nil
}

func fetchJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (jwk.Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build JWKS request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", jwksURL, resp.StatusCode)
	}

	set, err := jwk.ParseReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	return set, nil
}
