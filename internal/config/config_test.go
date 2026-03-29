package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/mqttproxy/internal/config"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func TestLoad_Valid(t *testing.T) {
	path := writeTemp(t, `
listen:
  addr: "0.0.0.0:8883"
  path: "/mqtt"

broker:
  addr: "127.0.0.1:9001"
  dial_timeout: "5s"

auth:
  well_known_url: "https://id.example.com/.well-known/oauth-authorization-server"
  issuer: "https://id.example.com"
  audience: "mqttproxy"
  jwks_cache_ttl: "1h"

acl:
  roles:
    admin:
      publish:   ["#"]
      subscribe: ["#"]
    user:
      publish:   []
      subscribe: ["#"]

logging:
  level: "info"
`)

	cfg, err := config.Load(path)
	require.NoError(t, err)

	assert.Equal(t, "0.0.0.0:8883", cfg.Listen.Addr)
	assert.Equal(t, "/mqtt", cfg.Listen.Path)
	assert.Equal(t, "127.0.0.1:9001", cfg.Broker.Addr)
	assert.Equal(t, 5*time.Second, cfg.Broker.DialTimeout)
	assert.Equal(t, "https://id.example.com/.well-known/oauth-authorization-server", cfg.Auth.WellKnownURL)
	assert.Equal(t, "https://id.example.com", cfg.Auth.Issuer)
	assert.Equal(t, "mqttproxy", cfg.Auth.Audience)
	assert.Equal(t, time.Hour, cfg.Auth.JWKSCacheTTL)
	assert.Equal(t, []string{"#"}, cfg.ACL.Roles["admin"].Publish)
	assert.Equal(t, []string{"#"}, cfg.ACL.Roles["admin"].Subscribe)
	assert.Empty(t, cfg.ACL.Roles["user"].Publish)
	assert.Equal(t, []string{"#"}, cfg.ACL.Roles["user"].Subscribe)
	assert.Equal(t, "info", cfg.Logging.Level)
}

func TestLoad_Defaults(t *testing.T) {
	// Only required fields — verify defaults are applied.
	path := writeTemp(t, `
listen:
  addr: "0.0.0.0:8883"
  path: "/mqtt"
broker:
  addr: "127.0.0.1:9001"
auth:
  well_known_url: "https://id.example.com/.well-known/oauth-authorization-server"
  issuer: "https://id.example.com"
`)

	cfg, err := config.Load(path)
	require.NoError(t, err)

	assert.Equal(t, 5*time.Second, cfg.Broker.DialTimeout)
	assert.Equal(t, time.Hour, cfg.Auth.JWKSCacheTTL)
	assert.Equal(t, "info", cfg.Logging.Level)
}

func TestLoad_MissingRequiredFields(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "missing listen addr",
			wantErr: "listen.addr",
			yaml: `
listen:
  path: "/mqtt"
broker:
  addr: "127.0.0.1:9001"
auth:
  well_known_url: "https://id.example.com/.well-known/oauth-authorization-server"
  issuer: "https://id.example.com"
`,
		},
		{
			name:    "missing broker addr",
			wantErr: "broker.addr",
			yaml: `
listen:
  addr: "0.0.0.0:8883"
  path: "/mqtt"
broker: {}
auth:
  well_known_url: "https://id.example.com/.well-known/oauth-authorization-server"
  issuer: "https://id.example.com"
`,
		},
		{
			name:    "missing auth well_known_url",
			wantErr: "auth.well_known_url",
			yaml: `
listen:
  addr: "0.0.0.0:8883"
  path: "/mqtt"
broker:
  addr: "127.0.0.1:9001"
auth:
  issuer: "https://id.example.com"
`,
		},
		{
			name:    "missing auth issuer",
			wantErr: "auth.issuer",
			yaml: `
listen:
  addr: "0.0.0.0:8883"
  path: "/mqtt"
broker:
  addr: "127.0.0.1:9001"
auth:
  well_known_url: "https://id.example.com/.well-known/oauth-authorization-server"
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, tc.yaml)
			_, err := config.Load(path)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTemp(t, `{this is: not: valid yaml:::`)
	_, err := config.Load(path)
	require.Error(t, err)
}

func TestLoad_InvalidDuration(t *testing.T) {
	path := writeTemp(t, `
listen:
  addr: "0.0.0.0:8883"
  path: "/mqtt"
broker:
  addr: "127.0.0.1:9001"
  dial_timeout: "notaduration"
auth:
  well_known_url: "https://id.example.com/.well-known/oauth-authorization-server"
  issuer: "https://id.example.com"
`)
	_, err := config.Load(path)
	require.Error(t, err)
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	require.Error(t, err)
}

func TestLoad_InvalidListenPath(t *testing.T) {
	path := writeTemp(t, `
listen:
  addr: "0.0.0.0:8883"
  path: "mqtt"
broker:
  addr: "127.0.0.1:9001"
auth:
  well_known_url: "https://id.example.com/.well-known/oauth-authorization-server"
  issuer: "https://id.example.com"
`)
	_, err := config.Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen.path")
}
