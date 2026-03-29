package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen  ListenConfig  `yaml:"listen"`
	Broker  BrokerConfig  `yaml:"broker"`
	Auth    AuthConfig    `yaml:"auth"`
	ACL     ACLConfig     `yaml:"acl"`
	Logging LoggingConfig `yaml:"logging"`
}

type ListenConfig struct {
	Addr string `yaml:"addr"`
	Path string `yaml:"path"`
}

type BrokerConfig struct {
	Addr        string        `yaml:"addr"`
	DialTimeout time.Duration `yaml:"dial_timeout"`
}

type AuthConfig struct {
	WellKnownURL string        `yaml:"well_known_url"`
	Issuer       string        `yaml:"issuer"`
	Audience     string        `yaml:"audience"`
	JWKSCacheTTL time.Duration `yaml:"jwks_cache_ttl"`
}

type ACLConfig struct {
	Roles map[string]RolePolicy `yaml:"roles"`
}

type RolePolicy struct {
	Publish   []string `yaml:"publish"`
	Subscribe []string `yaml:"subscribe"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
}

// raw mirrors Config but uses strings for duration fields so we can parse
// them ourselves and return useful errors.
type raw struct {
	Listen struct {
		Addr string `yaml:"addr"`
		Path string `yaml:"path"`
	} `yaml:"listen"`
	Broker struct {
		Addr        string `yaml:"addr"`
		DialTimeout string `yaml:"dial_timeout"`
	} `yaml:"broker"`
	Auth struct {
		WellKnownURL string `yaml:"well_known_url"`
		Issuer       string `yaml:"issuer"`
		Audience     string `yaml:"audience"`
		JWKSCacheTTL string `yaml:"jwks_cache_ttl"`
	} `yaml:"auth"`
	ACL     ACLConfig     `yaml:"acl"`
	Logging LoggingConfig `yaml:"logging"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var r raw
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg := &Config{}

	// Required fields.
	if r.Listen.Addr == "" {
		return nil, fmt.Errorf("listen.addr is required")
	}
	cfg.Listen.Addr = r.Listen.Addr

	path2 := r.Listen.Path
	if path2 == "" {
		path2 = "/mqtt"
	}
	if !strings.HasPrefix(path2, "/") {
		return nil, fmt.Errorf("listen.path must start with '/' (got %q)", path2)
	}
	cfg.Listen.Path = path2

	if r.Broker.Addr == "" {
		return nil, fmt.Errorf("broker.addr is required")
	}
	cfg.Broker.Addr = r.Broker.Addr

	if r.Auth.WellKnownURL == "" {
		return nil, fmt.Errorf("auth.well_known_url is required")
	}
	cfg.Auth.WellKnownURL = r.Auth.WellKnownURL

	if r.Auth.Issuer == "" {
		return nil, fmt.Errorf("auth.issuer is required")
	}
	cfg.Auth.Issuer = r.Auth.Issuer
	cfg.Auth.Audience = r.Auth.Audience // optional; empty means no aud check

	// Durations with defaults.
	cfg.Broker.DialTimeout, err = parseDurationDefault(r.Broker.DialTimeout, 5*time.Second, "broker.dial_timeout")
	if err != nil {
		return nil, err
	}

	cfg.Auth.JWKSCacheTTL, err = parseDurationDefault(r.Auth.JWKSCacheTTL, time.Hour, "auth.jwks_cache_ttl")
	if err != nil {
		return nil, err
	}

	cfg.ACL = r.ACL

	// Logging defaults.
	cfg.Logging.Level = r.Logging.Level
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}

	return cfg, nil
}

func parseDurationDefault(s string, def time.Duration, field string) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid duration %q: %w", field, s, err)
	}
	return d, nil
}
