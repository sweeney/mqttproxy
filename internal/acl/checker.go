// Package acl enforces topic-level publish and subscribe permissions based on
// the role claim in a validated JWT. Permissions are configured per role in
// the YAML config file and support MQTT wildcard patterns (# and +).
package acl

import (
	"strings"

	"github.com/sweeney/mqttproxy/internal/config"
	"github.com/sweeney/mqttproxy/internal/jwt"
)

// Checker evaluates whether a client may publish or subscribe to a topic
// based on the role in their JWT claims.
type Checker struct {
	roles map[string]config.RolePolicy
}

// NewChecker creates a Checker from the ACL section of the config.
func NewChecker(cfg config.ACLConfig) *Checker {
	roles := cfg.Roles
	if roles == nil {
		roles = make(map[string]config.RolePolicy)
	}
	return &Checker{roles: roles}
}

// CanPublish returns true if the claims permit publishing to topic.
func (c *Checker) CanPublish(claims *jwt.Claims, topic string) bool {
	policy, ok := c.roles[claims.Role]
	if !ok {
		return false
	}
	return matchesAny(topic, policy.Publish)
}

// CanSubscribe returns true if the claims permit subscribing to topic.
func (c *Checker) CanSubscribe(claims *jwt.Claims, topic string) bool {
	policy, ok := c.roles[claims.Role]
	if !ok {
		return false
	}
	return matchesAny(topic, policy.Subscribe)
}

// matchesAny returns true if topic matches any of the MQTT topic filter
// patterns in the list. Supports # (multi-level) and + (single-level)
// wildcards per the MQTT specification.
func matchesAny(topic string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchesTopic(pattern, topic) {
			return true
		}
	}
	return false
}

// matchesTopic tests whether a concrete topic string matches an MQTT topic
// filter pattern.
//
// Rules (MQTT 3.1.1 §4.7):
//   - '#' matches everything at and below the current level. It must be the
//     final character and, if not alone, must be preceded by '/'.
//   - '+' matches exactly one topic level (no '/' within the segment).
//   - All other characters must match exactly.
func matchesTopic(pattern, topic string) bool {
	patternParts := strings.Split(pattern, "/")
	topicParts := strings.Split(topic, "/")

	return matchParts(patternParts, topicParts)
}

func matchParts(pattern, topic []string) bool {
	for i, p := range pattern {
		if p == "#" {
			// '#' matches zero or more remaining levels.
			return true
		}
		if i >= len(topic) {
			return false
		}
		if p == "+" {
			// '+' matches exactly one level — any value is fine, continue.
			continue
		}
		if p != topic[i] {
			return false
		}
	}
	// All pattern parts consumed — must have consumed all topic parts too.
	return len(pattern) == len(topic)
}
