package acl_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sweeney/mqttproxy/internal/acl"
	"github.com/sweeney/mqttproxy/internal/config"
	"github.com/sweeney/mqttproxy/internal/jwt"
)

// defaultConfig mirrors the recommended config from config.example.yaml.
func defaultConfig() config.ACLConfig {
	return config.ACLConfig{
		Roles: map[string]config.RolePolicy{
			"admin": {
				Publish:   []string{"#"},
				Subscribe: []string{"#"},
			},
			"user": {
				Publish:   []string{},
				Subscribe: []string{"#"},
			},
		},
	}
}

func adminClaims() *jwt.Claims {
	return &jwt.Claims{Username: "admin-user", Role: "admin", IsActive: true}
}

func userClaims() *jwt.Claims {
	return &jwt.Claims{Username: "regular-user", Role: "user", IsActive: true}
}

// --- Publish ---

func TestAdmin_CanPublish_AnyTopic(t *testing.T) {
	c := acl.NewChecker(defaultConfig())
	topics := []string{"sensors/temp", "sensors/humidity", "$SYS/stats", "a/b/c/d/e"}
	for _, topic := range topics {
		assert.True(t, c.CanPublish(adminClaims(), topic), "admin should publish to %q", topic)
	}
}

func TestUser_CannotPublish_AnyTopic(t *testing.T) {
	c := acl.NewChecker(defaultConfig())
	topics := []string{"sensors/temp", "any/topic", "$SYS/stats"}
	for _, topic := range topics {
		assert.False(t, c.CanPublish(userClaims(), topic), "user should not publish to %q", topic)
	}
}

// --- Subscribe ---

func TestAdmin_CanSubscribe_AnyTopic(t *testing.T) {
	c := acl.NewChecker(defaultConfig())
	assert.True(t, c.CanSubscribe(adminClaims(), "sensors/#"))
	assert.True(t, c.CanSubscribe(adminClaims(), "$SYS/#"))
}

func TestUser_CanSubscribe_AnyTopic(t *testing.T) {
	c := acl.NewChecker(defaultConfig())
	assert.True(t, c.CanSubscribe(userClaims(), "sensors/temp"))
	assert.True(t, c.CanSubscribe(userClaims(), "a/b/c"))
}

// --- Unknown role ---

func TestUnknownRole_DeniedByDefault(t *testing.T) {
	c := acl.NewChecker(defaultConfig())
	unknown := &jwt.Claims{Username: "x", Role: "superadmin", IsActive: true}
	assert.False(t, c.CanPublish(unknown, "any/topic"))
	assert.False(t, c.CanSubscribe(unknown, "any/topic"))
}

// --- Topic pattern matching ---

func TestTopicPattern_HashWildcard(t *testing.T) {
	c := acl.NewChecker(config.ACLConfig{
		Roles: map[string]config.RolePolicy{
			"limited": {
				Publish:   []string{"sensors/#"},
				Subscribe: []string{"sensors/#"},
			},
		},
	})
	claims := &jwt.Claims{Role: "limited"}

	// Allowed: matches sensors/#
	assert.True(t, c.CanPublish(claims, "sensors/temp"))
	assert.True(t, c.CanPublish(claims, "sensors/room1/temp"))

	// Denied: does not match sensors/#
	assert.False(t, c.CanPublish(claims, "actuators/fan"))
	assert.False(t, c.CanPublish(claims, "other"))
}

func TestTopicPattern_PlusWildcard(t *testing.T) {
	c := acl.NewChecker(config.ACLConfig{
		Roles: map[string]config.RolePolicy{
			"floor-sensor": {
				Publish:   []string{"building/+/temperature"},
				Subscribe: []string{"building/+/temperature"},
			},
		},
	})
	claims := &jwt.Claims{Role: "floor-sensor"}

	assert.True(t, c.CanPublish(claims, "building/floor1/temperature"))
	assert.True(t, c.CanPublish(claims, "building/floor99/temperature"))

	assert.False(t, c.CanPublish(claims, "building/floor1/humidity"))
	assert.False(t, c.CanPublish(claims, "building/floor1/temperature/extra"))
}

func TestTopicPattern_ExactMatch(t *testing.T) {
	c := acl.NewChecker(config.ACLConfig{
		Roles: map[string]config.RolePolicy{
			"specific": {
				Publish:   []string{"exact/topic"},
				Subscribe: []string{"exact/topic"},
			},
		},
	})
	claims := &jwt.Claims{Role: "specific"}

	assert.True(t, c.CanPublish(claims, "exact/topic"))
	assert.False(t, c.CanPublish(claims, "exact/topic/sub"))
	assert.False(t, c.CanPublish(claims, "exact/other"))
}

func TestTopicPattern_MultiplePatterns(t *testing.T) {
	c := acl.NewChecker(config.ACLConfig{
		Roles: map[string]config.RolePolicy{
			"multi": {
				Publish:   []string{"sensors/#", "status/online"},
				Subscribe: []string{"sensors/#", "commands/#"},
			},
		},
	})
	claims := &jwt.Claims{Role: "multi"}

	assert.True(t, c.CanPublish(claims, "sensors/temp"))
	assert.True(t, c.CanPublish(claims, "status/online"))
	assert.False(t, c.CanPublish(claims, "commands/reboot"))

	assert.True(t, c.CanSubscribe(claims, "sensors/temp"))
	assert.True(t, c.CanSubscribe(claims, "commands/reboot"))
	assert.False(t, c.CanSubscribe(claims, "status/online"))
}

func TestTopicPattern_EmptyPatternList_DeniesAll(t *testing.T) {
	c := acl.NewChecker(config.ACLConfig{
		Roles: map[string]config.RolePolicy{
			"readonly": {
				Publish:   []string{},
				Subscribe: []string{"#"},
			},
		},
	})
	claims := &jwt.Claims{Role: "readonly"}
	assert.False(t, c.CanPublish(claims, "any/topic"))
	assert.True(t, c.CanSubscribe(claims, "any/topic"))
}
