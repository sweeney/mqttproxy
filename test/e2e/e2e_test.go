//go:build e2e

// Package e2e contains end-to-end tests that require live infrastructure:
// a running mosquitto broker and the id.swee.net auth server.
//
// Run with:
//
//	go test ./test/e2e/... -tags e2e -v
//
// Required environment variables:
//
//	E2E_PROXY_ADDR    WebSocket address of the proxy under test  (default: ws://localhost:8883/mqtt)
//	E2E_AUTH_URL      Base URL of the auth server               (default: https://id.swee.net)
//	E2E_ADMIN_USER    Username of a user with admin role
//	E2E_ADMIN_PASS    Password of the admin user
//	E2E_USER_USER     Username of a user with user role
//	E2E_USER_PASS     Password of the user-role user
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func proxyAddr() string {
	if v := os.Getenv("E2E_PROXY_ADDR"); v != "" {
		return v
	}
	return "ws://localhost:8883/mqtt"
}

func authURL() string {
	if v := os.Getenv("E2E_AUTH_URL"); v != "" {
		return v
	}
	return "https://id.swee.net"
}

func envRequired(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("skipping: %s not set", key)
	}
	return v
}

// login fetches a JWT access token from the auth server.
func login(t *testing.T, username, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	resp, err := http.Post(authURL()+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode, "login failed for %q", username)

	var result struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	require.NotEmpty(t, result.AccessToken, "empty access_token for %q", username)
	return result.AccessToken
}

// newMQTTClient creates a Paho MQTT client connected to the proxy via
// WebSocket, using the JWT as the MQTT password.
func newMQTTClient(t *testing.T, clientID, username, jwtToken string) mqtt.Client {
	t.Helper()
	opts := mqtt.NewClientOptions().
		AddBroker(proxyAddr()).
		SetClientID(clientID).
		SetUsername(username).
		SetPassword(jwtToken).
		SetConnectTimeout(5 * time.Second).
		SetAutoReconnect(false)

	client := mqtt.NewClient(opts)
	token := client.Connect()
	require.True(t, token.WaitTimeout(5*time.Second), "connect timed out")
	require.NoError(t, token.Error())
	t.Cleanup(func() { client.Disconnect(250) })
	return client
}

// --- Tests ---

func TestE2E_AdminConnect_PublishAndSubscribe(t *testing.T) {
	adminUser := envRequired(t, "E2E_ADMIN_USER")
	adminPass := envRequired(t, "E2E_ADMIN_PASS")

	jwtToken := login(t, adminUser, adminPass)

	client := newMQTTClient(t, "e2e-admin-pub", adminUser, jwtToken)
	subscriber := newMQTTClient(t, "e2e-admin-sub", adminUser, jwtToken)

	received := make(chan string, 1)
	topic := fmt.Sprintf("e2e/test/%d", time.Now().UnixNano())

	subToken := subscriber.Subscribe(topic, 0, func(_ mqtt.Client, msg mqtt.Message) {
		received <- string(msg.Payload())
	})
	require.True(t, subToken.WaitTimeout(5*time.Second))
	require.NoError(t, subToken.Error())

	pubToken := client.Publish(topic, 0, false, "hello-from-admin")
	require.True(t, pubToken.WaitTimeout(5*time.Second))
	require.NoError(t, pubToken.Error())

	select {
	case msg := <-received:
		assert.Equal(t, "hello-from-admin", msg)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for message")
	}
}

func TestE2E_UserConnect_SubscribeOnly(t *testing.T) {
	userUser := envRequired(t, "E2E_USER_USER")
	userPass := envRequired(t, "E2E_USER_PASS")
	adminUser := envRequired(t, "E2E_ADMIN_USER")
	adminPass := envRequired(t, "E2E_ADMIN_PASS")

	userToken := login(t, userUser, userPass)
	adminToken := login(t, adminUser, adminPass)

	userClient := newMQTTClient(t, "e2e-user-sub", userUser, userToken)
	adminClient := newMQTTClient(t, "e2e-admin-pub2", adminUser, adminToken)

	received := make(chan string, 1)
	topic := fmt.Sprintf("e2e/user/%d", time.Now().UnixNano())

	// User can subscribe.
	subToken := userClient.Subscribe(topic, 0, func(_ mqtt.Client, msg mqtt.Message) {
		received <- string(msg.Payload())
	})
	require.True(t, subToken.WaitTimeout(5*time.Second))
	require.NoError(t, subToken.Error())

	// Admin publishes on behalf of the user.
	pubToken := adminClient.Publish(topic, 0, false, "message-for-user")
	require.True(t, pubToken.WaitTimeout(5*time.Second))
	require.NoError(t, pubToken.Error())

	select {
	case msg := <-received:
		assert.Equal(t, "message-for-user", msg)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for message")
	}
}

func TestE2E_UserPublish_DisconnectedByProxy(t *testing.T) {
	userUser := envRequired(t, "E2E_USER_USER")
	userPass := envRequired(t, "E2E_USER_PASS")

	userToken := login(t, userUser, userPass)

	opts := mqtt.NewClientOptions().
		AddBroker(proxyAddr()).
		SetClientID("e2e-user-pub-attempt").
		SetUsername(userUser).
		SetPassword(userToken).
		SetConnectTimeout(5 * time.Second).
		SetAutoReconnect(false)

	disconnected := make(chan struct{})
	opts.SetConnectionLostHandler(func(_ mqtt.Client, _ error) {
		close(disconnected)
	})

	client := mqtt.NewClient(opts)
	token := client.Connect()
	require.True(t, token.WaitTimeout(5*time.Second))
	require.NoError(t, token.Error())
	defer client.Disconnect(250)

	// Attempt to publish — should cause the proxy to disconnect us.
	pubToken := client.Publish("sensors/temp", 0, false, "25.0")
	pubToken.WaitTimeout(2 * time.Second)

	select {
	case <-disconnected:
		// Expected: proxy disconnected us for unauthorized publish.
	case <-time.After(5 * time.Second):
		t.Fatal("expected to be disconnected after unauthorized publish, but connection remained")
	}
}

func TestE2E_InvalidToken_ConnectionRefused(t *testing.T) {
	opts := mqtt.NewClientOptions().
		AddBroker(proxyAddr()).
		SetClientID("e2e-bad-token").
		SetUsername("someone").
		SetPassword("this.is.not.a.valid.jwt").
		SetConnectTimeout(5 * time.Second).
		SetAutoReconnect(false)

	client := mqtt.NewClient(opts)
	token := client.Connect()
	token.WaitTimeout(5 * time.Second)

	// Connect should fail — proxy sends CONNACK Not Authorized.
	assert.Error(t, token.Error(), "expected connection to be refused with invalid JWT")
}

func TestE2E_NoToken_ConnectionRefused(t *testing.T) {
	opts := mqtt.NewClientOptions().
		AddBroker(proxyAddr()).
		SetClientID("e2e-no-token").
		SetUsername("someone").
		// No password — proxy should reject.
		SetConnectTimeout(5 * time.Second).
		SetAutoReconnect(false)

	client := mqtt.NewClient(opts)
	token := client.Connect()
	token.WaitTimeout(5 * time.Second)

	assert.Error(t, token.Error())
}
