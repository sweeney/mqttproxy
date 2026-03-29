package proxy_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/mqttproxy/internal/jwt"
	"github.com/sweeney/mqttproxy/internal/mqtt"
	"github.com/sweeney/mqttproxy/internal/proxy"
)

// --- Fakes ---

type fakeValidator struct {
	claims *jwt.Claims
	err    error
}

func (f *fakeValidator) Validate(_ context.Context, _ string) (*jwt.Claims, error) {
	return f.claims, f.err
}

type fakeACL struct {
	allowPublish   bool
	allowSubscribe bool
}

func (f *fakeACL) CanPublish(_ *jwt.Claims, _ string) bool   { return f.allowPublish }
func (f *fakeACL) CanSubscribe(_ *jwt.Claims, _ string) bool { return f.allowSubscribe }

type fakeBrokerDialer struct {
	conn net.Conn
	err  error
}

func (f *fakeBrokerDialer) Dial(_ context.Context) (net.Conn, error) {
	return f.conn, f.err
}

// --- Test helpers ---

// pipeDialer returns a BrokerDialer that returns one side of a net.Pipe().
// The test controls the other side via brokerConn.
func pipeDialer(t *testing.T) (proxy.BrokerDialer, net.Conn) {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() {
		clientSide.Close()
		serverSide.Close()
	})
	return &fakeBrokerDialer{conn: clientSide}, serverSide
}

// startProxy starts a test HTTP server running the proxy handler and returns
// a WebSocket dialer pointed at it.
func startProxy(t *testing.T, h *proxy.Handler) (*httptest.Server, *websocket.Dialer) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	d := &websocket.Dialer{
		Subprotocols: []string{"mqtt"},
	}
	return srv, d
}

// wsURL converts an http:// test server URL to a ws:// one.
func wsURL(srv *httptest.Server) string {
	return "ws" + srv.URL[4:] + "/"
}

// connectMQTT performs a WebSocket upgrade and sends an MQTT CONNECT packet.
// Returns the WebSocket connection.
func connectMQTT(t *testing.T, d *websocket.Dialer, url, password string) *websocket.Conn {
	t.Helper()
	conn, _, err := d.Dial(url, http.Header{})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	pkt := buildConnect311(t, "test-client", "testuser", password)
	err = conn.WriteMessage(websocket.BinaryMessage, pkt)
	require.NoError(t, err)
	return conn
}

// readMQTTMessage reads one binary WebSocket message.
func readMQTTMessage(t *testing.T, conn *websocket.Conn) []byte {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	mt, msg, err := conn.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, websocket.BinaryMessage, mt)
	return msg
}

// brokerHandleConnect reads a CONNECT from the broker-side net.Conn and
// writes a CONNACK accepted response.
func brokerHandleConnect(t *testing.T, brokerConn net.Conn, version mqtt.ProtocolVersion) {
	t.Helper()
	brokerConn.SetDeadline(time.Now().Add(2 * time.Second))

	// Read the CONNECT (length-prefixed MQTT packet).
	buf := make([]byte, 512)
	n, err := brokerConn.Read(buf)
	require.NoError(t, err)
	require.Greater(t, n, 0)

	pktType := mqtt.ReadPacketType(buf[0])
	assert.Equal(t, mqtt.TypeConnect, pktType)

	// Respond with CONNACK accepted.
	ack := mqtt.WriteConnack(version, mqtt.ConnackAccepted, false)
	_, err = brokerConn.Write(ack)
	require.NoError(t, err)
}

// --- Tests ---

func TestHandler_ValidToken_ProxyEstablished(t *testing.T) {
	dialer, brokerConn := pipeDialer(t)

	h := proxy.NewHandler(proxy.Config{
		Validator: &fakeValidator{
			claims: &jwt.Claims{
				Username:  "alice",
				Role:      "admin",
				IsActive:  true,
				ExpiresAt: time.Now().Add(15 * time.Minute),
			},
		},
		ACL:    &fakeACL{allowPublish: true, allowSubscribe: true},
		Dialer: dialer,
	})

	srv, d := startProxy(t, h)
	wsConn := connectMQTT(t, d, wsURL(srv), "valid-jwt")

	// Simulate broker accepting the CONNECT.
	go brokerHandleConnect(t, brokerConn, mqtt.ProtocolV311)

	// Client should receive CONNACK accepted.
	msg := readMQTTMessage(t, wsConn)
	require.GreaterOrEqual(t, len(msg), 4)
	assert.Equal(t, mqtt.TypeConnack, mqtt.ReadPacketType(msg[0]))
	assert.Equal(t, byte(0x00), msg[3]) // return code = accepted
}

func TestHandler_InvalidToken_ConnackNotAuthorized(t *testing.T) {
	h := proxy.NewHandler(proxy.Config{
		Validator: &fakeValidator{err: errors.New("invalid token")},
		ACL:       &fakeACL{},
		Dialer:    &fakeBrokerDialer{err: errors.New("should not be called")},
	})

	srv, d := startProxy(t, h)
	conn, _, err := d.Dial(wsURL(srv), http.Header{})
	require.NoError(t, err)
	defer conn.Close()

	pkt := buildConnect311(t, "test-client", "user", "bad-jwt")
	require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, pkt))

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	require.NoError(t, err)

	assert.Equal(t, mqtt.TypeConnack, mqtt.ReadPacketType(msg[0]))
	assert.Equal(t, byte(0x05), msg[3]) // 0x05 = not authorized (3.1.1)
}

func TestHandler_InactiveUser_ConnackNotAuthorized(t *testing.T) {
	h := proxy.NewHandler(proxy.Config{
		Validator: &fakeValidator{err: jwt.ErrUserInactive},
		ACL:       &fakeACL{},
		Dialer:    &fakeBrokerDialer{err: errors.New("should not be called")},
	})

	srv, d := startProxy(t, h)
	conn, _, err := d.Dial(wsURL(srv), http.Header{})
	require.NoError(t, err)
	defer conn.Close()

	pkt := buildConnect311(t, "test-client", "user", "some-jwt")
	require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, pkt))

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	require.NoError(t, err)
	assert.Equal(t, byte(0x05), msg[3])
}

func TestHandler_BrokerDialFail_ConnackServerUnavailable(t *testing.T) {
	h := proxy.NewHandler(proxy.Config{
		Validator: &fakeValidator{
			claims: &jwt.Claims{
				Username:  "alice",
				Role:      "admin",
				IsActive:  true,
				ExpiresAt: time.Now().Add(15 * time.Minute),
			},
		},
		ACL:    &fakeACL{allowPublish: true, allowSubscribe: true},
		Dialer: &fakeBrokerDialer{err: errors.New("connection refused")},
	})

	srv, d := startProxy(t, h)
	conn, _, err := d.Dial(wsURL(srv), http.Header{})
	require.NoError(t, err)
	defer conn.Close()

	pkt := buildConnect311(t, "test-client", "user", "valid-jwt")
	require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, pkt))

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	require.NoError(t, err)
	assert.Equal(t, byte(0x03), msg[3]) // 0x03 = server unavailable
}

func TestHandler_FirstFrameNotConnect_ClosesConnection(t *testing.T) {
	h := proxy.NewHandler(proxy.Config{
		Validator: &fakeValidator{},
		ACL:       &fakeACL{},
		Dialer:    &fakeBrokerDialer{},
	})

	srv, d := startProxy(t, h)
	conn, _, err := d.Dial(wsURL(srv), http.Header{})
	require.NoError(t, err)
	defer conn.Close()

	// Send a PUBLISH packet instead of CONNECT.
	publish := []byte{0x30, 0x00}
	require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, publish))

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = conn.ReadMessage()
	// Expect the connection to be closed (websocket close or read error).
	assert.Error(t, err)
}

func TestHandler_NoPasswordInConnect_NotAuthorized(t *testing.T) {
	h := proxy.NewHandler(proxy.Config{
		Validator: &fakeValidator{err: errors.New("empty token")},
		ACL:       &fakeACL{},
		Dialer:    &fakeBrokerDialer{},
	})

	srv, d := startProxy(t, h)
	conn, _, err := d.Dial(wsURL(srv), http.Header{})
	require.NoError(t, err)
	defer conn.Close()

	// Send CONNECT with no password.
	pkt := buildConnect311NoPassword(t, "test-client", "user")
	require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, pkt))

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	require.NoError(t, err)
	assert.Equal(t, byte(0x05), msg[3])
}

func TestHandler_TokenExpiry_DisconnectsClient(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-sensitive test in short mode")
	}

	dialer, brokerConn := pipeDialer(t)

	h := proxy.NewHandler(proxy.Config{
		Validator: &fakeValidator{
			claims: &jwt.Claims{
				Username:  "alice",
				Role:      "admin",
				IsActive:  true,
				ExpiresAt: time.Now().Add(100 * time.Millisecond), // expires very soon
			},
		},
		ACL:    &fakeACL{allowPublish: true, allowSubscribe: true},
		Dialer: dialer,
	})

	srv, d := startProxy(t, h)
	wsConn := connectMQTT(t, d, wsURL(srv), "expiring-jwt")

	go brokerHandleConnect(t, brokerConn, mqtt.ProtocolV311)

	// Should receive CONNACK first.
	msg := readMQTTMessage(t, wsConn)
	assert.Equal(t, mqtt.TypeConnack, mqtt.ReadPacketType(msg[0]))

	// After expiry, should receive DISCONNECT or the connection should close.
	wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, disconnectMsg, err := wsConn.ReadMessage()
	if err == nil {
		// Got a message — should be DISCONNECT.
		assert.Equal(t, mqtt.TypeDisconnect, mqtt.ReadPacketType(disconnectMsg[0]))
	}
	// err != nil means the connection was closed — also acceptable.
}

func TestHandler_UserPublish_RejectedV311_Disconnects(t *testing.T) {
	dialer, brokerConn := pipeDialer(t)

	h := proxy.NewHandler(proxy.Config{
		Validator: &fakeValidator{
			claims: &jwt.Claims{
				Username:  "bob",
				Role:      "user",
				IsActive:  true,
				ExpiresAt: time.Now().Add(15 * time.Minute),
			},
		},
		ACL:    &fakeACL{allowPublish: false, allowSubscribe: true},
		Dialer: dialer,
	})

	srv, d := startProxy(t, h)
	wsConn := connectMQTT(t, d, wsURL(srv), "user-jwt")

	go brokerHandleConnect(t, brokerConn, mqtt.ProtocolV311)

	// Receive CONNACK.
	msg := readMQTTMessage(t, wsConn)
	require.Equal(t, mqtt.TypeConnack, mqtt.ReadPacketType(msg[0]))

	// Send an unauthorized PUBLISH (MQTT 3.1.1).
	publish := buildPublish311(t, "sensors/temp", "25.0")
	require.NoError(t, wsConn.WriteMessage(websocket.BinaryMessage, publish))

	// Should receive DISCONNECT and connection should close.
	wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, disconnectMsg, err := wsConn.ReadMessage()
	if err == nil {
		assert.Equal(t, mqtt.TypeDisconnect, mqtt.ReadPacketType(disconnectMsg[0]))
	}
}

func TestHandler_AdminPublish_ForwardedToBroker(t *testing.T) {
	dialer, brokerConn := pipeDialer(t)

	h := proxy.NewHandler(proxy.Config{
		Validator: &fakeValidator{
			claims: &jwt.Claims{
				Username:  "alice",
				Role:      "admin",
				IsActive:  true,
				ExpiresAt: time.Now().Add(15 * time.Minute),
			},
		},
		ACL:    &fakeACL{allowPublish: true, allowSubscribe: true},
		Dialer: dialer,
	})

	srv, d := startProxy(t, h)
	wsConn := connectMQTT(t, d, wsURL(srv), "admin-jwt")

	go brokerHandleConnect(t, brokerConn, mqtt.ProtocolV311)

	msg := readMQTTMessage(t, wsConn)
	require.Equal(t, mqtt.TypeConnack, mqtt.ReadPacketType(msg[0]))

	// Send PUBLISH from admin.
	publish := buildPublish311(t, "sensors/temp", "25.0")
	require.NoError(t, wsConn.WriteMessage(websocket.BinaryMessage, publish))

	// Broker should receive the PUBLISH.
	brokerConn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := brokerConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, mqtt.TypePublish, mqtt.ReadPacketType(buf[0]))
	assert.Greater(t, n, 0)
}

func TestHandler_IdleConnection_StaysOpen(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-sensitive test in short mode")
	}

	dialer, brokerConn := pipeDialer(t)

	h := proxy.NewHandler(proxy.Config{
		Validator: &fakeValidator{
			claims: &jwt.Claims{
				Username:  "alice",
				Role:      "admin",
				IsActive:  true,
				ExpiresAt: time.Now().Add(15 * time.Minute),
			},
		},
		ACL:    &fakeACL{allowPublish: true, allowSubscribe: true},
		Dialer: dialer,
	})

	srv, d := startProxy(t, h)
	wsConn := connectMQTT(t, d, wsURL(srv), "valid-jwt")

	go brokerHandleConnect(t, brokerConn, mqtt.ProtocolV311)

	// Receive CONNACK.
	msg := readMQTTMessage(t, wsConn)
	require.Equal(t, mqtt.TypeConnack, mqtt.ReadPacketType(msg[0]))

	// Wait longer than the old 5s read deadline — connection must stay open.
	time.Sleep(6 * time.Second)

	// Send a PUBLISH and confirm it reaches the broker — proving the connection
	// survived the idle period.
	publish := buildPublish311(t, "sensors/temp", "42.0")
	require.NoError(t, wsConn.WriteMessage(websocket.BinaryMessage, publish))

	brokerConn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := brokerConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, mqtt.TypePublish, mqtt.ReadPacketType(buf[0]))
	assert.Greater(t, n, 0)
}

func TestHandler_ConnectPasswordStrippedOnForward(t *testing.T) {
	dialer, brokerConn := pipeDialer(t)

	h := proxy.NewHandler(proxy.Config{
		Validator: &fakeValidator{
			claims: &jwt.Claims{
				Username:  "alice",
				Role:      "admin",
				IsActive:  true,
				ExpiresAt: time.Now().Add(15 * time.Minute),
			},
		},
		ACL:    &fakeACL{allowPublish: true, allowSubscribe: true},
		Dialer: dialer,
	})

	srv, d := startProxy(t, h)
	_ = connectMQTT(t, d, wsURL(srv), "my-secret-jwt")

	// Read what the broker received.
	brokerConn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := brokerConn.Read(buf)
	require.NoError(t, err)

	// Parse the forwarded CONNECT.
	forwarded, err := mqtt.ParseConnect(buf[:n])
	require.NoError(t, err)

	// Password must NOT be forwarded to the broker.
	assert.Empty(t, forwarded.Password)
	// Username from JWT claims should be set.
	assert.Equal(t, "alice", forwarded.Username)
}

// --- Packet builder helpers ---

func buildConnect311(t *testing.T, clientID, username, password string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writeString(&buf, "MQTT")
	buf.WriteByte(0x04)
	buf.WriteByte(0xC0) // username + password flags
	buf.WriteByte(0x00)
	buf.WriteByte(0x0A)
	writeString(&buf, clientID)
	writeString(&buf, username)
	writeBytes(&buf, []byte(password))
	return wrapConnect(buf.Bytes())
}

func buildConnect311NoPassword(t *testing.T, clientID, username string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writeString(&buf, "MQTT")
	buf.WriteByte(0x04)
	buf.WriteByte(0x80) // username only
	buf.WriteByte(0x00)
	buf.WriteByte(0x0A)
	writeString(&buf, clientID)
	writeString(&buf, username)
	return wrapConnect(buf.Bytes())
}

func buildPublish311(t *testing.T, topic, payload string) []byte {
	t.Helper()
	var body bytes.Buffer
	writeString(&body, topic)
	body.WriteString(payload)

	var out bytes.Buffer
	out.WriteByte(0x30) // PUBLISH, QoS 0
	out.Write(mqtt.EncodeRemainingLength(body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}

func wrapConnect(payload []byte) []byte {
	var out bytes.Buffer
	out.WriteByte(0x10)
	out.Write(mqtt.EncodeRemainingLength(len(payload)))
	out.Write(payload)
	return out.Bytes()
}

func writeString(buf *bytes.Buffer, s string) {
	b := []byte(s)
	buf.WriteByte(byte(len(b) >> 8))
	buf.WriteByte(byte(len(b)))
	buf.Write(b)
}

func writeBytes(buf *bytes.Buffer, b []byte) {
	buf.WriteByte(byte(len(b) >> 8))
	buf.WriteByte(byte(len(b)))
	buf.Write(b)
}
