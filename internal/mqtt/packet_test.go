package mqtt_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/mqttproxy/internal/mqtt"
)

// --- CONNECT parsing ---

func TestParseConnect_V311_WithUsernamePassword(t *testing.T) {
	// Hand-crafted MQTT 3.1.1 CONNECT packet:
	// clientID="test", username="user", password="s3cr3t"
	pkt := buildConnect311(t, "test", "user", "s3cr3t")

	conn, err := mqtt.ParseConnect(pkt)
	require.NoError(t, err)

	assert.Equal(t, mqtt.ProtocolV311, conn.Version)
	assert.Equal(t, "test", conn.ClientID)
	assert.Equal(t, "user", conn.Username)
	assert.Equal(t, "s3cr3t", conn.Password)
}

func TestParseConnect_V311_NoPassword(t *testing.T) {
	pkt := buildConnect311NoPassword(t, "clientA", "someuser")

	conn, err := mqtt.ParseConnect(pkt)
	require.NoError(t, err)

	assert.Equal(t, mqtt.ProtocolV311, conn.Version)
	assert.Equal(t, "clientA", conn.ClientID)
	assert.Equal(t, "someuser", conn.Username)
	assert.Empty(t, conn.Password)
}

func TestParseConnect_V311_NoUsernameNoPassword(t *testing.T) {
	pkt := buildConnect311Bare(t, "bare-client")

	conn, err := mqtt.ParseConnect(pkt)
	require.NoError(t, err)

	assert.Equal(t, mqtt.ProtocolV311, conn.Version)
	assert.Equal(t, "bare-client", conn.ClientID)
	assert.Empty(t, conn.Username)
	assert.Empty(t, conn.Password)
}

func TestParseConnect_V50_WithUsernamePassword(t *testing.T) {
	pkt := buildConnect50(t, "v5client", "v5user", "v5pass")

	conn, err := mqtt.ParseConnect(pkt)
	require.NoError(t, err)

	assert.Equal(t, mqtt.ProtocolV50, conn.Version)
	assert.Equal(t, "v5client", conn.ClientID)
	assert.Equal(t, "v5user", conn.Username)
	assert.Equal(t, "v5pass", conn.Password)
}

func TestParseConnect_WrongPacketType(t *testing.T) {
	// First byte 0x30 = PUBLISH, not CONNECT (0x10)
	_, err := mqtt.ParseConnect([]byte{0x30, 0x00})
	require.Error(t, err)
	assert.ErrorIs(t, err, mqtt.ErrNotConnect)
}

func TestParseConnect_TruncatedPacket(t *testing.T) {
	// Valid fixed header but body truncated.
	_, err := mqtt.ParseConnect([]byte{0x10, 0x10, 0x00})
	require.Error(t, err)
}

func TestParseConnect_UnknownProtocol(t *testing.T) {
	// Build a packet with protocol name "MQZZ" — not a known version.
	pkt := buildConnectWithProtocol(t, "MQZZ", 0x04, "c", "u", "p")
	_, err := mqtt.ParseConnect(pkt)
	require.Error(t, err)
	assert.ErrorIs(t, err, mqtt.ErrUnknownProtocol)
}

func TestParseConnect_CleanSession(t *testing.T) {
	// Build a CONNECT with CleanSession bit set (flags byte 0xC2 = user+pass+clean).
	var buf bytes.Buffer
	writeString(&buf, "MQTT")
	buf.WriteByte(0x04)
	buf.WriteByte(0xC2) // username | password | clean session
	buf.WriteByte(0x00)
	buf.WriteByte(0x3C) // keepalive = 60s
	writeString(&buf, "clean-client")
	writeString(&buf, "user")
	writeBytes(&buf, []byte("pass"))
	pkt := wrapConnect(buf.Bytes())

	conn, err := mqtt.ParseConnect(pkt)
	require.NoError(t, err)
	assert.True(t, conn.CleanSession)
	assert.Equal(t, uint16(60), conn.KeepAlive)

	// Rewrite and confirm CleanSession is preserved.
	rewritten := conn.WithUsername("newuser")
	reparsed, err := mqtt.ParseConnect(rewritten)
	require.NoError(t, err)
	assert.True(t, reparsed.CleanSession)
	assert.Equal(t, uint16(60), reparsed.KeepAlive)
}

func TestParseConnect_NoCleanSession_Preserved(t *testing.T) {
	// Default buildConnect311 uses 0xC0 — no clean session bit.
	pkt := buildConnect311(t, "c1", "u", "p")
	conn, err := mqtt.ParseConnect(pkt)
	require.NoError(t, err)
	assert.False(t, conn.CleanSession)

	rewritten := conn.WithUsername("u2")
	reparsed, err := mqtt.ParseConnect(rewritten)
	require.NoError(t, err)
	assert.False(t, reparsed.CleanSession)
}

// --- CONNECT rewriting ---

func TestConnect_WithoutPassword(t *testing.T) {
	pkt := buildConnect311(t, "c1", "alice", "myjwt")

	conn, err := mqtt.ParseConnect(pkt)
	require.NoError(t, err)

	stripped := conn.WithoutPassword()
	reparsed, err := mqtt.ParseConnect(stripped)
	require.NoError(t, err)

	assert.Equal(t, conn.ClientID, reparsed.ClientID)
	assert.Equal(t, conn.Username, reparsed.Username)
	assert.Empty(t, reparsed.Password)
}

func TestConnect_WithUsername(t *testing.T) {
	pkt := buildConnect311(t, "c1", "ignored", "myjwt")

	conn, err := mqtt.ParseConnect(pkt)
	require.NoError(t, err)

	rewritten := conn.WithUsername("extracted-from-jwt")
	reparsed, err := mqtt.ParseConnect(rewritten)
	require.NoError(t, err)

	assert.Equal(t, "extracted-from-jwt", reparsed.Username)
	assert.Empty(t, reparsed.Password)
}

// --- CONNACK serialisation ---

func TestWriteConnack_V311_Accepted(t *testing.T) {
	b := mqtt.WriteConnack(mqtt.ProtocolV311, mqtt.ConnackAccepted, false)
	// Fixed header 0x20, remaining length 2, session present 0, return code 0
	assert.Equal(t, []byte{0x20, 0x02, 0x00, 0x00}, b)
}

func TestWriteConnack_V311_NotAuthorized(t *testing.T) {
	b := mqtt.WriteConnack(mqtt.ProtocolV311, mqtt.ConnackNotAuthorized, false)
	assert.Equal(t, []byte{0x20, 0x02, 0x00, 0x05}, b)
}

func TestWriteConnack_V311_ServerUnavailable(t *testing.T) {
	b := mqtt.WriteConnack(mqtt.ProtocolV311, mqtt.ConnackServerUnavailable, false)
	assert.Equal(t, []byte{0x20, 0x02, 0x00, 0x03}, b)
}

func TestWriteConnack_V50_Accepted(t *testing.T) {
	b := mqtt.WriteConnack(mqtt.ProtocolV50, mqtt.ConnackAccepted, false)
	// MQTT 5.0 CONNACK: 0x20, remaining=3, session present=0, reason=0x00, properties length=0
	assert.Equal(t, []byte{0x20, 0x03, 0x00, 0x00, 0x00}, b)
}

func TestWriteConnack_V50_NotAuthorized(t *testing.T) {
	b := mqtt.WriteConnack(mqtt.ProtocolV50, mqtt.ConnackNotAuthorized, false)
	// reason code 0x87 = Not Authorized in MQTT 5.0
	assert.Equal(t, []byte{0x20, 0x03, 0x00, 0x87, 0x00}, b)
}

// --- DISCONNECT serialisation ---

func TestWriteDisconnect_V311(t *testing.T) {
	b := mqtt.WriteDisconnect(mqtt.ProtocolV311, mqtt.DisconnectNormal)
	// MQTT 3.1.1 DISCONNECT is always just: 0xE0 0x00
	assert.Equal(t, []byte{0xE0, 0x00}, b)
}

func TestWriteDisconnect_V50_Normal(t *testing.T) {
	b := mqtt.WriteDisconnect(mqtt.ProtocolV50, mqtt.DisconnectNormal)
	// MQTT 5.0: 0xE0, remaining=2, reason=0x00, properties length=0
	assert.Equal(t, []byte{0xE0, 0x02, 0x00, 0x00}, b)
}

func TestWriteDisconnect_V50_NotAuthorized(t *testing.T) {
	b := mqtt.WriteDisconnect(mqtt.ProtocolV50, mqtt.DisconnectNotAuthorized)
	// reason code 0x87
	assert.Equal(t, []byte{0xE0, 0x02, 0x87, 0x00}, b)
}

func TestWriteDisconnect_V50_SessionTakenOver(t *testing.T) {
	b := mqtt.WriteDisconnect(mqtt.ProtocolV50, mqtt.DisconnectSessionTakenOver)
	// reason code 0x8E
	assert.Equal(t, []byte{0xE0, 0x02, 0x8E, 0x00}, b)
}

// --- PUBACK serialisation (for ACL rejection in MQTT 5.0) ---

func TestWritePuback_V50_NotAuthorized(t *testing.T) {
	b := mqtt.WritePuback(mqtt.ProtocolV50, 42, mqtt.PubackNotAuthorized)
	// 0x40, remaining=4, packet id high, packet id low, reason=0x87, properties=0
	assert.Equal(t, []byte{0x40, 0x04, 0x00, 0x2A, 0x87, 0x00}, b)
}

func TestWritePuback_V311_Success(t *testing.T) {
	b := mqtt.WritePuback(mqtt.ProtocolV311, 1, mqtt.PubackSuccess)
	// MQTT 3.1.1 PUBACK is just fixed header + packet id (2 bytes)
	assert.Equal(t, []byte{0x40, 0x02, 0x00, 0x01}, b)
}

// --- SUBACK serialisation (for ACL rejection) ---

func TestWriteSuback_V50_NotAuthorized(t *testing.T) {
	b := mqtt.WriteSuback(mqtt.ProtocolV50, 7, []mqtt.SubackCode{mqtt.SubackNotAuthorized})
	// 0x90, remaining=4, pkt id high, pkt id low, properties=0, reason=0x87
	assert.Equal(t, []byte{0x90, 0x04, 0x00, 0x07, 0x00, 0x87}, b)
}

func TestWriteSuback_V311_Success(t *testing.T) {
	// QoS 0 granted for one subscription
	b := mqtt.WriteSuback(mqtt.ProtocolV311, 3, []mqtt.SubackCode{mqtt.SubackGrantedQoS0})
	assert.Equal(t, []byte{0x90, 0x03, 0x00, 0x03, 0x00}, b)
}

// --- Packet type inspection ---

func TestPacketType(t *testing.T) {
	cases := []struct {
		first byte
		want  mqtt.PacketType
	}{
		{0x10, mqtt.TypeConnect},
		{0x20, mqtt.TypeConnack},
		{0x30, mqtt.TypePublish},
		{0x3F, mqtt.TypePublish}, // publish with flags
		{0x82, mqtt.TypeSubscribe},
		{0x90, mqtt.TypeSuback},
		{0xA2, mqtt.TypeUnsubscribe},
		{0xC0, mqtt.TypePingreq},
		{0xD0, mqtt.TypePingresp},
		{0xE0, mqtt.TypeDisconnect},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, mqtt.ReadPacketType(tc.first), "byte 0x%02X", tc.first)
	}
}

// --- Variable-length encoding ---

func TestEncodeRemainingLength(t *testing.T) {
	cases := []struct {
		n    int
		want []byte
	}{
		{0, []byte{0x00}},
		{127, []byte{0x7F}},
		{128, []byte{0x80, 0x01}},
		{16383, []byte{0xFF, 0x7F}},
		{16384, []byte{0x80, 0x80, 0x01}},
	}
	for _, tc := range cases {
		got := mqtt.EncodeRemainingLength(tc.n)
		assert.Equal(t, tc.want, got, "n=%d", tc.n)
	}
}

func TestDecodeRemainingLength(t *testing.T) {
	cases := []struct {
		input []byte
		want  int
		bytes int // bytes consumed
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0x7F}, 127, 1},
		{[]byte{0x80, 0x01}, 128, 2},
		{[]byte{0xFF, 0x7F}, 16383, 2},
		{[]byte{0x80, 0x80, 0x01}, 16384, 3},
	}
	for _, tc := range cases {
		got, n, err := mqtt.DecodeRemainingLength(tc.input)
		require.NoError(t, err)
		assert.Equal(t, tc.want, got, "input=%v", tc.input)
		assert.Equal(t, tc.bytes, n, "input=%v", tc.input)
	}
}

func TestDecodeRemainingLength_Truncated(t *testing.T) {
	// Continuation bit set but no more bytes.
	_, _, err := mqtt.DecodeRemainingLength([]byte{0x80})
	require.Error(t, err)
}

// --- Helpers to build raw MQTT packets for tests ---

func buildConnect311(t *testing.T, clientID, username, password string) []byte {
	t.Helper()
	return buildConnectWithProtocol(t, "MQTT", 0x04, clientID, username, password)
}

func buildConnect311NoPassword(t *testing.T, clientID, username string) []byte {
	t.Helper()
	var buf bytes.Buffer
	// Variable header
	writeString(&buf, "MQTT")
	buf.WriteByte(0x04) // protocol level
	buf.WriteByte(0x80) // connect flags: username only (bit7=1, bit6=0)
	buf.WriteByte(0x00) // keep alive MSB
	buf.WriteByte(0x0A) // keep alive LSB = 10s
	// Payload
	writeString(&buf, clientID)
	writeString(&buf, username)
	return wrapConnect(buf.Bytes())
}

func buildConnect311Bare(t *testing.T, clientID string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writeString(&buf, "MQTT")
	buf.WriteByte(0x04)
	buf.WriteByte(0x00) // no username, no password
	buf.WriteByte(0x00)
	buf.WriteByte(0x0A)
	writeString(&buf, clientID)
	return wrapConnect(buf.Bytes())
}

func buildConnect50(t *testing.T, clientID, username, password string) []byte {
	t.Helper()
	return buildConnectWithProtocol(t, "MQTT", 0x05, clientID, username, password)
}

func buildConnectWithProtocol(t *testing.T, proto string, level byte, clientID, username, password string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writeString(&buf, proto)
	buf.WriteByte(level)
	buf.WriteByte(0xC0) // connect flags: username + password
	buf.WriteByte(0x00)
	buf.WriteByte(0x0A) // keep alive = 10s
	if level == 0x05 {
		buf.WriteByte(0x00) // MQTT 5.0 properties length = 0
	}
	writeString(&buf, clientID)
	writeString(&buf, username)
	writeBytes(&buf, []byte(password))
	return wrapConnect(buf.Bytes())
}

func wrapConnect(payload []byte) []byte {
	var out bytes.Buffer
	out.WriteByte(0x10) // CONNECT fixed header
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
