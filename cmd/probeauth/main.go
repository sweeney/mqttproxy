// probeauth attempts MQTT-over-WebSocket connections with invalid or malicious
// inputs to verify the proxy correctly rejects them.
//
// Usage:
//
//	go run ./cmd/probeauth [-addr ws://localhost:8883/mqtt] [-slow]
//
// -slow includes the connect-then-silence test which waits 12 seconds for the
// proxy's connectReadTimeout to fire.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// kid observed from id.swee.net — using the real kid causes the proxy to fetch
// the real public key before failing on the forged signature, exercising the
// JWKS lookup + signature verification path rather than just key-not-found.
const realKID = "AEQrEEyvCaA"

func main() {
	addr := flag.String("addr", "ws://localhost:8883/mqtt", "proxy WebSocket URL")
	slow := flag.Bool("slow", false, "include tests that wait for server-side timeouts (~12s)")
	flag.Parse()

	type testCase struct {
		section string
		name    string
		fn      func() string
	}

	cases := []testCase{
		// ── Basic credential tests ────────────────────────────────────────────
		{"credentials", "no credentials", func() string {
			return probeConnect(*addr, "", "")
		}},
		{"credentials", "username only, no password", func() string {
			return probeConnect(*addr, "someuser", "")
		}},
		{"credentials", "fake credentials (test/test)", func() string {
			return probeConnect(*addr, "test", "test")
		}},

		// ── Protocol abuse ────────────────────────────────────────────────────
		{"protocol abuse", "PUBLISH as first packet (not CONNECT)", func() string {
			return probeRaw(*addr, []byte{0x30, 0x0A, 0x00, 0x05, 't', 'e', 's', 't', '/', '1', 'x', 'x'})
		}},
		{"protocol abuse", "SUBSCRIBE as first packet (not CONNECT)", func() string {
			return probeRaw(*addr, []byte{0x82, 0x02, 0x00, 0x01})
		}},
		{"protocol abuse", "truncated packet (2 bytes)", func() string {
			return probeRaw(*addr, []byte{0x10, 0x05})
		}},
		{"protocol abuse", "garbage bytes", func() string {
			return probeRaw(*addr, []byte{0xFF, 0xFE, 0xAB, 0xCD, 0x00, 0x00})
		}},
		{"protocol abuse", "oversized message (>8KB read limit)", func() string {
			return probeRaw(*addr, make([]byte, 9*1024))
		}},

		// ── Token attacks ─────────────────────────────────────────────────────
		{"token attacks", "not a JWT (plain string)", func() string {
			return probeConnect(*addr, "user", "notavalidtoken")
		}},
		{"token attacks", "two-part JWT (missing signature)", func() string {
			return probeConnect(*addr, "user", "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1In0")
		}},
		{"token attacks", "unknown kid — key not found", func() string {
			return probeConnect(*addr, "user", forgeJWT("unknown-kid-xyz", validClaims()))
		}},
		{"token attacks", "real kid, forged signature — sig verification fails", func() string {
			return probeConnect(*addr, "user", forgeJWT(realKID, validClaims()))
		}},
		{"token attacks", "real kid, expired exp claim", func() string {
			claims := validClaims()
			claims["exp"] = time.Now().Add(-10 * time.Minute).Unix()
			return probeConnect(*addr, "user", forgeJWT(realKID, claims))
		}},
		{"token attacks", "real kid, wrong issuer", func() string {
			claims := validClaims()
			claims["iss"] = "https://evil.example.com"
			return probeConnect(*addr, "user", forgeJWT(realKID, claims))
		}},
		{"token attacks", "real kid, act: false (inactive user)", func() string {
			claims := validClaims()
			claims["act"] = false
			return probeConnect(*addr, "user", forgeJWT(realKID, claims))
		}},
		{"token attacks", "real kid, missing rol claim", func() string {
			claims := validClaims()
			delete(claims, "rol")
			return probeConnect(*addr, "user", forgeJWT(realKID, claims))
		}},
		{"token attacks", "token exactly at 8KB limit", func() string {
			// Build a CONNECT where the password brings the total just under 8KB.
			padding := strings.Repeat("A", 7*1024)
			return probeConnect(*addr, "user", padding)
		}},
		{"token attacks", "token just over 8KB limit", func() string {
			padding := strings.Repeat("A", 8*1024+1)
			return probeConnect(*addr, "user", padding)
		}},
	}

	if *slow {
		cases = append(cases, testCase{
			"protocol abuse", "WebSocket connect then silence (waits for 10s server timeout)", func() string {
				return probeSilence(*addr)
			},
		})
	}

	section := ""
	for _, tc := range cases {
		if tc.section != section {
			section = tc.section
			fmt.Printf("\n━━ %s ━━\n", strings.ToUpper(section))
		}
		fmt.Printf("  %-55s  %s\n", tc.name, tc.fn())
	}
	fmt.Println()
}

// ── Probe helpers ─────────────────────────────────────────────────────────────

func dial(addr string) (*websocket.Conn, error) {
	d := websocket.Dialer{
		Subprotocols:     []string{"mqtt"},
		HandshakeTimeout: 5 * time.Second,
	}
	conn, _, err := d.Dial(addr, http.Header{})
	return conn, err
}

// probeConnect sends a MQTT CONNECT with the given credentials and reads the response.
func probeConnect(addr, username, password string) string {
	conn, err := dial(addr)
	if err != nil {
		return fmt.Sprintf("dial failed: %v", err)
	}
	defer conn.Close()

	conn.WriteMessage(websocket.BinaryMessage, buildConnect(username, password))
	return readOne(conn, 3*time.Second)
}

// probeRaw sends arbitrary bytes as the first WebSocket message.
func probeRaw(addr string, payload []byte) string {
	conn, err := dial(addr)
	if err != nil {
		return fmt.Sprintf("dial failed: %v", err)
	}
	defer conn.Close()

	conn.WriteMessage(websocket.BinaryMessage, payload)
	return readOne(conn, 3*time.Second)
}

// probeSilence connects via WebSocket and sends nothing, waiting for the proxy
// to enforce connectReadTimeout.
func probeSilence(addr string) string {
	conn, err := dial(addr)
	if err != nil {
		return fmt.Sprintf("dial failed: %v", err)
	}
	defer conn.Close()

	return readOne(conn, 12*time.Second)
}

func readOne(conn *websocket.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		if websocket.IsCloseError(err,
			websocket.CloseNormalClosure,
			websocket.CloseGoingAway,
			websocket.ClosePolicyViolation,
			websocket.CloseProtocolError,
			websocket.CloseNoStatusReceived,
		) {
			return fmt.Sprintf("connection closed by server (WS close code %v) ✓", closeCode(err))
		}
		return fmt.Sprintf("connection terminated: %v ✓", err)
	}
	return interpretMQTT(msg)
}

func closeCode(err error) string {
	if e, ok := err.(*websocket.CloseError); ok {
		return fmt.Sprintf("%d", e.Code)
	}
	return "unknown"
}

// ── MQTT helpers ──────────────────────────────────────────────────────────────

func buildConnect(username, password string) []byte {
	var flags byte
	if username != "" {
		flags |= 0x80
	}
	if password != "" {
		flags |= 0x40
	}

	var payload []byte
	payload = appendString(payload, "MQTT")
	payload = append(payload, 0x04)         // MQTT 3.1.1
	payload = append(payload, flags)
	payload = append(payload, 0x00, 0x1E)   // keepalive 30s
	payload = appendString(payload, "probeauth-client")
	if username != "" {
		payload = appendString(payload, username)
	}
	if password != "" {
		payload = appendBytes(payload, []byte(password))
	}

	pkt := []byte{0x10}
	pkt = appendVarInt(pkt, len(payload))
	return append(pkt, payload...)
}

func interpretMQTT(msg []byte) string {
	if len(msg) == 0 {
		return "empty message"
	}
	pktType := msg[0] >> 4
	switch pktType {
	case 0x02: // CONNACK
		if len(msg) < 4 {
			return fmt.Sprintf("short CONNACK (%d bytes)", len(msg))
		}
		switch msg[3] {
		case 0x00:
			return "CONNACK 0x00 — ACCEPTED ✗ (should not happen)"
		case 0x05:
			return "CONNACK 0x05 — NOT AUTHORISED ✓"
		default:
			return fmt.Sprintf("CONNACK 0x%02x", msg[3])
		}
	case 0x0E:
		return fmt.Sprintf("DISCONNECT (reason 0x%02x) ✓", disconnectReason(msg))
	default:
		return fmt.Sprintf("unexpected packet type 0x%02x: %x", pktType, msg)
	}
}

func disconnectReason(msg []byte) byte {
	if len(msg) >= 3 {
		return msg[2]
	}
	return 0
}

// ── JWT forgery helpers ───────────────────────────────────────────────────────

func validClaims() map[string]any {
	return map[string]any{
		"iss": "https://id.swee.net",
		"sub": "probe-user",
		"aud": []string{"mqttproxy"},
		"exp": time.Now().Add(15 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
		"usr": "probe_user",
		"rol": "user",
		"act": true,
	}
}

// forgeJWT builds a JWT with the given kid and claims but a zeroed-out
// signature. It will fail signature verification but exercises all earlier
// steps (header parsing, JWKS key lookup, claim extraction).
func forgeJWT(kid string, claims map[string]any) string {
	header := b64j(map[string]any{
		"alg": "ES256",
		"kid": kid,
		"typ": "JWT",
	})
	payload := b64j(claims)
	// ES256 signature is 64 bytes = 86 base64url chars. Use zeros.
	sig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	return header + "." + payload + "." + sig
}

func b64j(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ── Byte builders ─────────────────────────────────────────────────────────────

func appendString(b []byte, s string) []byte {
	b = append(b, byte(len(s)>>8), byte(len(s)))
	return append(b, s...)
}

func appendBytes(b []byte, data []byte) []byte {
	b = append(b, byte(len(data)>>8), byte(len(data)))
	return append(b, data...)
}

func appendVarInt(b []byte, n int) []byte {
	for {
		digit := n % 128
		n /= 128
		if n > 0 {
			digit |= 0x80
		}
		b = append(b, byte(digit))
		if n == 0 {
			break
		}
	}
	return b
}
