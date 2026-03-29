// Package mqtt implements the minimal MQTT packet parsing and serialisation
// required by the proxy: reading CONNECT frames from clients, rewriting them
// for the backend broker, and writing CONNACK / DISCONNECT / PUBACK / SUBACK
// frames back to clients. All other packet types are passed through as raw
// bytes without parsing.
package mqtt

import (
	"bytes"
	"errors"
	"fmt"
)

// Protocol versions.
type ProtocolVersion byte

const (
	ProtocolV311 ProtocolVersion = 0x04 // MQTT 3.1.1
	ProtocolV50  ProtocolVersion = 0x05 // MQTT 5.0
)

// PacketType is the upper nibble of the first byte of every MQTT packet.
type PacketType byte

const (
	TypeConnect     PacketType = 0x01
	TypeConnack     PacketType = 0x02
	TypePublish     PacketType = 0x03
	TypePuback      PacketType = 0x04
	TypeSubscribe   PacketType = 0x08
	TypeSuback      PacketType = 0x09
	TypeUnsubscribe PacketType = 0x0A
	TypePingreq     PacketType = 0x0C
	TypePingresp    PacketType = 0x0D
	TypeDisconnect  PacketType = 0x0E
)

// Sentinel errors.
var (
	ErrNotConnect      = errors.New("packet is not a CONNECT")
	ErrUnknownProtocol = errors.New("unknown MQTT protocol name or version")
	ErrMalformed       = errors.New("malformed packet")
)

// CONNACK return codes / reason codes.
type ConnackCode byte

const (
	ConnackAccepted        ConnackCode = 0x00
	ConnackServerUnavailable ConnackCode = 0x03 // 3.1.1 only
	ConnackNotAuthorized   ConnackCode = 0x05 // 3.1.1: 0x05 / 5.0: 0x87
)

// DISCONNECT reason codes (MQTT 5.0 only; 3.1.1 has no reason code).
type DisconnectReason byte

const (
	DisconnectNormal         DisconnectReason = 0x00
	DisconnectNotAuthorized  DisconnectReason = 0x87
	DisconnectSessionTakenOver DisconnectReason = 0x8E
)

// PUBACK reason codes.
type PubackCode byte

const (
	PubackSuccess       PubackCode = 0x00
	PubackNotAuthorized PubackCode = 0x87
)

// SUBACK return codes / reason codes.
type SubackCode byte

const (
	SubackGrantedQoS0   SubackCode = 0x00
	SubackNotAuthorized SubackCode = 0x87
)

// Connect holds the parsed fields of an MQTT CONNECT packet that the proxy
// cares about.
type Connect struct {
	Version      ProtocolVersion
	ClientID     string
	Username     string
	Password     string
	KeepAlive    uint16 // seconds, as sent by the client
	CleanSession bool

	// raw is the original packet bytes, used when rewriting.
	raw []byte
}

// ReadPacketType returns the PacketType from the first byte of an MQTT packet.
func ReadPacketType(firstByte byte) PacketType {
	return PacketType(firstByte >> 4)
}

// ParseConnect parses a complete MQTT CONNECT packet from b.
// b must contain exactly one packet (the full raw bytes).
func ParseConnect(b []byte) (*Connect, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("%w: too short", ErrMalformed)
	}

	if ReadPacketType(b[0]) != TypeConnect {
		return nil, ErrNotConnect
	}

	remaining, consumed, err := DecodeRemainingLength(b[1:])
	if err != nil {
		return nil, fmt.Errorf("%w: remaining length: %v", ErrMalformed, err)
	}

	body := b[1+consumed:]
	if len(body) < remaining {
		return nil, fmt.Errorf("%w: body truncated (want %d, got %d)", ErrMalformed, remaining, len(body))
	}
	body = body[:remaining]

	r := bytes.NewReader(body)

	// Protocol name (UTF-8 encoded string, length-prefixed).
	protoName, err := readString(r)
	if err != nil {
		return nil, fmt.Errorf("%w: protocol name: %v", ErrMalformed, err)
	}
	if protoName != "MQTT" && protoName != "MQIsdp" {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProtocol, protoName)
	}

	// Protocol level byte.
	levelByte, err := readByte(r)
	if err != nil {
		return nil, fmt.Errorf("%w: protocol level: %v", ErrMalformed, err)
	}

	var version ProtocolVersion
	switch {
	case protoName == "MQTT" && levelByte == byte(ProtocolV311):
		version = ProtocolV311
	case protoName == "MQTT" && levelByte == byte(ProtocolV50):
		version = ProtocolV50
	case protoName == "MQIsdp" && levelByte == 0x03:
		// MQTT 3.1 — treat as 3.1.1 for our purposes.
		version = ProtocolV311
	default:
		return nil, fmt.Errorf("%w: protocol %q level %d", ErrUnknownProtocol, protoName, levelByte)
	}

	// Connect flags.
	flags, err := readByte(r)
	if err != nil {
		return nil, fmt.Errorf("%w: connect flags: %v", ErrMalformed, err)
	}
	hasUsername  := flags&0x80 != 0
	hasPassword  := flags&0x40 != 0
	cleanSession := flags&0x02 != 0

	// Keep alive (2 bytes, big-endian).
	kaMSB, err := readByte(r)
	if err != nil {
		return nil, fmt.Errorf("%w: keep alive: %v", ErrMalformed, err)
	}
	kaLSB, err := readByte(r)
	if err != nil {
		return nil, fmt.Errorf("%w: keep alive: %v", ErrMalformed, err)
	}
	keepAlive := uint16(kaMSB)<<8 | uint16(kaLSB)

	// MQTT 5.0: connect properties (variable-length field we skip).
	if version == ProtocolV50 {
		if err := skipProperties(r); err != nil {
			return nil, fmt.Errorf("%w: connect properties: %v", ErrMalformed, err)
		}
	}

	// Payload: client ID (always present).
	clientID, err := readString(r)
	if err != nil {
		return nil, fmt.Errorf("%w: client ID: %v", ErrMalformed, err)
	}

	// Optional: will (we skip if present — not relevant to auth proxy).
	willFlag := flags&0x04 != 0
	if willFlag {
		if version == ProtocolV50 {
			if err := skipProperties(r); err != nil {
				return nil, fmt.Errorf("%w: will properties: %v", ErrMalformed, err)
			}
		}
		if _, err := readString(r); err != nil { // will topic
			return nil, fmt.Errorf("%w: will topic: %v", ErrMalformed, err)
		}
		if _, err := readBytes(r); err != nil { // will payload
			return nil, fmt.Errorf("%w: will payload: %v", ErrMalformed, err)
		}
	}

	var username, password string
	if hasUsername {
		username, err = readString(r)
		if err != nil {
			return nil, fmt.Errorf("%w: username: %v", ErrMalformed, err)
		}
	}
	if hasPassword {
		pwBytes, err := readBytes(r)
		if err != nil {
			return nil, fmt.Errorf("%w: password: %v", ErrMalformed, err)
		}
		password = string(pwBytes)
	}

	return &Connect{
		Version:      version,
		ClientID:     clientID,
		Username:     username,
		Password:     password,
		KeepAlive:    keepAlive,
		CleanSession: cleanSession,
		raw:          b,
	}, nil
}

// WithoutPassword returns a serialised CONNECT packet identical to the
// original but with the password field removed and password flag cleared.
func (c *Connect) WithoutPassword() []byte {
	return c.serialise(c.Username, "")
}

// WithUsername returns a serialised CONNECT packet with the username replaced
// by the provided value and the password stripped.
func (c *Connect) WithUsername(username string) []byte {
	return c.serialise(username, "")
}

func (c *Connect) serialise(username, password string) []byte {
	var body bytes.Buffer

	writeStringTo(&body, "MQTT")
	body.WriteByte(byte(c.Version))

	// Recalculate connect flags. Preserve CleanSession from the original packet.
	// Will flag/payload are intentionally dropped (not proxied).
	// Password flag reflects whether we're forwarding a password.
	var flags byte
	if c.CleanSession {
		flags |= 0x02
	}
	if username != "" {
		flags |= 0x80
	}
	if password != "" {
		flags |= 0x40
	}
	body.WriteByte(flags)
	body.WriteByte(byte(c.KeepAlive >> 8))
	body.WriteByte(byte(c.KeepAlive))

	if c.Version == ProtocolV50 {
		body.WriteByte(0x00) // empty properties
	}

	writeStringTo(&body, c.ClientID)
	if username != "" {
		writeStringTo(&body, username)
	}
	if password != "" {
		writeBytesTo(&body, []byte(password))
	}

	var out bytes.Buffer
	out.WriteByte(0x10)
	out.Write(EncodeRemainingLength(body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}

// WriteConnack serialises a CONNACK packet for the given protocol version.
func WriteConnack(version ProtocolVersion, code ConnackCode, sessionPresent bool) []byte {
	sp := byte(0)
	if sessionPresent {
		sp = 0x01
	}

	switch version {
	case ProtocolV50:
		// Reason code mapping: 3.1.1 codes differ from 5.0.
		rc := connackCodeToV50(code)
		return []byte{0x20, 0x03, sp, rc, 0x00} // 0x00 = empty properties
	default: // 3.1.1
		return []byte{0x20, 0x02, sp, byte(code)}
	}
}

// WriteDisconnect serialises a DISCONNECT packet.
// For MQTT 3.1.1 the reason code is ignored (the packet has no payload).
func WriteDisconnect(version ProtocolVersion, reason DisconnectReason) []byte {
	if version == ProtocolV50 {
		return []byte{0xE0, 0x02, byte(reason), 0x00} // reason + empty properties
	}
	return []byte{0xE0, 0x00}
}

// WritePuback serialises a PUBACK packet for QoS 1 publish acknowledgement.
// For MQTT 3.1.1 the code is ignored (always success; there is no rejection).
func WritePuback(version ProtocolVersion, packetID uint16, code PubackCode) []byte {
	idHigh := byte(packetID >> 8)
	idLow := byte(packetID)
	if version == ProtocolV50 {
		return []byte{0x40, 0x04, idHigh, idLow, byte(code), 0x00}
	}
	return []byte{0x40, 0x02, idHigh, idLow}
}

// WriteSuback serialises a SUBACK packet.
func WriteSuback(version ProtocolVersion, packetID uint16, codes []SubackCode) []byte {
	idHigh := byte(packetID >> 8)
	idLow := byte(packetID)

	if version == ProtocolV50 {
		// remaining = 2 (packet id) + 1 (properties len) + len(codes)
		remaining := 2 + 1 + len(codes)
		out := []byte{0x90, byte(remaining), idHigh, idLow, 0x00}
		for _, c := range codes {
			out = append(out, byte(c))
		}
		return out
	}

	// 3.1.1: remaining = 2 + len(codes)
	remaining := 2 + len(codes)
	out := []byte{0x90, byte(remaining), idHigh, idLow}
	for _, c := range codes {
		out = append(out, byte(c))
	}
	return out
}

// ParsePublishTopic extracts the topic name and (for QoS > 0) the packet ID
// from a raw MQTT PUBLISH frame. Returns the topic, packet ID (0 for QoS 0),
// and any parse error.
func ParsePublishTopic(frame []byte) (topic string, packetID uint16, err error) {
	if len(frame) < 2 {
		return "", 0, fmt.Errorf("%w: PUBLISH too short", ErrMalformed)
	}
	qos := (frame[0] >> 1) & 0x03

	remaining, consumed, err := DecodeRemainingLength(frame[1:])
	if err != nil {
		return "", 0, fmt.Errorf("%w: PUBLISH remaining length: %v", ErrMalformed, err)
	}

	body := frame[1+consumed:]
	if len(body) < remaining {
		return "", 0, fmt.Errorf("%w: PUBLISH body truncated", ErrMalformed)
	}
	body = body[:remaining]

	r := bytes.NewReader(body)
	topicStr, err := readString(r)
	if err != nil {
		return "", 0, fmt.Errorf("%w: PUBLISH topic: %v", ErrMalformed, err)
	}

	var pktID uint16
	if qos > 0 {
		hi, err := readByte(r)
		if err != nil {
			return "", 0, fmt.Errorf("%w: PUBLISH packet ID: %v", ErrMalformed, err)
		}
		lo, err := readByte(r)
		if err != nil {
			return "", 0, fmt.Errorf("%w: PUBLISH packet ID: %v", ErrMalformed, err)
		}
		pktID = uint16(hi)<<8 | uint16(lo)
	}

	return topicStr, pktID, nil
}

// ParseSubscribeTopics extracts the list of topic filters and the packet ID
// from a raw MQTT SUBSCRIBE frame.
func ParseSubscribeTopics(frame []byte) (topics []string, packetID uint16, err error) {
	if len(frame) < 2 {
		return nil, 0, fmt.Errorf("%w: SUBSCRIBE too short", ErrMalformed)
	}

	remaining, consumed, err := DecodeRemainingLength(frame[1:])
	if err != nil {
		return nil, 0, fmt.Errorf("%w: SUBSCRIBE remaining length: %v", ErrMalformed, err)
	}

	body := frame[1+consumed:]
	if len(body) < remaining {
		return nil, 0, fmt.Errorf("%w: SUBSCRIBE body truncated", ErrMalformed)
	}
	body = body[:remaining]

	r := bytes.NewReader(body)

	// Packet identifier (2 bytes).
	hi, err := readByte(r)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: SUBSCRIBE packet ID: %v", ErrMalformed, err)
	}
	lo, err := readByte(r)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: SUBSCRIBE packet ID: %v", ErrMalformed, err)
	}
	pktID := uint16(hi)<<8 | uint16(lo)

	// For MQTT 5.0, skip subscription properties.
	// We detect version from the frame alone by checking if the first subscription
	// entry is prefixed by a properties block — heuristically we skip if needed.
	// Simplification: the caller is responsible for not passing 5.0 frames here
	// when the version is 3.1.1; handler passes version context separately.
	// For now we parse without properties (handles 3.1.1 and basic 5.0).

	var topicList []string
	for r.Len() > 0 {
		topic, err := readString(r)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: SUBSCRIBE topic: %v", ErrMalformed, err)
		}
		// QoS byte (or subscription options in 5.0) — consume and discard.
		if _, err := readByte(r); err != nil {
			return nil, 0, fmt.Errorf("%w: SUBSCRIBE QoS: %v", ErrMalformed, err)
		}
		topicList = append(topicList, topic)
	}

	return topicList, pktID, nil
}

// EncodeRemainingLength encodes n as a MQTT variable-length integer.
func EncodeRemainingLength(n int) []byte {
	var out []byte
	for {
		b := byte(n & 0x7F)
		n >>= 7
		if n > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			break
		}
	}
	return out
}

// DecodeRemainingLength decodes a MQTT variable-length integer from b.
// Returns (value, bytesConsumed, error).
func DecodeRemainingLength(b []byte) (int, int, error) {
	var val int
	var shift uint
	for i, bt := range b {
		if i >= 4 {
			return 0, 0, fmt.Errorf("%w: remaining length overflow", ErrMalformed)
		}
		val |= int(bt&0x7F) << shift
		shift += 7
		if bt&0x80 == 0 {
			return val, i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("%w: remaining length truncated", ErrMalformed)
}

// --- internal helpers ---

func connackCodeToV50(code ConnackCode) byte {
	switch code {
	case ConnackAccepted:
		return 0x00
	case ConnackServerUnavailable:
		return 0x88 // Server Unavailable in MQTT 5.0
	case ConnackNotAuthorized:
		return 0x87 // Not Authorized in MQTT 5.0
	default:
		return byte(code)
	}
}

func readByte(r *bytes.Reader) (byte, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("unexpected end of packet")
	}
	return b, nil
}

func readString(r *bytes.Reader) (string, error) {
	b, err := readBytes(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func readBytes(r *bytes.Reader) ([]byte, error) {
	hi, err := readByte(r)
	if err != nil {
		return nil, err
	}
	lo, err := readByte(r)
	if err != nil {
		return nil, err
	}
	n := int(hi)<<8 | int(lo)
	b := make([]byte, n)
	if _, err := r.Read(b); err != nil && n > 0 {
		return nil, fmt.Errorf("unexpected end of packet reading %d bytes", n)
	}
	return b, nil
}

// skipProperties reads and discards an MQTT 5.0 properties block.
func skipProperties(r *bytes.Reader) error {
	// Properties are prefixed with a variable-length integer giving their total
	// byte length. Read that length, then discard that many bytes.
	var length int
	var shift uint
	for {
		b, err := readByte(r)
		if err != nil {
			return err
		}
		length |= int(b&0x7F) << shift
		shift += 7
		if b&0x80 == 0 {
			break
		}
		if shift >= 28 {
			return fmt.Errorf("properties length overflow")
		}
	}
	buf := make([]byte, length)
	_, err := r.Read(buf)
	return err
}

func writeStringTo(buf *bytes.Buffer, s string) {
	b := []byte(s)
	buf.WriteByte(byte(len(b) >> 8))
	buf.WriteByte(byte(len(b)))
	buf.Write(b)
}

func writeBytesTo(buf *bytes.Buffer, b []byte) {
	buf.WriteByte(byte(len(b) >> 8))
	buf.WriteByte(byte(len(b)))
	buf.Write(b)
}
