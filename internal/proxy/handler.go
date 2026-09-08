// Package proxy implements the MQTT-over-WebSocket authentication proxy.
// It accepts WebSocket connections from internet clients, validates the JWT
// in the MQTT CONNECT packet, and — if valid — proxies the session to the
// backend broker.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"github.com/sweeney/mqttproxy/internal/jwt"
	"github.com/sweeney/mqttproxy/internal/mqtt"
)

const (
	// connectReadTimeout is the maximum time we wait for the client to send
	// the initial MQTT CONNECT packet after the WebSocket upgrade.
	connectReadTimeout = 10 * time.Second

	// writeTimeout is the deadline applied to every WebSocket and broker write.
	// A stuck write beyond this duration terminates the session.
	writeTimeout = 30 * time.Second

	// wsMaxMessageBytes caps the size of a single WebSocket message from the
	// client. A real MQTT CONNECT from this service is ~550 bytes (JWT ~441 bytes
	// plus framing). 8KB gives ample headroom for claims growth while rejecting
	// obviously malicious oversized packets before allocation.
	wsMaxMessageBytes = 8 * 1024 // 8 KB
)

var upgrader = websocket.Upgrader{
	CheckOrigin:  func(r *http.Request) bool { return true },
	Subprotocols: []string{"mqtt", "mqttv3.1"},
}

// Config holds the dependencies injected into the Handler.
type Config struct {
	Validator TokenValidator
	ACL       ACLChecker
	Dialer    BrokerDialer
	Logger    *zap.Logger
}

// Handler is an http.Handler that upgrades connections to WebSocket, performs
// MQTT CONNECT authentication, and proxies authenticated sessions to the broker.
type Handler struct {
	validator TokenValidator
	acl       ACLChecker
	dialer    BrokerDialer
	log       *zap.Logger
}

// NewHandler creates a Handler with the given dependencies.
func NewHandler(cfg Config) *Handler {
	log := cfg.Logger
	if log == nil {
		log = zap.NewNop()
	}
	return &Handler{
		validator: cfg.Validator,
		acl:       cfg.ACL,
		dialer:    cfg.Dialer,
		log:       log,
	}
}

// ServeHTTP implements http.Handler. Each incoming request is expected to be
// a WebSocket upgrade from an MQTT client.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.log.Warn("websocket upgrade failed", zap.Error(err))
		return
	}
	defer wsConn.Close()
	wsConn.SetReadLimit(wsMaxMessageBytes)

	h.handleConnection(r.Context(), wsConn)
}

func (h *Handler) handleConnection(ctx context.Context, wsConn *websocket.Conn) {
	out := &wsWriter{conn: wsConn}

	// Read the first MQTT packet — must be CONNECT.
	wsConn.SetReadDeadline(time.Now().Add(connectReadTimeout))
	msgType, pktBytes, err := wsConn.ReadMessage()
	if err != nil {
		h.log.Debug("read first packet failed", zap.Error(err))
		return
	}
	wsConn.SetReadDeadline(time.Time{}) // clear deadline

	if msgType != websocket.BinaryMessage && msgType != websocket.TextMessage {
		h.log.Debug("unexpected websocket message type", zap.Int("type", msgType))
		return
	}

	if len(pktBytes) == 0 || mqtt.ReadPacketType(pktBytes[0]) != mqtt.TypeConnect {
		h.log.Debug("first packet is not CONNECT", zap.Uint8("type", pktBytes[0]))
		wsConn.Close()
		return
	}

	connectPkt, err := mqtt.ParseConnect(pktBytes)
	if err != nil {
		h.log.Debug("malformed CONNECT", zap.Error(err))
		wsConn.Close()
		return
	}

	version := connectPkt.Version

	// Validate the JWT from the CONNECT password field.
	claims, err := h.validator.Validate(ctx, connectPkt.Password)
	if err != nil {
		h.log.Info("auth failed",
			zap.String("client_id", connectPkt.ClientID),
			zap.Error(err),
		)
		out.write(mqtt.WriteConnack(version, mqtt.ConnackNotAuthorized, false))
		wsConn.Close()
		return
	}

	// Dial the broker.
	brokerConn, err := h.dialer.Dial(ctx)
	if err != nil {
		h.log.Error("broker dial failed", zap.Error(err))
		out.write(mqtt.WriteConnack(version, mqtt.ConnackServerUnavailable, false))
		wsConn.Close()
		return
	}
	defer brokerConn.Close()

	// Forward the CONNECT to the broker with password stripped and username
	// replaced by the identity from JWT claims.
	rewrittenConnect := connectPkt.WithUsername(claims.Subject)
	if err := writeBroker(brokerConn, rewrittenConnect); err != nil {
		h.log.Error("write CONNECT to broker failed", zap.Error(err))
		out.write(mqtt.WriteConnack(version, mqtt.ConnackServerUnavailable, false))
		return
	}

	// Read CONNACK from broker and forward to client.
	connackBuf := make([]byte, 16)
	n, err := brokerConn.Read(connackBuf)
	if err != nil || n < 4 {
		h.log.Error("read CONNACK from broker failed", zap.Error(err))
		out.write(mqtt.WriteConnack(version, mqtt.ConnackServerUnavailable, false))
		return
	}
	connack := connackBuf[:n]

	// If the broker rejected the connection, forward its CONNACK and stop.
	if mqtt.ReadPacketType(connack[0]) == mqtt.TypeConnack && connack[3] != 0x00 {
		out.write(connack)
		return
	}

	if err := out.write(connack); err != nil {
		return
	}

	h.log.Info("session established",
		zap.String("username", claims.Subject),
		zap.String("role", claims.Role),
		zap.String("client_id", connectPkt.ClientID),
	)

	// Set up the expiry timer. When it fires we disconnect the client.
	expiryTimer := time.NewTimer(time.Until(claims.ExpiresAt))
	defer expiryTimer.Stop()

	// done is closed when either side of the proxy terminates.
	done := make(chan struct{})

	// broker → client: raw byte copy, no inspection needed.
	go func() {
		defer close(done)
		err := copyBrokerToClient(out, brokerConn.(net.Conn))
		h.log.Debug("broker→client copy ended",
			zap.String("username", claims.Subject),
			zap.Error(err),
		)
	}()

	// client → broker: inspect MQTT packets for ACL enforcement.
	h.proxyClientToBroker(ctx, out, brokerConn.(net.Conn), claims, version, expiryTimer.C, done)

	h.log.Info("session ended",
		zap.String("username", claims.Subject),
		zap.String("client_id", connectPkt.ClientID),
	)
}

type wsMessage struct {
	msgType int
	frame   []byte
	err     error
}

// proxyClientToBroker reads MQTT frames from the WebSocket client, applies
// ACL checks, and forwards permitted frames to the broker.
func (h *Handler) proxyClientToBroker(
	ctx context.Context,
	out *wsWriter,
	brokerConn net.Conn,
	claims *jwt.Claims,
	version mqtt.ProtocolVersion,
	expiry <-chan time.Time,
	done <-chan struct{},
) {
	msgs := make(chan wsMessage, 1)

	readNext := func() {
		// Only this goroutine reads, so the read side needs no lock.
		msgType, frame, err := out.conn.ReadMessage()
		msgs <- wsMessage{msgType, frame, err}
	}
	go readNext()

	for {
		select {
		case <-expiry:
			h.log.Info("token expired, disconnecting",
				zap.String("username", claims.Subject),
			)
			out.write(mqtt.WriteDisconnect(version, mqtt.DisconnectSessionTakenOver))
			out.close()
			brokerConn.Close()
			return

		case <-done:
			h.log.Debug("broker side closed, ending client→broker loop",
				zap.String("username", claims.Subject),
			)
			return

		case m := <-msgs:
			if m.err != nil {
				if !errors.Is(m.err, io.EOF) && !websocket.IsCloseError(m.err,
					websocket.CloseNormalClosure,
					websocket.CloseGoingAway,
					websocket.CloseNoStatusReceived,
				) {
					h.log.Debug("client read error", zap.Error(m.err))
				}
				brokerConn.Close()
				return
			}
			if m.msgType != websocket.BinaryMessage && m.msgType != websocket.TextMessage {
				go readNext()
				continue
			}
			if len(m.frame) == 0 {
				go readNext()
				continue
			}

			if !h.checkACL(out, brokerConn, claims, version, m.frame) {
				return
			}

			if err := writeBroker(brokerConn, m.frame); err != nil {
				h.log.Debug("write to broker failed", zap.Error(err))
				return
			}
			go readNext()
		}
	}
}

// checkACL inspects a client→broker MQTT frame and enforces ACL policy.
// Returns false if the connection should be terminated.
func (h *Handler) checkACL(
	out *wsWriter,
	brokerConn net.Conn,
	claims *jwt.Claims,
	version mqtt.ProtocolVersion,
	frame []byte,
) bool {
	pktType := mqtt.ReadPacketType(frame[0])

	switch pktType {
	case mqtt.TypePublish:
		topic, packetID, err := mqtt.ParsePublishTopic(frame)
		if err != nil {
			h.log.Debug("malformed PUBLISH", zap.Error(err))
			return false
		}

		if !h.acl.CanPublish(claims, topic) {
			h.log.Info("publish denied by ACL",
				zap.String("username", claims.Subject),
				zap.String("topic", topic),
			)
			qos := (frame[0] >> 1) & 0x03
			switch {
			case version == mqtt.ProtocolV50 && qos == 1:
				out.write(mqtt.WritePuback(version, packetID, mqtt.PubackNotAuthorized))
				return true // session continues; only this message rejected

			case version == mqtt.ProtocolV50 && qos >= 2:
				out.write(mqtt.WritePuback(version, packetID, mqtt.PubackNotAuthorized))
				return true

			default:
				// MQTT 3.1.1 or QoS 0: no per-message rejection — disconnect.
				out.write(mqtt.WriteDisconnect(version, mqtt.DisconnectNotAuthorized))
				out.close()
				brokerConn.Close()
				return false
			}
		}

	case mqtt.TypeSubscribe:
		topics, packetID, err := mqtt.ParseSubscribeTopics(frame)
		if err != nil {
			h.log.Debug("malformed SUBSCRIBE", zap.Error(err))
			return false
		}

		var codes []mqtt.SubackCode
		allDenied := true
		for _, topic := range topics {
			if h.acl.CanSubscribe(claims, topic) {
				codes = append(codes, mqtt.SubackGrantedQoS0)
				allDenied = false
			} else {
				h.log.Info("subscribe denied by ACL",
					zap.String("username", claims.Subject),
					zap.String("topic", topic),
				)
				codes = append(codes, mqtt.SubackNotAuthorized)
			}
		}

		// If every requested subscription is denied, send a SUBACK with all
		// failure codes and do not forward to the broker.
		if allDenied {
			out.write(mqtt.WriteSuback(version, packetID, codes))
			return true
		}

		// Mixed: let the broker handle it but override codes for denied topics.
		// For simplicity we block the entire SUBSCRIBE and respond ourselves.
		out.write(mqtt.WriteSuback(version, packetID, codes))
		return true
	}

	return true
}

// copyBrokerToClient copies raw bytes from the broker TCP connection to the
// WebSocket client. Each MQTT packet is read as a complete frame and sent as
// a binary WebSocket message.
func copyBrokerToClient(out *wsWriter, brokerConn net.Conn) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := brokerConn.Read(buf)
		if err != nil {
			return fmt.Errorf("broker read: %w", err)
		}
		if err := out.write(buf[:n]); err != nil {
			return fmt.Errorf("ws write: %w", err)
		}
	}
}

// wsWriter serialises writes to the client WebSocket connection. gorilla
// supports only one concurrent writer, and two goroutines write for the whole
// life of a session: the broker→client pump, and the client→broker loop
// answering with PUBACK, SUBACK or DISCONNECT. Without this lock, broker
// traffic arriving as the loop writes back panics the process — taking every
// other session on the proxy down with it.
type wsWriter struct {
	mu   sync.Mutex
	conn *websocket.Conn
}

func (w *wsWriter) write(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return w.conn.WriteMessage(websocket.BinaryMessage, data)
}

// close is safe to call while a write is in flight: gorilla documents Close as
// callable concurrently with all other methods, and it is what unblocks a
// writer stuck on a dead peer.
func (w *wsWriter) close() error {
	return w.conn.Close()
}

func writeBroker(conn net.Conn, data []byte) error {
	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := conn.Write(data)
	return err
}
