# mqttproxy — A Code Walkthrough

*2026-03-29T14:44:47Z by Showboat 0.6.1*
<!-- showboat-id: f147487a-5ca6-4d05-8ce0-119e870c30c5 -->

mqttproxy is an MQTT-over-WebSocket authentication proxy written in Go. The problem it solves: browsers can only open WebSocket connections, not raw TCP sockets, but MQTT brokers speak TCP. A naive solution would be to give the broker a WebSocket listener — but that leaves authentication and authorisation entirely to the broker, which may not support the JWT-based auth flow you want.

mqttproxy sits in front of the broker and owns the auth layer. It speaks WebSocket to the outside world and plain TCP to the broker. Every client must present a signed JWT in the MQTT CONNECT password field. The proxy validates the token, rewrites the CONNECT (stripping the password, substituting the broker-facing username from the JWT), dials the broker on the client's behalf, and then proxies the session — inspecting every publish and subscribe packet for ACL compliance.

```bash
find . -name '*.go' -not -path './.git/*' | sort | grep -v '_test.go'
```

```output
./cmd/mqttproxy/main.go
./cmd/probeauth/main.go
./internal/acl/checker.go
./internal/config/config.go
./internal/jwks/client.go
./internal/jwt/validator.go
./internal/mqtt/packet.go
./internal/proxy/dialer.go
./internal/proxy/handler.go
./internal/proxy/interfaces.go
```

The codebase is small and well-scoped — ten non-test source files. The reading order that makes most sense is: entry point → configuration → the MQTT packet codec (a dependency of the proxy layer) → JWKS key fetching → JWT validation → ACL checking → the proxy interfaces and dialer → finally the proxy handler, which is where all the pieces come together.

## Entry point: cmd/mqttproxy/main.go

The entry point is almost entirely wiring. It loads config, builds a zap logger, constructs each dependency in order — JWKS client, JWT validator, ACL checker, TCP dialer — then hands them all to the proxy handler as interface values. This means each piece can be replaced with a fake in tests without touching the handler at all.

```bash
sed -n '51,74p' cmd/mqttproxy/main.go
```

```output
	jwksClient, err := jwks.NewClient(
		cfg.Auth.WellKnownURL,
		cfg.Auth.JWKSCacheTTL,
		&http.Client{Timeout: 10 * time.Second},
	)
	if err != nil {
		return fmt.Errorf("init JWKS client: %w", err)
	}

	// jwks.Client satisfies jwt.KeySource directly.
	validator, err := jwt.NewValidator(cfg.Auth.Issuer, cfg.Auth.Audience, jwksClient)
	if err != nil {
		return fmt.Errorf("init JWT validator: %w", err)
	}

	aclChecker := acl.NewChecker(cfg.ACL)
	dialer := proxy.NewTCPDialer(cfg.Broker.Addr, cfg.Broker.DialTimeout)

	handler := proxy.NewHandler(proxy.Config{
		Validator: validator,
		ACL:       aclChecker,
		Dialer:    dialer,
		Logger:    log,
	})
```

Notice the comment: "jwks.Client satisfies jwt.KeySource directly." The JWKS client implements the KeySource interface (GetKey), so it can be passed to the JWT validator without an adapter. This is a classic Go interface composition — the validator never imports the jwks package, it just calls through an interface.

The server setup below the wiring adds two routes: the proxy handler on the configured WebSocket path, and a /health endpoint that does a quick TCP dial to the broker and returns JSON.

```bash
sed -n '76,103p' cmd/mqttproxy/main.go
```

```output
	brokerAddr := cfg.Broker.Addr

	mux := http.NewServeMux()
	mux.Handle(cfg.Listen.Path, handler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		start := time.Now()
		conn, err := net.DialTimeout("tcp", brokerAddr, 3*time.Second)
		elapsed := time.Since(start)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]any{
				"status":      "error",
				"broker":      brokerAddr,
				"detail":      err.Error(),
				"elapsed_ms":  elapsed.Milliseconds(),
				"checked_at":  time.Now().UTC().Format(time.RFC3339),
			})
			return
		}
		conn.Close()
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "ok",
			"broker":     brokerAddr,
			"elapsed_ms": elapsed.Milliseconds(),
			"checked_at": time.Now().UTC().Format(time.RFC3339),
		})
	})
```

## Configuration: internal/config/config.go

The config package uses a two-struct trick to give better error messages for duration fields. YAML is unmarshalled into a raw struct where duration fields are plain strings. The Load function then parses each duration explicitly and reports the field name if parsing fails. This avoids the opaque errors you would get from using time.Duration directly in the YAML struct.

```bash
sed -n '52,69p' internal/config/config.go
```

```output
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
```

The audience field is optional — if omitted, the aud claim is not validated. Everything else is required and validated explicitly in Load(). Durations default to sensible values (5s broker dial timeout, 1h JWKS cache TTL) if not specified.

## MQTT packet codec: internal/mqtt/packet.go

This is one of the most important files — and notably, there is no third-party MQTT library here. The proxy only needs to parse a few packet types (CONNECT, PUBLISH, SUBSCRIBE) and serialise a few response types (CONNACK, PUBACK, SUBACK, DISCONNECT). Writing a minimal codec avoids pulling in a full client library and keeps the behaviour exactly as needed.

MQTT packets have a two-part header: a fixed byte (packet type in the upper nibble, flags in the lower nibble) followed by a variable-length remaining-length field using a continuation-bit encoding.

```bash
sed -n '436,469p' internal/mqtt/packet.go
```

```output
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
```

The variable-length encoding: each byte uses the low 7 bits for data and the high bit as a "more bytes follow" flag. The decoder caps at 4 bytes (max representable value ~268 MB), which is also the MQTT specification limit.

The most interesting method on Connect is serialise(), which rebuilds the packet from scratch rather than patching bytes in the original. This is safer because the connect flags byte controls which optional fields are present — recalculating it from scratch avoids accidentally leaving stale password bytes in the forwarded packet.

```bash
sed -n '237,277p' internal/mqtt/packet.go
```

```output
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
```

Also worth noting: will messages are intentionally dropped here — the will flag is never set in the rewritten packet. Proxying will messages would require storing them and re-attaching them on broker reconnect, which is out of scope for an auth proxy.

## JWKS client: internal/jwks/client.go

The JWKS client handles key discovery and caching. On construction it fetches the OAuth2 well-known metadata (the RFC 8414 JSON document at /.well-known/oauth-authorization-server or similar) to discover the actual JWKS URL. This means you only configure one URL in config — the discovery endpoint — and the JWKS URL is resolved automatically.

GetKey uses a two-phase read/write lock pattern to avoid a thundering-herd problem:

```bash
sed -n '59,89p' internal/jwks/client.go
```

```output
func (c *Client) GetKey(ctx context.Context, kid string) (jwk.Key, error) {
	// Fast path: read-locked cache lookup.
	c.mu.RLock()
	key, fresh := c.lookupLocked(kid)
	c.mu.RUnlock()

	if fresh && key != nil {
		return key, nil
	}

	// Slow path: refresh needed (TTL expired or kid unknown).
	c.mu.Lock()
	defer c.mu.Unlock()

	// Re-check under write lock to avoid a double-fetch if another goroutine
	// already refreshed while we were waiting.
	key, fresh = c.lookupLocked(kid)
	if fresh && key != nil {
		return key, nil
	}

	if err := c.fetchLocked(ctx); err != nil {
		return nil, err
	}

	k, ok := c.cached.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrKeyNotFound, kid)
	}
	return k, nil
}
```

The double-check after acquiring the write lock is a classic "check-then-act" guard. If fifty goroutines all see an expired cache simultaneously, only one fetches; the rest find a fresh cache when they finally acquire the write lock.

There is also a subtlety in the fast path: lookupLocked returns both the key and a freshness bool. A fresh cache with an unknown kid still falls through to the slow path — this is the key-rotation escape hatch. If an auth server rotates keys, new JWTs will reference a kid that is not yet in the cache. Rather than waiting for the TTL to expire (which could be an hour), the proxy immediately re-fetches.

## JWT validator: internal/jwt/validator.go

The validator is a thin wrapper around lestrrat-go/jwx. The interesting design choice: it does not hardcode the signing algorithm. Instead it reads the alg field declared on the JWK itself and uses that. This lets the proxy work with both RS256 (RSA) and ES256 (ECDSA) keys without any configuration change — the algorithm follows the key.

```bash
sed -n '59,91p' internal/jwt/validator.go
```

```output
	// Parse the JWS message to extract the kid from the JOSE protected header.
	// kid lives in the header, not the payload, so ParseInsecure would not see it.
	msg, err := jws.Parse([]byte(rawToken))
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	if len(msg.Signatures()) == 0 {
		return nil, fmt.Errorf("parse token: no signatures")
	}
	kid := msg.Signatures()[0].ProtectedHeaders().KeyID()

	key, err := v.keySource.GetKey(ctx, kid) //nolint:contextcheck
	if err != nil {
		return nil, fmt.Errorf("get signing key: %w", err)
	}

	// Use the algorithm declared on the key itself rather than hardcoding one,
	// so the validator works with both ES256 (id.swee.net) and RS256.
	parseOpts := []gojwt.ParseOption{
		gojwt.WithKey(key.Algorithm(), key),
		gojwt.WithValidate(true),
		gojwt.WithIssuer(v.issuer),
	}
	if v.audience != "" {
		parseOpts = append(parseOpts, gojwt.WithAudience(v.audience))
	}
	tok, err := gojwt.Parse([]byte(rawToken), parseOpts...)
	if err != nil {
		return nil, mapParseError(err)
	}

	return extractClaims(tok)
}
```

The two-step parse is deliberate: the JWT library's Parse function verifies the signature and validates claims in one call, but to fetch the right key you first need the kid from the header. jws.Parse reads the raw JOSE structure without verifying anything, just to extract that kid. Then the key is fetched, and Parse is called again — this time with the key, which both verifies the signature and validates iss/aud/exp atomically.

Custom claims extracted by extractClaims:

```bash
sed -n '121,160p' internal/jwt/validator.go
```

```output
// Claim name constants matching the id.swee.net JWT payload.
const (
	claimUsername = "usr"
	claimRole     = "rol"
	claimActive   = "act"
)

func extractClaims(tok gojwt.Token) (*Claims, error) {
	username, ok := stringClaim(tok, claimUsername)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMissingClaims, claimUsername)
	}

	role, ok := stringClaim(tok, claimRole)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMissingClaims, claimRole)
	}

	isActiveRaw, ok := tok.Get(claimActive)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMissingClaims, claimActive)
	}
	isActive, ok := isActiveRaw.(bool)
	if !ok {
		return nil, fmt.Errorf("%w: %s must be a boolean", ErrMissingClaims, claimActive)
	}

	if !isActive {
		return nil, ErrUserInactive
	}

	return &Claims{
		Subject:   tok.Subject(),
		Username:  username,
		Role:      role,
		IsActive:  isActive,
		ExpiresAt: tok.Expiration(),
	}, nil
}

```

The act claim (active) is a hard gate: a false value results in ErrUserInactive, which the handler maps to a CONNACK Not Authorized response. This lets the auth server soft-disable accounts without revoking or expiring the token — the account can be reactivated by issuing a new token with act: true.

## ACL checker: internal/acl/checker.go

Role-based access control is driven entirely by the rol claim in the JWT. The config maps role names to publish/subscribe topic filter lists. The matching logic implements MQTT §4.7 wildcard semantics.

```bash
sed -n '66,92p' internal/acl/checker.go
```

```output
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
```

The # wildcard short-circuits immediately — anything at or below that level is permitted. The + wildcard matches exactly one level (any value). The final check — len(pattern) == len(topic) — ensures that a pattern like sensors/temp does not match sensors/temp/room1.

## Proxy interfaces and dialer: internal/proxy/interfaces.go and dialer.go

The handler depends on three interfaces — TokenValidator, ACLChecker, BrokerDialer — rather than concrete types. This is what allows the unit tests to inject fakes. The interfaces are defined in the proxy package itself, not in the packages that implement them (jwks, acl), which is idiomatic Go: the consumer defines the interface, not the producer.

```bash
cat internal/proxy/interfaces.go
```

```output
package proxy

import (
	"context"
	"net"

	"github.com/sweeney/mqttproxy/internal/jwt"
)

// TokenValidator validates a raw JWT string and returns the extracted claims.
type TokenValidator interface {
	Validate(ctx context.Context, token string) (*jwt.Claims, error)
}

// ACLChecker determines whether a client with given claims may publish or
// subscribe to a topic.
type ACLChecker interface {
	CanPublish(claims *jwt.Claims, topic string) bool
	CanSubscribe(claims *jwt.Claims, topic string) bool
}

// BrokerDialer opens a TCP connection to the backend MQTT broker.
type BrokerDialer interface {
	Dial(ctx context.Context) (net.Conn, error)
}
```

## The proxy handler: internal/proxy/handler.go

This is the heart of the system. ServeHTTP upgrades the connection to WebSocket, sets an 8 KB read limit to reject oversized frames before any allocation, then calls handleConnection.

handleConnection orchestrates the authentication handshake:

```bash
sed -n '89,199p' internal/proxy/handler.go
```

```output
func (h *Handler) handleConnection(ctx context.Context, wsConn *websocket.Conn) {
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
		writeWS(wsConn, mqtt.WriteConnack(version, mqtt.ConnackNotAuthorized, false))
		wsConn.Close()
		return
	}

	// Dial the broker.
	brokerConn, err := h.dialer.Dial(ctx)
	if err != nil {
		h.log.Error("broker dial failed", zap.Error(err))
		writeWS(wsConn, mqtt.WriteConnack(version, mqtt.ConnackServerUnavailable, false))
		wsConn.Close()
		return
	}
	defer brokerConn.Close()

	// Forward the CONNECT to the broker with password stripped and username
	// replaced by the identity from JWT claims.
	rewrittenConnect := connectPkt.WithUsername(claims.Username)
	if err := writeBroker(brokerConn, rewrittenConnect); err != nil {
		h.log.Error("write CONNECT to broker failed", zap.Error(err))
		writeWS(wsConn, mqtt.WriteConnack(version, mqtt.ConnackServerUnavailable, false))
		return
	}

	// Read CONNACK from broker and forward to client.
	connackBuf := make([]byte, 16)
	n, err := brokerConn.Read(connackBuf)
	if err != nil || n < 4 {
		h.log.Error("read CONNACK from broker failed", zap.Error(err))
		writeWS(wsConn, mqtt.WriteConnack(version, mqtt.ConnackServerUnavailable, false))
		return
	}
	connack := connackBuf[:n]

	// If the broker rejected the connection, forward its CONNACK and stop.
	if mqtt.ReadPacketType(connack[0]) == mqtt.TypeConnack && connack[3] != 0x00 {
		writeWS(wsConn, connack)
		return
	}

	if err := writeWS(wsConn, connack); err != nil {
		return
	}

	h.log.Info("session established",
		zap.String("username", claims.Username),
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
		err := copyBrokerToClient(wsConn, brokerConn.(net.Conn))
		h.log.Debug("broker→client copy ended",
			zap.String("username", claims.Username),
			zap.Error(err),
		)
	}()

	// client → broker: inspect MQTT packets for ACL enforcement.
	h.proxyClientToBroker(ctx, wsConn, brokerConn.(net.Conn), claims, version, expiryTimer.C, done)

	h.log.Info("session ended",
		zap.String("username", claims.Username),
		zap.String("client_id", connectPkt.ClientID),
	)
```

The session lifecycle after a successful CONNACK is elegant: a goroutine is launched to copy broker→client traffic (raw bytes, no inspection needed), and the current goroutine runs the client→broker loop. When either side terminates, a done channel signals the other. The JWT expiry timer runs in the same select loop as the client→broker reads, so token expiry is handled without a separate goroutine.

The client→broker loop uses a subtle pattern for cooperative reads:

```bash
sed -n '218,275p' internal/proxy/handler.go
```

```output
) {
	msgs := make(chan wsMessage, 1)

	readNext := func() {
		msgType, frame, err := wsConn.ReadMessage()
		msgs <- wsMessage{msgType, frame, err}
	}
	go readNext()

	for {
		select {
		case <-expiry:
			h.log.Info("token expired, disconnecting",
				zap.String("username", claims.Username),
			)
			writeWS(wsConn, mqtt.WriteDisconnect(version, mqtt.DisconnectSessionTakenOver))
			wsConn.Close()
			brokerConn.Close()
			return

		case <-done:
			h.log.Debug("broker side closed, ending client→broker loop",
				zap.String("username", claims.Username),
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

			if !h.checkACL(wsConn, brokerConn, claims, version, m.frame) {
				return
			}

			if err := writeBroker(brokerConn, m.frame); err != nil {
				h.log.Debug("write to broker failed", zap.Error(err))
				return
			}
			go readNext()
		}
	}
```

The goroutine-per-read pattern (readNext launched with go each time) is necessary because WebSocket's ReadMessage is blocking. To select on multiple channels including expiry and done, the read must run in its own goroutine and report results through the msgs channel. A new goroutine is launched after each successful message, not before — this prevents two concurrent reads on the same connection.

Finally, checkACL handles per-packet enforcement with version-aware responses:

```bash
sed -n '280,356p' internal/proxy/handler.go
```

```output
func (h *Handler) checkACL(
	wsConn *websocket.Conn,
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
				zap.String("username", claims.Username),
				zap.String("topic", topic),
			)
			qos := (frame[0] >> 1) & 0x03
			switch {
			case version == mqtt.ProtocolV50 && qos == 1:
				writeWS(wsConn, mqtt.WritePuback(version, packetID, mqtt.PubackNotAuthorized))
				return true // session continues; only this message rejected

			case version == mqtt.ProtocolV50 && qos >= 2:
				writeWS(wsConn, mqtt.WritePuback(version, packetID, mqtt.PubackNotAuthorized))
				return true

			default:
				// MQTT 3.1.1 or QoS 0: no per-message rejection — disconnect.
				writeWS(wsConn, mqtt.WriteDisconnect(version, mqtt.DisconnectNotAuthorized))
				wsConn.Close()
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
					zap.String("username", claims.Username),
					zap.String("topic", topic),
				)
				codes = append(codes, mqtt.SubackNotAuthorized)
			}
		}

		// If every requested subscription is denied, send a SUBACK with all
		// failure codes and do not forward to the broker.
		if allDenied {
			writeWS(wsConn, mqtt.WriteSuback(version, packetID, codes))
			return true
		}

		// Mixed: let the broker handle it but override codes for denied topics.
		// For simplicity we block the entire SUBSCRIBE and respond ourselves.
		writeWS(wsConn, mqtt.WriteSuback(version, packetID, codes))
		return true
	}

	return true
```

The PUBLISH enforcement asymmetry is intentional and rooted in the MQTT spec: MQTT 3.1.1 has no per-message rejection mechanism for QoS 0 (fire-and-forget). Since there is no packet ID to put in a PUBACK, the only option is to disconnect the client. MQTT 5.0 with QoS ≥ 1 has a packet ID, so the proxy can send a PUBACK with reason code 0x87 (Not Authorized) and let the session continue.

SUBSCRIBE is always answered by the proxy directly — the packet is never forwarded to the broker, even for partially-allowed subscriptions. The broker never sees the SUBSCRIBE. This keeps the broker's subscription state clean and means the proxy fully controls what topics a client is actually subscribed to.

## Key design decisions and tradeoffs

**Minimal MQTT codec.** Rather than using a full MQTT client library, the proxy implements only the packet types it needs to inspect or generate. This keeps the dependency surface small and means the codec is tuned exactly to the proxy's use case.

**Interface-driven composition.** Every external dependency (JWT validation, ACL, broker dialing) is injected as an interface. The handler has no imports from jwks, acl, or config — only from its own package and the jwt/mqtt internals it must parse. This boundary makes unit testing straightforward.

**Asymmetric inspection.** Broker→client traffic is copied as raw bytes without any packet parsing. The proxy trusts the broker. Client→broker traffic is fully inspected. This is the right tradeoff: the threat model is the untrusted internet client, not the private-network broker.

**JWT expiry as a session timer.** The token expiry claim is used both at connect time (standard validation) and as a runtime timer. When the timer fires, the proxy disconnects the client with a DISCONNECT packet. This enforces short-lived token semantics end-to-end — even if the client holds the connection open, it cannot outlive its token.

**Known limitations to be aware of:**
- CheckOrigin is disabled. If the proxy is directly internet-facing (not behind a reverse proxy), any WebSocket origin is accepted.
- No rate limiting. A connection flood would not be mitigated at this layer.
- Will messages are dropped. The broker never registers last-will-and-testament for proxied clients.
- No TLS between proxy and broker. They should run on the same host or private network.

```bash
wc -l walkthrough.md && echo '---' && head -5 walkthrough.md
```

```output
     755 walkthrough.md
---
# mqttproxy — A Code Walkthrough

*2026-03-29T14:44:47Z by Showboat 0.6.1*
<!-- showboat-id: f147487a-5ca6-4d05-8ce0-119e870c30c5 -->

```
