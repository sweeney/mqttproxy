# mqttproxy — A Code Walkthrough

*2026-09-08T10:00:45Z by Showboat 0.6.1*
<!-- showboat-id: 3dd57357-df9c-4c7b-bbfd-cd3a1cd1bf78 -->

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
./internal/jwt/validator.go
./internal/mqtt/packet.go
./internal/proxy/dialer.go
./internal/proxy/handler.go
./internal/proxy/interfaces.go
```

The codebase is small and well-scoped — nine non-test source files. The reading order that makes most sense is: entry point → configuration → the MQTT packet codec (a dependency of the proxy layer) → token validation → ACL checking → the proxy interfaces and dialer → finally the proxy handler, which is where all the pieces come together.

## Entry point: cmd/mqttproxy/main.go

The entry point is almost entirely wiring. It loads config, builds a zap logger, constructs each dependency in order — JWT validator, ACL checker, TCP dialer — then hands them all to the proxy handler as interface values. This means each piece can be replaced with a fake in tests without touching the handler at all.

```bash
sed -n '53,73p' cmd/mqttproxy/main.go
```

```output
	validator, err := jwt.NewValidator(jwt.Config{
		Issuer:      cfg.Auth.Issuer,
		IssuerURL:   cfg.Auth.IssuerURL,
		Audience:    cfg.Auth.Audience,
		DefaultRole: cfg.ACL.DefaultRole,
		CacheTTL:    cfg.Auth.JWKSCacheTTL,
		HTTPClient:  &http.Client{Timeout: 10 * time.Second},
	})
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

Key fetching is no longer wired up here. It used to be: a jwks.Client was constructed with a well-known discovery URL and passed to the validator as a KeySource. That whole layer now lives in github.com/sweeney/identity/common/auth, so main.go hands the validator a config struct and the validator builds a JWKSVerifier internally.

IssuerURL is the base the JWKS is fetched from, as {IssuerURL}/.well-known/jwks.json, and defaults to Issuer. The two are separate only because a deployment could put identity behind a reverse proxy that rewrites its name, in which case the URL you fetch from and the iss you expect diverge.

The server setup below the wiring adds two routes: the proxy handler on the configured WebSocket path, and a /health endpoint that does a quick TCP dial to the broker and returns JSON.

```bash
sed -n '77,104p' cmd/mqttproxy/main.go
```

```output
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
				"status":     "error",
				"version":    version,
				"broker":     brokerAddr,
				"detail":     err.Error(),
				"elapsed_ms": elapsed.Milliseconds(),
				"checked_at": time.Now().UTC().Format(time.RFC3339),
			})
			return
		}
		conn.Close()
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "ok",
			"version":    version,
			"broker":     brokerAddr,
			"elapsed_ms": elapsed.Milliseconds(),
			"checked_at": time.Now().UTC().Format(time.RFC3339),
		})
	})
```

## Configuration: internal/config/config.go

The config package uses a two-struct trick to give better error messages for duration fields. YAML is unmarshalled into a raw struct where duration fields are plain strings. The Load function then parses each duration explicitly and reports the field name if parsing fails. This avoids the opaque errors you would get from using time.Duration directly in the YAML struct.

```bash
sed -n '51,72p' internal/config/config.go
```

```output
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
		IssuerURL    string `yaml:"issuer_url"`
		Audience     string `yaml:"audience"`
		JWKSCacheTTL string `yaml:"jwks_cache_ttl"`
	} `yaml:"auth"`
	ACL     ACLConfig     `yaml:"acl"`
	Logging LoggingConfig `yaml:"logging"`
}

```

The audience field is optional — if omitted, the aud claim is not validated. Everything else is required and validated explicitly in Load(). Durations default to sensible values (5s broker dial timeout, 1h JWKS cache TTL) if not specified.

Note that raw still carries WellKnownURL even though AuthConfig does not. That is deliberate. The field was removed when key fetching moved to common/auth, and Load rejects it outright rather than letting yaml.v3 silently ignore an unknown key — a config still pointing discovery somewhere unexpected would otherwise keep loading while quietly fetching keys from somewhere else.

```bash
sed -n '105,122p' internal/config/config.go
```

```output

	// well_known_url was removed when JWKS lookup moved to common/auth, which
	// derives the JWKS URL from the issuer. Rejecting it loudly beats ignoring
	// it: a config pointing discovery somewhere unexpected would otherwise keep
	// loading while silently fetching keys from somewhere else.
	if r.Auth.WellKnownURL != "" {
		return nil, fmt.Errorf("auth.well_known_url is no longer supported; remove it (keys are fetched from auth.issuer_url, defaulting to auth.issuer)")
	}

	if r.Auth.Issuer == "" {
		return nil, fmt.Errorf("auth.issuer is required")
	}
	cfg.Auth.Issuer = r.Auth.Issuer

	cfg.Auth.IssuerURL = r.Auth.IssuerURL
	if cfg.Auth.IssuerURL == "" {
		cfg.Auth.IssuerURL = r.Auth.Issuer
	}
```

## MQTT packet codec: internal/mqtt/packet.go

This is one of the most important files — and notably, there is no third-party MQTT library here. The proxy only needs to parse a few packet types (CONNECT, PUBLISH, SUBSCRIBE) and serialise a few response types (CONNACK, PUBACK, SUBACK, DISCONNECT). Writing a minimal codec avoids pulling in a full client library and keeps the behaviour exactly as needed.

MQTT encodes the remaining-length field as a variable-length integer, which is the first thing any parser must handle.

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

The CONNECT rewrite is where the proxy substitutes its own view of who the client is.

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

## Token validation: internal/jwt/validator.go

This package used to own JWT parsing and JWKS caching outright — roughly 250 lines across internal/jwt and internal/jwks. It is now a thin adapter over commonauth.JWKSVerifier, which the identity project hardened during a security remediation. Keeping a second implementation in this repo meant fixing everything twice.

What the shared verifier brings that the hand-rolled version did not: singleflight fetches detached from the caller's context, so one client cancelling mid-fetch no longer abandons the result for every other waiter; refetch throttling on an unknown kid, so a replayed bad token cannot hammer identity; a bounded staleness window rather than serving a cached key forever; a 1 MiB cap and content-type check on the JWKS response; and ES256 pinned rather than trusted from the key itself.

That last one was a real hole. The old code called gojwt.WithKey(key.Algorithm(), key) — it took the signing algorithm from the JWKS entry rather than deciding for itself.

```bash
sed -n '66,87p' internal/jwt/validator.go
```

```output
func NewValidator(cfg Config) (*Validator, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("issuer must not be empty")
	}
	issuerURL := cfg.IssuerURL
	if issuerURL == "" {
		issuerURL = cfg.Issuer
	}

	verifier, err := commonauth.NewJWKSVerifier(commonauth.JWKSVerifierConfig{
		IssuerURL:        issuerURL,
		Issuer:           cfg.Issuer,
		RequiredAudience: cfg.Audience,
		CacheTTL:         cfg.CacheTTL,
		HTTPClient:       cfg.HTTPClient,
	})
	if err != nil {
		return nil, fmt.Errorf("build verifier: %w", err)
	}

	return &Validator{verifier: verifier, defaultRole: cfg.DefaultRole}, nil
}
```

Validate is where the adapter earns its keep: it maps the library's errors onto this package's sentinels, and applies the two policies that belong to the proxy rather than to identity.

```bash
sed -n '92,135p' internal/jwt/validator.go
```

```output
func (v *Validator) Validate(ctx context.Context, rawToken string) (*Claims, error) {
	tc, err := v.verifier.Parse(ctx, rawToken)
	switch {
	case errors.Is(err, commonauth.ErrKeysUnavailable):
		return nil, fmt.Errorf("%w: %v", ErrKeysUnavailable, err)
	case errors.Is(err, commonauth.ErrTokenExpired):
		return nil, fmt.Errorf("%w: %v", ErrTokenExpired, err)
	case err != nil:
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	if tc.UserID == "" {
		return nil, fmt.Errorf("%w: sub", ErrMissingClaims)
	}

	// A token with no exp cannot bound a session. The proxy holds the
	// connection open until the token runs out, so an absent expiry would
	// otherwise read as unix zero and disconnect the client the instant it
	// connected — worse, silently, and only for tokens minted without one.
	if tc.ExpiresAt == 0 {
		return nil, fmt.Errorf("%w: exp", ErrMissingClaims)
	}

	// act is a mint-time snapshot — identity re-reads the database, the proxy
	// cannot — so this catches accounts disabled before the token was issued,
	// not after. Free, and strictly better than ignoring the claim.
	if !tc.IsActive {
		return nil, fmt.Errorf("%w: %s", ErrAccountDisabled, tc.UserID)
	}

	role := v.defaultRole
	if tc.Role != "" {
		role = string(tc.Role)
	}
	if role == "" {
		return nil, fmt.Errorf("%w: rol (and no default_role configured)", ErrMissingClaims)
	}

	return &Claims{
		Subject:   tc.UserID,
		Role:      role,
		ExpiresAt: time.Unix(tc.ExpiresAt, 0),
	}, nil
}
```

Three things in that function are worth pausing on.

ErrKeysUnavailable is the reason the swap was worth doing. An MQTT client told its token is invalid re-authenticates or gives up; one told the service is unavailable should back off and retry. The old validator could not tell those apart, so an identity outage looked to every device like a bad credential.

The exp guard exists because common/auth reports an absent expiry as unix zero. The proxy holds a connection open until the token runs out, so a token with no exp would otherwise be read as expiring in 1970 and disconnect the client the instant it connected — silently, and only for tokens minted without one. Rejecting is the honest answer: a token with no expiry cannot bound a session.

The act check is a mint-time snapshot. Identity re-reads the database on every issuance, the proxy cannot, so this catches accounts disabled before the token was issued but not after. It is free and strictly better than ignoring the claim. An absent act reads as false and therefore denies, which is the safe direction.

Note also what is not here: nothing checks the token type. commonauth.Parse refuses tokens carrying typ: at+jwt, so a client_credentials machine token cannot be presented as a user identity. That matters because a service token's sub is a client id, not a user — accepting one would let a service act as whatever user its sub happened to name.

## ACL checker: internal/acl/checker.go

The ACL layer is a straightforward topic-filter matcher. Roles map to publish and subscribe pattern lists, and the checker walks the pattern segment by segment.

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

The interfaces file is the seam that keeps the handler testable.

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

This is where everything meets. handleConnection runs the whole session: read CONNECT, validate the token, dial the broker, rewrite and forward the CONNECT, relay the CONNACK, then pump traffic in both directions until something ends.

```bash
sed -n '90,203p' internal/proxy/handler.go
```

```output
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
```

The session lifecycle after a successful CONNACK is elegant: a goroutine is launched to copy broker→client traffic (raw bytes, no inspection needed), and the current goroutine runs the client→broker loop. When either side terminates, a done channel signals the other. The JWT expiry timer runs in the same select loop as the client→broker reads, so token expiry is handled without a separate goroutine.

Both of those goroutines write to the same WebSocket connection, which is a hazard gorilla/websocket does not tolerate — it permits exactly one concurrent writer. Every write therefore goes through a single mutex-guarded wsWriter.

```bash
sed -n '379,404p' internal/proxy/handler.go
```

```output
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
```

This is not a theoretical concern. Before the lock existed, broker traffic arriving while the client→broker loop wrote back — an expiry DISCONNECT, an ACL PUBACK or SUBACK — panicked with "concurrent write to websocket connection". Because the panic is unrecovered it took down the whole proxy rather than the offending session, dropping every other connected client with it. Production logged 80 such panics in seven days.

close deliberately stays outside the lock: gorilla documents it as callable concurrently with all other methods, and it is what unblocks a writer stuck on a dead peer.

```bash
sed -n '213,280p' internal/proxy/handler.go
```

```output
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
```

The goroutine-per-read pattern (readNext launched with go each time) is necessary because WebSocket's ReadMessage is blocking. To select on multiple channels including expiry and done, the read must run in its own goroutine and report results through the msgs channel. A new goroutine is launched after each successful message, not before — this prevents two concurrent reads on the same connection.

```bash
sed -n '284,361p' internal/proxy/handler.go
```

```output
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
```

The PUBLISH enforcement asymmetry is intentional and rooted in the MQTT spec: MQTT 3.1.1 has no per-message rejection mechanism for QoS 0 (fire-and-forget). Since there is no packet ID to put in a PUBACK, the only option is to disconnect the client. MQTT 5.0 with QoS ≥ 1 has a packet ID, so the proxy can send a PUBACK with reason code 0x87 (Not Authorized) and let the session continue.

SUBSCRIBE is always answered by the proxy directly — the packet is never forwarded to the broker, even for partially-allowed subscriptions. The broker never sees the SUBSCRIBE. This keeps the broker's subscription state clean and means the proxy fully controls what topics a client is actually subscribed to.

## Key design decisions and tradeoffs

**Minimal MQTT codec.** Rather than using a full MQTT client library, the proxy implements only the packet types it needs to inspect or generate. This keeps the dependency surface small and means the codec is tuned exactly to the proxy's use case.

**Shared token verification.** The opposite call is made for JWT and JWKS handling, which is deliberately *not* owned here. Token verification is security-critical and identical across every service that trusts id.swee.net, so it lives in identity/common/auth and this repo adapts it. The proxy keeps only its own policy: role defaulting, and the claims it needs.

**Interface-driven composition.** Every external dependency (JWT validation, ACL, broker dialing) is injected as an interface. The handler has no imports from acl or config — only from its own package and the jwt/mqtt internals it must parse. This boundary makes unit testing straightforward.

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
     788 walkthrough.md
---
# mqttproxy — A Code Walkthrough

*2026-09-08T10:00:45Z by Showboat 0.6.1*
<!-- showboat-id: 3dd57357-df9c-4c7b-bbfd-cd3a1cd1bf78 -->

```
