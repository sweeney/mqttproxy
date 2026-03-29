# mqttproxy

An MQTT-over-WebSocket authentication proxy that validates JWT tokens before forwarding client sessions to a backend broker, enforcing role-based ACL rules on every publish and subscribe packet.

## How it works

Internet clients connect via WebSocket and send a standard MQTT CONNECT packet with a JWT in the password field. The proxy validates the token, rewrites the CONNECT (replacing the password with the authenticated username), and opens a TCP connection to the backend broker on the client's behalf. From that point on, client-to-broker packets are inspected for ACL compliance while broker-to-client traffic is passed through as raw bytes.

```
Browser / MQTT client
      |
      | WebSocket (ws:// or wss://)
      | MQTT CONNECT — JWT in password field
      v
  mqttproxy  (:8883/mqtt)
      |  1. Upgrade WebSocket
      |  2. Parse MQTT CONNECT, extract JWT from password
      |  3. Validate JWT (JWKS, issuer, audience, exp, usr/rol/act)
      |  4. Dial backend broker over TCP
      |  5. Rewrite CONNECT: strip password, set username = JWT usr claim
      |  6. Forward session; enforce ACL on every PUBLISH and SUBSCRIBE
      v
  MQTT broker  (TCP :1883)
```

The proxy terminates the session automatically when the JWT `exp` claim is reached.

## Prerequisites

- Go 1.22 or later
- A running MQTT broker accessible over plain TCP (e.g. Mosquitto on port 1883)
- An OAuth2 authorization server that publishes a JWKS at a well-known discovery URL

## Configuration

Copy `config.example.yaml` and edit it:

```yaml
listen:
  addr: "0.0.0.0:8883"   # address and port the proxy listens on
  path: "/mqtt"           # WebSocket path; defaults to /mqtt if omitted

broker:
  addr: "127.0.0.1:1883"  # backend broker TCP address (not a WebSocket port)
  dial_timeout: "5s"       # timeout for opening the TCP connection to the broker

auth:
  well_known_url: "https://example.com/.well-known/oauth-authorization-server"
  issuer: "https://example.com"   # must match the iss claim in issued tokens
  audience: "mqttproxy"           # must match the aud claim; omit to skip aud check
  jwks_cache_ttl: "1h"            # how long to cache the JWKS before re-fetching

acl:
  roles:
    admin:
      publish:   ["#"]   # MQTT topic filters; # and + wildcards supported
      subscribe: ["#"]
    user:
      publish:   []
      subscribe: ["#"]

logging:
  level: "info"   # debug | info | warn | error
```

All fields except `audience` and `jwks_cache_ttl` are required. Duration strings use Go syntax (`5s`, `1h`, `30m`).

## Running

```bash
go build -o mqttproxy ./cmd/mqttproxy
./mqttproxy -config config.yaml
```

The `-config` flag defaults to `config.yaml` in the working directory.

The process handles `SIGINT` and `SIGTERM` with a 30-second graceful shutdown window.

## Auth flow

Clients authenticate by placing a signed JWT in the MQTT `password` field. The `username` field is accepted but ignored for authentication; it is replaced by the `usr` claim from the validated token when forwarding to the broker.

**Token validation steps:**

1. Parse the JWT header to extract the `kid`.
2. Fetch the matching public key from the JWKS (via the well-known discovery endpoint).
3. Verify the signature using the algorithm declared on the key (RS256 or ES256).
4. Validate standard claims: `iss`, `aud` (if configured), `exp`.
5. Extract and validate custom claims:

| Claim | Type   | Description                                    |
|-------|--------|------------------------------------------------|
| `usr` | string | Username forwarded to the broker               |
| `rol` | string | Role name used for ACL lookup                  |
| `act` | bool   | Must be `true`; `false` rejects the connection |

Any failure at any step produces a CONNACK with return code `Not Authorized` (0x05 for MQTT 3.1.1, 0x87 for MQTT 5.0) and the connection is closed.

**JWKS caching:** Keys are cached for `jwks_cache_ttl`. A cache miss for an unknown `kid` triggers an immediate one-time refresh to support key rotation without waiting for the TTL to expire.

## ACL

Permissions are defined per role in the config. Role names must match the `rol` JWT claim exactly. Each role has independent `publish` and `subscribe` topic filter lists. Both `#` (multi-level) and `+` (single-level) MQTT wildcards are supported and evaluated per MQTT 3.1.1 §4.7.

A client with no matching role, or a role with an empty list for an operation, is denied that operation.

**Enforcement behaviour:**

- **PUBLISH denied:**
  - MQTT 5.0, QoS 1 or 2: proxy sends PUBACK with reason code `Not Authorized` (0x87); session continues.
  - MQTT 3.1.1 or QoS 0: no per-message rejection mechanism exists, so the proxy sends DISCONNECT and closes the connection.
- **SUBSCRIBE:** The proxy responds directly with a SUBACK containing per-topic result codes (`0x00` granted, `0x87` denied) and does not forward the SUBSCRIBE to the broker. Partially-denied requests receive mixed codes.

## Health check

```
GET /health
```

Attempts a TCP connection to the configured broker address and returns JSON:

```json
{"status":"ok","broker":"127.0.0.1:1883","elapsed_ms":1,"checked_at":"2024-01-01T00:00:00Z"}
```

Returns HTTP 200 on success, 503 if the broker is unreachable.

## Testing

**Unit tests** cover packet parsing, JWT validation, JWKS caching, ACL matching, and the proxy handler:

```bash
go test ./internal/...
```

**End-to-end tests** require a live broker and auth server. Use the helper script which builds the proxy, generates a config, starts the proxy, and runs the suite:

```bash
E2E_ADMIN_USER=alice E2E_ADMIN_PASS=... \
E2E_USER_USER=bob   E2E_USER_PASS=...  \
./scripts/e2e.sh
```

Optional overrides: `E2E_BROKER_ADDR`, `E2E_PROXY_ADDR`, `E2E_PROXY_PORT`, `E2E_AUTH_URL`, `E2E_CONFIG`.

The e2e suite covers: admin publish/subscribe, user subscribe-only, user publish causing disconnect, invalid token rejection, and missing token rejection.

**probeauth** is a manual adversarial probe tool that fires a battery of bad inputs at a running proxy to verify rejection behaviour:

```bash
go run ./cmd/probeauth [-addr ws://localhost:8883/mqtt] [-slow]
```

Probes include: missing credentials, malformed packets, oversized messages, forged JWTs with bad signatures, expired tokens, wrong issuers, inactive users, and missing claims. The `-slow` flag adds a connect-then-silence test that waits for the 10-second `connectReadTimeout` to fire.

## Security notes

**Handled:**
- JWT signature verification using the issuer's public key (RS256 and ES256)
- Token expiry enforced at connect time and as a session timer
- Issuer and audience validation
- User account status (`act` claim)
- Per-packet ACL enforcement on publish and subscribe
- 8 KB cap on incoming WebSocket frames before allocation
- 10-second deadline for the initial CONNECT packet
- 30-second write deadline on all broker and WebSocket writes
- Graceful DISCONNECT or CONNACK on every rejection path

**Known limitations:**
- `CheckOrigin` is disabled — any Origin header is accepted. Add a check if the proxy is directly internet-facing rather than behind a reverse proxy that handles CORS.
- No rate limiting. A connection flood is not mitigated at the proxy layer.
- Will messages are dropped. The CONNECT is rewritten without the will flag, so clients cannot register last-will-and-testament messages through the proxy.
- The broker connection is plain TCP. TLS between proxy and broker is not implemented; run them on the same host or private network.
- MQTT 5.0 SUBSCRIBE properties are not parsed (skipped); subscription options beyond QoS are ignored.

## Production notes

- Set `logging.level` to `info` or `warn` in production. `debug` logs every packet event and is verbose under load.
- The included frontend (`frontend/index.html`) uses a `LEASE_MS` constant to cap the effective token lifetime displayed in the UI and trigger proactive refresh. Set it to match your token TTL in production (default in the file is `2 * 60 * 1000` for testing).
- When running behind Cloudflare, TLS termination happens at the edge. The proxy receives plain HTTP WebSocket upgrades; do not configure TLS on the proxy listener itself. Ensure the Cloudflare WebSocket proxying option is enabled for the hostname.
