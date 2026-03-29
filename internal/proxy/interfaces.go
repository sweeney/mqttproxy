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
