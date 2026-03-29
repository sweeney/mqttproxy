package proxy

import (
	"context"
	"fmt"
	"net"
	"time"
)

// TCPDialer dials the broker over a plain TCP connection.
type TCPDialer struct {
	addr    string
	timeout time.Duration
}

// NewTCPDialer creates a TCPDialer for the given address and dial timeout.
func NewTCPDialer(addr string, timeout time.Duration) *TCPDialer {
	return &TCPDialer{addr: addr, timeout: timeout}
}

func (d *TCPDialer) Dial(ctx context.Context) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", d.addr)
	if err != nil {
		return nil, fmt.Errorf("dial broker %s: %w", d.addr, err)
	}
	return conn, nil
}
