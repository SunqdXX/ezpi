package main

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

type strategyConn struct {
	net.Conn
	strat Strategy
	first bool
}

func (c *strategyConn) Write(b []byte) (int, error) {
	if !c.first {
		c.first = true
		if len(b) > recHeaderLen && b[0] == recHandshake {
			if err := c.strat.Apply(c.Conn, b); err == nil {
				return len(b), nil
			}
		}
	}
	return c.Conn.Write(b)
}

func DialTLSWithStrategy(ctx context.Context, dialer *net.Dialer, addr, serverName string, strat Strategy) (*tls.Conn, error) {
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		raw.SetDeadline(dl)
	}
	conn := tls.Client(&strategyConn{Conn: raw, strat: strat},
		&tls.Config{ServerName: serverName, NextProtos: []string{"h2", "http/1.1"}})
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	return conn, nil
}
