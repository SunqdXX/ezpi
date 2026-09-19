//go:build linux

package main

import (
	"net"
	"time"
)

func selfTestDial(cfg *Config, host, addr string, timeout time.Duration) (net.Conn, error) {
	return (&net.Dialer{Timeout: timeout}).Dial("tcp", addr)
}
