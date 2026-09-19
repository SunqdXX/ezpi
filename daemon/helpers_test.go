package main

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func realClientHello(t *testing.T, host string) []byte {
	t.Helper()
	c, s := net.Pipe()
	go func() {
		tls.Client(c, &tls.Config{ServerName: host}).Handshake()
		c.Close()
	}()
	defer s.Close()
	s.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, recHeaderLen)
	if _, err := io.ReadFull(s, hdr); err != nil {
		t.Fatalf("reading record header: %v", err)
	}
	rec := make([]byte, recHeaderLen+int(binary.BigEndian.Uint16(hdr[3:5])))
	copy(rec, hdr)
	if _, err := io.ReadFull(s, rec[recHeaderLen:]); err != nil {
		t.Fatalf("reading record body: %v", err)
	}
	return rec
}
