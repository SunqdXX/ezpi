package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	host := os.Args[1]
	addr := os.Args[2]
	d := net.Dialer{Timeout: 8 * time.Second}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("%-22s DIAL FAIL: %v\n", host, err)
		os.Exit(1)
	}
	raw.SetDeadline(time.Now().Add(8 * time.Second))
	c := tls.Client(raw, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := c.Handshake(); err != nil {
		fmt.Printf("%-22s TLS FAIL: %v\n", host, err)
		os.Exit(1)
	}
	st := c.ConnectionState()
	cn, san := "?", ""
	if len(st.PeerCertificates) > 0 {
		cn = st.PeerCertificates[0].Subject.CommonName
		if n := st.PeerCertificates[0].DNSNames; len(n) > 0 {
			san = n[0]
		}
	}
	fmt.Printf("%-22s OK  ver=%x cn=%q san=%q\n", host, st.Version, cn, san)
	c.Close()
}
