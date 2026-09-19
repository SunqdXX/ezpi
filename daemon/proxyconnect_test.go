package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConnectTunnelRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		target, err := readCONNECT(c, 3*time.Second)
		if err != nil {
			got <- "error: " + err.Error()
			return
		}
		got <- target
		io.Copy(c, c)
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := sendCONNECT(c, "www.roblox.com:443", 3*time.Second); err != nil {
		t.Fatalf("sendCONNECT: %v", err)
	}

	select {
	case target := <-got:
		if target != "www.roblox.com:443" {
			t.Fatalf("server saw %q", target)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never parsed the request")
	}

	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("tunnel did not carry data: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("tunnel corrupted data: %q", buf)
	}
}

func TestConnectDefaultsToPort443(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		a.Write([]byte("CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		io.Copy(io.Discard, a)
	}()
	target, err := readCONNECT(b, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if target != "example.com:443" {
		t.Fatalf("got %q, want example.com:443", target)
	}
}

func TestConnectRejectsOtherMethods(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		a.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		io.Copy(io.Discard, a)
	}()
	if _, err := readCONNECT(b, 3*time.Second); err == nil {
		t.Fatal("a GET was accepted as a tunnel request")
	}
}

func TestConnectTunnelCarriesRealTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "through the tunnel")
	}))
	defer srv.Close()

	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	strat, _ := StrategyByName("record-sni")
	go func() {
		for {
			c, err := proxy.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if _, err := readCONNECT(c, 3*time.Second); err != nil {
					return
				}
				dial := func(addr string) (net.Conn, error) { return net.Dial("tcp", addr) }
				Relay(c, srv.Listener.Addr().String(), dial, []Strategy{strat},
					RelayOpts{Handshake: 3 * time.Second})
			}()
		}
	}()

	client := srv.Client()
	tr := client.Transport.(*http.Transport)
	tr.DialContext = nil
	tr.Dial = nil
	tr.DialTLS = func(_, addr string) (net.Conn, error) {
		c, err := net.Dial("tcp", proxy.Addr().String())
		if err != nil {
			return nil, err
		}
		if err := sendCONNECT(c, addr, 3*time.Second); err != nil {
			c.Close()
			return nil, err
		}
		host, _, _ := strings.Cut(addr, ":")
		tc := tls.Client(c, &tls.Config{ServerName: host, RootCAs: tr.TLSClientConfig.RootCAs})
		if err := tc.Handshake(); err != nil {
			c.Close()
			return nil, err
		}
		return tc, nil
	}
	client.Timeout = 15 * time.Second

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("TLS through the CONNECT tunnel failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "through the tunnel" {
		t.Fatalf("got %q", body)
	}
}
